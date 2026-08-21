"""Class 1: tool selection under a growing surface.

The question: given a request phrased the way a person actually asks it, does
the model reach for the right tool?

The design choice that matters is that this class never reports one number.
Every case is asked three times against three catalogs built from the same
registration: ``focused`` (8 tools, stacked with the confusable ones),
``module`` (32), and ``full`` (every registered tool, which is what a real
client receives). Accuracy is reported per tier.

A single aggregate would hide the finding. A server can be perfectly
documented and still be hard to aim once it ships 134 tools, and the shape of
that curve is the actionable output: a model that scores well focused and
poorly full has a discovery problem, which is fixed by splitting modules or
sharpening summaries. A model that scores poorly at every tier has a
comprehension problem, which is fixed by rewriting the tool's description.

Outcomes are kept apart rather than collapsed into pass/fail:

``correct``      the answer, or a listed acceptable alternative
``wrong_tool``   a different tool, recorded by name so misroutes are countable
``trap``         specifically the confusable tool the case was built around
``no_call``      answered in prose instead of calling anything
``error``        the provider failed; not the model's fault and not a pass
"""

from __future__ import annotations

from typing import Any

import httpx

from evals.catalog import TIER_ORDER, ToolSpec, build_tier, load_surface
from evals.classes import load_cases
from evals.harness import eval_server
from evals.model import ModelTarget, call_with_tools
from evals.scoring import CaseResult, ClassResult

SYSTEM_PROMPT = (
    "You are operating a UniFi network through an MCP server. Answer the user's "
    "request by calling exactly one tool. Choose the single tool that most "
    "directly answers what was asked. Do not ask a clarifying question and do "
    "not explain your choice."
)


async def run_tool_selection(
    target: ModelTarget | None,
    *,
    skip_reason: str = "",
    tiers: tuple[str, ...] = TIER_ORDER,
) -> ClassResult:
    """Grade tool selection across surface tiers, or skip cleanly with no model."""
    if target is None:
        return ClassResult(
            name="tool_selection",
            deterministic=False,
            skipped=True,
            skip_reason=skip_reason or "no model configured",
        )
    cases = load_cases("tool_selection")
    graded: dict[str, list[CaseResult]] = {tier: [] for tier in tiers}
    async with eval_server(readonly=False) as session:
        surface = await load_surface(session.server)
        async with httpx.AsyncClient() as http:
            for tier in tiers:
                for case in cases:
                    graded[tier].append(
                        await _grade(target, http, surface=surface, case=case, tier=tier)
                    )
    return ClassResult(name="tool_selection", deterministic=False, tiers=graded)


async def _grade(
    target: ModelTarget,
    http: httpx.AsyncClient,
    *,
    surface: list[ToolSpec],
    case: dict[str, Any],
    tier: str,
) -> CaseResult:
    case_id = str(case["id"])
    answer = str(case["answer"])
    also_correct = frozenset(str(n) for n in (case.get("also_correct") or []))
    catalog = build_tier(surface, answer=answer, also_correct=also_correct, tier=tier, seed=case_id)

    choice = await call_with_tools(
        target,
        system=SYSTEM_PROMPT,
        user=str(case["prompt"]),
        tools=catalog,
        client=http,
    )
    if choice.error:
        return CaseResult(case_id, False, "error", choice.error)
    if choice.tool_name is None:
        return CaseResult(case_id, False, "no_call", "answered without calling a tool")
    if choice.tool_name == answer or choice.tool_name in also_correct:
        return CaseResult(case_id, True, "correct", choice.tool_name)
    if choice.tool_name == str(case.get("trap") or ""):
        return CaseResult(case_id, False, "trap", f"picked the confusable tool {choice.tool_name}")
    return CaseResult(case_id, False, "wrong_tool", f"picked {choice.tool_name}")


__all__ = ["SYSTEM_PROMPT", "run_tool_selection"]
