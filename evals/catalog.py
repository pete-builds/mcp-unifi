"""Tool-surface construction for the tool-selection class.

The point of this module is the **surface tier**. Asking "can the model pick
the right tool" against one fixed catalog produces a single number that hides
the thing worth knowing: a 134-tool server is harder to aim than an 8-tool
server, and how much harder is the finding.

So every tool-selection case runs three times against three surfaces built
from the same registration:

``focused``
    The correct tool plus its nearest neighbours by name and summary overlap.
    Small, and deliberately stacked with the confusable options, so a miss
    here is a genuine comprehension failure rather than a search failure.

``module``
    A mid-sized slice, still neighbour-weighted but padded out with a
    deterministic sample of the rest.

``full``
    Every registered tool. What a real client actually receives.

Distractor choice is seeded from the case id, so two runs of the same case
see byte-identical catalogs and a score change means the model changed.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass
from typing import Any

from fastmcp import FastMCP

#: Tier name -> number of tools presented. ``None`` means the whole surface.
TIER_SIZES: dict[str, int | None] = {
    "focused": 8,
    "module": 32,
    "full": None,
}

#: Tier order used in every report, smallest surface first, so a scoreboard
#: reads left to right as "add tools, watch accuracy move".
TIER_ORDER: tuple[str, ...] = ("focused", "module", "full")

_WORD = re.compile(r"[a-z0-9]+")


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """One tool as it is presented to a model."""

    name: str
    description: str
    parameters: dict[str, Any]

    def as_openai_tool(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def as_anthropic_tool(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.parameters,
        }


async def load_surface(server: FastMCP) -> list[ToolSpec]:
    """Return every registered tool as a :class:`ToolSpec`, name-sorted."""
    specs: list[ToolSpec] = []
    for tool in await server.list_tools():
        schema = getattr(tool, "parameters", None)
        if not isinstance(schema, dict):
            schema = {"type": "object", "properties": {}}
        specs.append(
            ToolSpec(
                name=tool.name,
                description=(tool.description or "").strip(),
                parameters=schema,
            )
        )
    return sorted(specs, key=lambda s: s.name)


def _tokens(spec: ToolSpec) -> set[str]:
    """Bag of words from a tool's name and its first description line."""
    first_line = spec.description.split("\n", 1)[0]
    return set(_WORD.findall(f"{spec.name} {first_line}".lower()))


def _similarity(a: ToolSpec, b: ToolSpec) -> float:
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def build_tier(
    surface: list[ToolSpec],
    *,
    answer: str,
    also_correct: frozenset[str],
    tier: str,
    seed: str,
) -> list[ToolSpec]:
    """Return the catalog a model sees for one case at one tier.

    The correct tool and every ``also_correct`` alternative are always
    present: a case where the right answer was not in the catalog would score
    the harness, not the model.

    Raises:
        KeyError: ``tier`` is not one of :data:`TIER_SIZES`.
        ValueError: ``answer`` is not a registered tool name.
    """
    size = TIER_SIZES[tier]
    by_name = {s.name: s for s in surface}
    if answer not in by_name:
        raise ValueError(f"case answer {answer!r} is not a registered tool")
    if size is None:
        chosen = list(surface)
    else:
        required = [by_name[n] for n in ({answer} | set(also_correct)) if n in by_name]
        target = by_name[answer]
        pool = [s for s in surface if s.name not in {r.name for r in required}]
        # Nearest neighbours first: the distractors that actually compete.
        pool.sort(key=lambda s: (-_similarity(target, s), s.name))
        neighbours = max(0, size - len(required))
        chosen = required + pool[:neighbours]
    rng = random.Random(f"{seed}:{tier}")  # noqa: S311 - shuffling a catalog, not crypto
    rng.shuffle(chosen)
    return chosen


__all__ = ["TIER_ORDER", "TIER_SIZES", "ToolSpec", "build_tier", "load_surface"]
