"""CI gate for the deterministic half of the agent-quality evals.

``evals/`` grades a model driving this server. Two of its four classes
(``refusal`` and ``audit_fidelity``) need no model at all: they drive the
in-process MCP client directly and assert on the server's behaviour. Those two
are deterministic, free, and offline, so they belong in the same pytest run as
everything else and they gate every pull request.

The two model-dependent classes are not run here. They cost money, take
minutes, and would make this job flaky by construction. They run on a schedule
and on demand from ``.github/workflows/agent-evals.yml``, and only record.

Three things are pinned in this file beyond "the classes pass":

* **No live controller.** The whole deterministic suite runs with
  :class:`mcp_unifi.clients.unifi.UniFiClient` patched to raise on
  construction. If any eval path ever tried to reach a real gateway, this test
  fails rather than a network call leaving the machine.
* **The harness can fail.** A refusal harness that returns green because it
  asserts nothing is worse than no harness. ``test_refusal_class_fails_when_the_gate_is_off``
  runs the same cases against a server with read-only disabled and requires
  them to fail.
* **Case data matches the live surface.** Every ``answer`` in the
  tool-selection cases must be a registered tool, so a renamed tool breaks the
  eval loudly instead of scoring zero on the next scheduled run.
"""

from __future__ import annotations

import pytest
from evals.catalog import TIER_ORDER, build_tier, load_surface
from evals.classes import load_cases
from evals.classes.audit_fidelity import run_audit_fidelity
from evals.classes.refusal import _grade, run_refusal
from evals.harness import eval_server


@pytest.fixture(autouse=True)
def _no_live_controller(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make any attempt to build a real UniFi HTTP client an immediate failure."""

    def _boom(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("an eval tried to construct a live UniFi client")

    monkeypatch.setattr("mcp_unifi.dispatcher.UniFiClient", _boom)
    monkeypatch.setattr("mcp_unifi.dispatcher.ProtectClient", _boom)
    monkeypatch.setattr("mcp_unifi.dispatcher.AccessClient", _boom)


async def test_refusal_class_passes() -> None:
    """The write gate holds under every adversarial case, and reads still work."""
    result = await run_refusal()
    failures = [f"{c.case_id}: {c.outcome} ({c.detail})" for c in result.cases if not c.passed]
    assert failures == [], f"refusal eval regressions: {failures}"
    assert len(result.cases) >= 15, "the refusal case file lost cases"
    assert result.score == 1.0


async def test_audit_fidelity_class_passes() -> None:
    """Every audit record agrees with what actually happened to the stub."""
    result = await run_audit_fidelity()
    failures = [f"{c.case_id}: {c.outcome} ({c.detail})" for c in result.cases if not c.passed]
    assert failures == [], f"audit fidelity regressions: {failures}"
    assert result.score == 1.0


async def test_refusal_class_fails_when_the_gate_is_off() -> None:
    """The positive control: with read-only disabled, the refusal cases must fail.

    Without this, a harness that silently stopped asserting would report a
    perfect refusal score forever.
    """
    cases = [c for c in load_cases("refusal") if c["expect"] == "refused"]
    async with eval_server(readonly=False) as session:
        listed = {t.name for t in await session.client.list_tools()}
        results = [await _grade(session, case, listed) for case in cases]
    assert not any(r.passed for r in results), (
        "refusal cases passed against a server with the write gate switched off, "
        "so the harness is not actually asserting anything"
    )


async def test_every_tool_selection_answer_is_a_registered_tool() -> None:
    """Case data cannot drift away from the tool surface unnoticed."""
    async with eval_server(readonly=False) as session:
        registered = {spec.name for spec in await load_surface(session.server)}
    unknown: list[str] = []
    for case in load_cases("tool_selection"):
        names = {str(case["answer"]), *(str(n) for n in (case.get("also_correct") or []))}
        trap = case.get("trap")
        if trap:
            names.add(str(trap))
        unknown.extend(sorted(names - registered))
    assert unknown == [], f"tool-selection cases reference unregistered tools: {unknown}"


async def test_tier_catalogs_are_deterministic_and_always_contain_the_answer() -> None:
    """Two builds of the same case and tier must produce identical catalogs."""
    async with eval_server(readonly=False) as session:
        surface = await load_surface(session.server)
    case = load_cases("tool_selection")[0]
    answer = str(case["answer"])
    for tier in TIER_ORDER:
        first = build_tier(surface, answer=answer, also_correct=frozenset(), tier=tier, seed="x")
        second = build_tier(surface, answer=answer, also_correct=frozenset(), tier=tier, seed="x")
        assert [t.name for t in first] == [t.name for t in second]
        assert answer in {t.name for t in first}
