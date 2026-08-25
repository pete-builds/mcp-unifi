"""MCP tool annotations, and the one check that makes them trustworthy.

Nothing in an MCP manifest distinguishes ``delete_wlan`` from
``get_system_info`` unless the tool says so. Without annotations a client has
no basis on which to prompt before a call -- which on this server means no
basis on which to prompt before deleting a VLAN, blocking a client, restarting
a live gateway, or restoring a whole configuration over the current one.

THE TEST THAT MATTERS IS ``test_annotations_agree_with_the_write_gate``.

This server already classifies every tool once, via ``@audited(..., mutates=)``,
and that classification drives the read-only gate. The annotations are a second,
independently authored classification of the same 134 tools. Two independent
classifications that disagree mean one of them is wrong, and the disagreement is
mechanically findable. So rather than assert my own list back to myself, the
test asserts the two agree -- which is a claim I could not have made true by
copying, because the gate's answer lives in a decorator argument and the
annotation's lives in a dict.

``test_prefix_classifier_would_have_missed_these`` in test_write_gate.py already
records that a name-prefix classifier leaves 13 mutating tools callable. The
annotations were applied by prefix WITH an explicit override table, so that same
list is the natural place for this to have gone wrong, and the agreement test is
what proves it did not.
"""

from __future__ import annotations

import pytest

from mcp_unifi.scoping import MUTATING_TAG
from mcp_unifi.server import build_server
from tests.test_write_gate import NO_PREFIX_MUTATING_TOOLS, _settings


@pytest.fixture(autouse=True)
def _all_modules_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """Register network + protect + access, so every tool is in the manifest.

    Autouse rather than a per-test parameter: a test here that silently ran
    against a partial registration would pass while saying nothing about the
    tools that were not loaded.
    """
    monkeypatch.setenv("MCP_UNIFI_MODULES_ENABLED", "network,protect,access")


async def _tools() -> dict:
    server = build_server(_settings(readonly=False))
    return {t.name: t for t in await server.list_tools()}


@pytest.mark.asyncio
async def test_every_tool_is_annotated() -> None:
    """A tool added later without annotations fails here, not in production."""
    tools = await _tools()
    assert len(tools) > 100, "sanity: the whole surface should be registered"
    assert sorted(n for n, t in tools.items() if t.annotations is None) == []


@pytest.mark.asyncio
async def test_annotations_agree_with_the_write_gate() -> None:
    """Two independent classifications of the same 134 tools must not disagree.

    ``readOnlyHint`` must be True exactly when the gate does NOT consider the
    tool mutating. Either side being wrong shows up here, and neither could
    have been made to agree by copying: the gate's answer is a decorator
    argument, the annotation's is a dict on the tool.
    """
    tools = await _tools()
    disagreements = sorted(
        f"{name}: readOnlyHint={t.annotations.readOnlyHint} but "
        f"gate says mutating={MUTATING_TAG in t.tags}"
        for name, t in tools.items()
        if t.annotations.readOnlyHint is (MUTATING_TAG in t.tags)
    )
    assert disagreements == []


@pytest.mark.asyncio
async def test_the_tools_a_prefix_classifier_misses_are_right() -> None:
    """The explicit override table did its job on the known-hard names.

    These are pinned in test_write_gate.py as the tools a name-based classifier
    gets wrong. backup_config is in that set as a READ, deliberately, so this
    asserts both directions rather than blanket-marking the whole list.
    """
    tools = await _tools()
    gate_mutating = {n for n, t in tools.items() if MUTATING_TAG in t.tags}
    wrong = sorted(
        name
        for name in NO_PREFIX_MUTATING_TOOLS
        if tools[name].annotations.readOnlyHint is (name in gate_mutating)
    )
    assert wrong == []
    assert tools["backup_config"].annotations.readOnlyHint is True


@pytest.mark.asyncio
async def test_the_deletions_are_marked_destructive() -> None:
    """Every delete_*, plus the four that take something away without saying so."""
    tools = await _tools()
    expected = {n for n in tools if n.startswith("delete_")} | {
        "block_client",
        "quarantine_client",
        "restart_device",
        "reconnect_client",
        "restore_config",
        "confirm_destructive_action",
    }
    missing = sorted(n for n in expected if not tools[n].annotations.destructiveHint)
    assert missing == []


@pytest.mark.asyncio
async def test_confirm_destructive_action_is_marked_destructive() -> None:
    """The single most important annotation on this server.

    It is the tool that actually executes every gated deletion, and its name
    contains no delete-shaped word. A client that annotated by name would mark
    it safe.

    It is also non-idempotent: a preview token is single-use, so a second call
    with the same token is an error rather than a no-op.
    """
    ann = (await _tools())["confirm_destructive_action"].annotations
    assert ann.destructiveHint is True
    assert ann.readOnlyHint is False
    assert ann.idempotentHint is False


@pytest.mark.asyncio
async def test_creates_are_not_idempotent() -> None:
    """Calling create_ twice makes two, so an idempotent hint would invite a retry."""
    tools = await _tools()
    wrong = sorted(
        n
        for n in tools
        if n.startswith(("create_", "provision_")) and tools[n].annotations.idempotentHint
    )
    assert wrong == []


@pytest.mark.asyncio
async def test_updates_and_sets_are_idempotent() -> None:
    """The other direction: applying the same value twice IS the same state.

    Marking these non-idempotent alongside the creates would be a false alarm,
    and hints that cry wolf get ignored.
    """
    tools = await _tools()
    wrong = sorted(
        n
        for n in tools
        if n.startswith(("update_", "set_", "toggle_"))
        and tools[n].annotations.idempotentHint is not True
    )
    assert wrong == []


@pytest.mark.asyncio
async def test_trigger_speedtest_is_neither_read_only_nor_destructive() -> None:
    """It changes no controller state but saturates the WAN for ~a minute.

    Read-only would be a plain lie, destructive would be an overstatement, and
    idempotent would invite a second one on top of the first.
    """
    ann = (await _tools())["trigger_speedtest"].annotations
    assert ann.readOnlyHint is False
    assert ann.destructiveHint is False
    assert ann.idempotentHint is False


@pytest.mark.asyncio
async def test_every_tool_declares_an_open_world() -> None:
    """All 134 talk to a UniFi controller; none operates on a closed set."""
    tools = await _tools()
    closed = sorted(n for n, t in tools.items() if t.annotations.openWorldHint is not True)
    assert closed == []


@pytest.mark.asyncio
async def test_no_tool_is_both_read_only_and_destructive() -> None:
    tools = await _tools()
    contradictory = sorted(
        n for n, t in tools.items() if t.annotations.readOnlyHint and t.annotations.destructiveHint
    )
    assert contradictory == []
