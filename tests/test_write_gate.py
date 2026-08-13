"""Tests for the read-only write gate (``MCP_UNIFI_READONLY``, v0.21.0).

The gate has three layers and each is tested separately, because each one
fails in a different silent way:

* **Classification** (``@audited(..., mutates=...)``). Every registered tool
  declares whether it mutates. The completeness test below enumerates the live
  registration and fails if anything is unclassified, so a tool added later
  cannot default into being callable in read-only mode.
* **Visibility** (``tools/list``). A read-only client must not be shown a
  mutating tool.
* **Invocation** (``tools/call``). A caller that names a hidden tool anyway
  must be refused, with the server's normal error envelope, before the tool
  body runs. Hiding without refusing is a suggestion, not a control, so both
  halves are asserted — including that the underlying state did not move.

``test_prefix_classifier_would_have_missed_these`` is the regression test for
the design that was rejected: classifying by name prefix
(``create_``/``update_``/``delete_``/``set_``/``provision_``/``apply_``/
``reboot``) leaves 13 mutating tools callable, one of which is
``confirm_destructive_action`` — the tool that executes a queued delete. That
list is pinned here so nobody re-derives the shortcut later and finds the tests
still green.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastmcp import Client, FastMCP

from mcp_unifi.clients.stubs import StubState
from mcp_unifi.config import Settings
from mcp_unifi.dispatcher import UnclassifiedToolError, _tag_new_tools
from mcp_unifi.modules._audit import audited, classified_tools
from mcp_unifi.modules.network._common import make_err
from mcp_unifi.scoping import MUTATING_TAG
from mcp_unifi.server import build_server

#: Mutating tools whose names carry none of the write-shaped prefixes a
#: name-based classifier would key on. Pinned so the shortcut stays dead.
NO_PREFIX_MUTATING_TOOLS: frozenset[str] = frozenset(
    {
        "backup_config",  # read; listed here because a prefix gate would also miss it
        "block_client",
        "confirm_destructive_action",
        "locate_device",
        "quarantine_client",
        "reconnect_client",
        "rename_device",
        "restart_device",
        "restore_config",
        "toggle_traffic_route",
        "toggle_traffic_rule",
        "trigger_speedtest",
        "unblock_client",
    }
)


@pytest.fixture()
def _all_modules_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """Register network + protect + access so the gate is tested over every tool."""
    monkeypatch.setenv("MCP_UNIFI_MODULES_ENABLED", "network,protect,access")


def _settings(*, readonly: bool) -> Settings:
    return Settings(
        stub_mode=True,
        log_format="text",
        mcp_transport="stdio",
        auth_required=False,
        readonly=readonly,
    )


def _payload(result: Any) -> Any:
    return json.loads(result.content[0].text)


# ---------------------------------------------------------------------------
# Layer 1: classification is total
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_every_registered_tool_is_classified(_all_modules_enabled: None) -> None:
    """The gate is only trustworthy if nothing is unclassified.

    This is the test that blocks CI when someone adds a tool and forgets. It
    reads the live registration rather than any hand-maintained list.
    """
    server = build_server(_settings(readonly=False))
    tools = await server.list_tools()
    classified = classified_tools()
    unclassified = sorted(t.name for t in tools if t.name not in classified)
    assert unclassified == [], (
        f"tools with no mutates= declaration: {unclassified}. "
        f"Add it to their @audited(...) decorator."
    )
    assert len(tools) > 100, "sanity: the whole tool surface should be registered here"


@pytest.mark.asyncio
async def test_classification_reaches_the_tool_tags(_all_modules_enabled: None) -> None:
    """The declaration must survive registration as the tag the middleware reads."""
    server = build_server(_settings(readonly=False))
    classified = classified_tools()
    mismatched = [
        t.name
        for t in await server.list_tools()
        if (MUTATING_TAG in t.tags) is not classified[t.name]
    ]
    assert mismatched == []


@pytest.mark.asyncio
async def test_both_read_and_write_tools_exist(_all_modules_enabled: None) -> None:
    """Guard against a classification bug that collapses everything one way."""
    tools = await build_server(_settings(readonly=False)).list_tools()
    mutating = {t.name for t in tools if MUTATING_TAG in t.tags}
    reads = {t.name for t in tools} - mutating
    assert len(mutating) > 50
    assert len(reads) > 50


def test_prefix_classifier_would_have_missed_these() -> None:
    """The 13 tools that make a name-prefix gate unsafe.

    Twelve of them mutate and would have stayed callable in "read-only" mode.
    ``backup_config`` is the thirteenth: a prefix gate would have missed it
    too, but in the harmless direction — it is a pure read and is classified
    as one here. Asserting both directions keeps this test honest about which
    is which.
    """
    classified = classified_tools()
    missing = NO_PREFIX_MUTATING_TOOLS - set(classified)
    assert missing == set(), f"unregistered names in the pin list: {sorted(missing)}"

    expected_reads = {"backup_config"}
    for name in sorted(NO_PREFIX_MUTATING_TOOLS - expected_reads):
        assert classified[name] is True, f"{name} must be classified as mutating"
    for name in sorted(expected_reads):
        assert classified[name] is False, f"{name} must be classified as a read"


def test_confirm_destructive_action_is_mutating() -> None:
    """Called out on its own: it executes a queued delete.

    A read-only mode that still permits this tool lets an agent commit a
    deletion that was previewed before the mode was turned on.
    """
    assert classified_tools()["confirm_destructive_action"] is True


def test_unclassified_tool_refuses_to_register() -> None:
    """Registration fails closed, so an unclassified tool cannot reach a client."""
    mcp: FastMCP = FastMCP("test")

    @mcp.tool()
    async def unclassified_tool() -> str:
        return "{}"

    with pytest.raises(UnclassifiedToolError, match="did not declare"):
        _tag_new_tools(mcp, module_name="network", existing=set())


def test_unenumerable_tool_list_refuses_to_register(monkeypatch: pytest.MonkeyPatch) -> None:
    """If tools cannot be enumerated, nothing gets tagged — so refuse to start.

    ``_iter_registered_tools`` reads FastMCP internals and used to degrade to
    an empty list. Degrading silently would leave every tool untagged, which
    the write gate would read as "no mutating tools to hide" — a read-only
    server with the gate wide open.
    """
    from mcp_unifi import dispatcher

    monkeypatch.setattr(dispatcher, "_iter_registered_tools", lambda _mcp: [])
    with pytest.raises(UnclassifiedToolError, match="could not enumerate"):
        build_server(_settings(readonly=True))


def test_conflicting_classification_is_rejected() -> None:
    """One tool name cannot carry two answers."""
    from mcp_unifi.modules._audit import ToolClassificationConflictError

    @audited("write_gate_conflict_probe", mutates=False)
    async def probe() -> str:
        return "{}"

    with pytest.raises(ToolClassificationConflictError):

        @audited("write_gate_conflict_probe", mutates=True)
        async def probe_again() -> str:
            return "{}"


# ---------------------------------------------------------------------------
# Layer 2: tools/list hides mutating tools
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_readonly_list_tools_hides_every_mutating_tool(
    _all_modules_enabled: None,
) -> None:
    open_tools = {t.name for t in await build_server(_settings(readonly=False)).list_tools()}
    readonly_tools = await build_server(_settings(readonly=True)).list_tools()

    assert [t.name for t in readonly_tools if MUTATING_TAG in t.tags] == []
    hidden = open_tools - {t.name for t in readonly_tools}
    assert "create_vlan" in hidden
    assert "confirm_destructive_action" in hidden
    assert "restore_config" in hidden


@pytest.mark.asyncio
async def test_readonly_list_tools_keeps_read_tools(_all_modules_enabled: None) -> None:
    names = {t.name for t in await build_server(_settings(readonly=True)).list_tools()}
    for expected in ("list_networks", "get_site_health", "backup_config", "audit_open_ports"):
        assert expected in names


@pytest.mark.asyncio
async def test_default_mode_lists_mutating_tools(_all_modules_enabled: None) -> None:
    """Existing deployments must be untouched when the setting is left off."""
    names = {t.name for t in await build_server(_settings(readonly=False)).list_tools()}
    assert "create_vlan" in names
    assert "confirm_destructive_action" in names


# ---------------------------------------------------------------------------
# Layer 3: tools/call refuses mutating tools
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_readonly_call_of_a_hidden_tool_is_refused(stub_state: StubState) -> None:
    """Naming the tool anyway must not work — and must not touch state."""
    server = build_server(_settings(readonly=True), stub=stub_state)
    before = len(stub_state.networks)

    result = await server.call_tool(
        "create_vlan",
        {"name": "ShouldNotExist", "vlan_id": 99, "subnet": "10.0.99.0/24"},
    )

    payload = _payload(result)
    assert "read-only mode" in payload["error"]
    assert "create_vlan" in payload["error"]
    assert len(stub_state.networks) == before, "the tool body ran despite the refusal"
    assert not any(n.get("name") == "ShouldNotExist" for n in stub_state.networks)


@pytest.mark.asyncio
async def test_readonly_refusal_uses_the_standard_error_envelope(
    stub_settings: Settings,
) -> None:
    """A refusal is an error envelope, not a framework exception.

    Callers already parse ``{"error": ..., "stub_mode": ...}`` from every tool
    in this server. The gate must not make them learn a second failure shape.
    """
    server = build_server(_settings(readonly=True))
    result = await server.call_tool("delete_vlan", {"network_id": "whatever"})
    payload = _payload(result)

    reference = json.loads(make_err(stub_settings)("some upstream failure"))
    assert set(payload) == set(reference)
    assert payload["stub_mode"] is True


@pytest.mark.asyncio
async def test_readonly_refusal_names_no_controller_call(stub_state: StubState) -> None:
    """Every destructive path is refused, including the confirm half."""
    server = build_server(_settings(readonly=True), stub=stub_state)
    before = list(stub_state.wlans)
    result = await server.call_tool("confirm_destructive_action", {"token": "anything"})
    assert "read-only mode" in _payload(result)["error"]
    assert stub_state.wlans == before


@pytest.mark.asyncio
async def test_readonly_read_tools_still_work(stub_state: StubState) -> None:
    """The gate must not be a blunt instrument: reads behave exactly as before."""
    server = build_server(_settings(readonly=True), stub=stub_state)
    payload = _payload(await server.call_tool("list_networks", {}))
    assert isinstance(payload, list)
    assert len(payload) == len(stub_state.networks)
    assert "error" not in payload[0]


@pytest.mark.asyncio
async def test_default_mode_still_allows_mutating_calls(stub_state: StubState) -> None:
    """The whole feature is opt-in; with it off, writes go through."""
    server = build_server(_settings(readonly=False), stub=stub_state)
    before = len(stub_state.networks)
    payload = _payload(
        await server.call_tool(
            "create_vlan",
            {"name": "GateOff", "vlan_id": 77, "subnet": "10.0.77.0/24"},
        )
    )
    assert "error" not in payload
    assert len(stub_state.networks) == before + 1


@pytest.mark.asyncio
async def test_readonly_refusal_reaches_a_negotiated_client(stub_state: StubState) -> None:
    """End-to-end over a real MCP session, not just the in-process call path.

    Proves the refusal survives the adaptive-response middleware and arrives
    as a readable error rather than a transport-level failure.
    """
    server = build_server(_settings(readonly=True), stub=stub_state)
    async with Client(server) as client:
        listed = {t.name for t in await client.list_tools()}
        assert "create_vlan" not in listed
        assert "list_networks" in listed

        result = await client.call_tool(
            "create_vlan",
            {"name": "Nope", "vlan_id": 88, "subnet": "10.0.88.0/24"},
        )
        assert "read-only mode" in result.structured_content["error"]
        assert not any(n.get("name") == "Nope" for n in stub_state.networks)


# ---------------------------------------------------------------------------
# Fail-closed behavior on an unresolvable tool
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unresolvable_tool_is_refused_not_permitted() -> None:
    """If the middleware cannot resolve a tool's tags, it denies.

    ``fastmcp_context`` is ``None`` here, which is the shape the middleware
    sees when it cannot reach the registration. Permitting on doubt would turn
    any lookup failure into an open gate.
    """
    from mcp_unifi.scoping import WriteGateMiddleware

    class _Ctx:
        def __init__(self) -> None:
            self.message = type("M", (), {"name": "create_vlan"})()
            self.fastmcp_context = None

    called = False

    async def call_next(_ctx: Any) -> Any:
        nonlocal called
        called = True
        return "SHOULD NOT HAPPEN"

    gate = WriteGateMiddleware(stub_mode=True)
    result = await gate.on_call_tool(_Ctx(), call_next)  # type: ignore[arg-type]
    assert called is False
    assert "read-only mode" in json.loads(result.content[0].text)["error"]


# ---------------------------------------------------------------------------
# Settings surface
# ---------------------------------------------------------------------------


def test_readonly_defaults_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_UNIFI_READONLY", raising=False)
    assert Settings(stub_mode=True, auth_required=False).readonly is False


def test_readonly_reads_the_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_UNIFI_READONLY", "true")
    assert Settings(stub_mode=True, auth_required=False).readonly is True


def test_readonly_appears_in_safe_repr() -> None:
    """Operators need to see the posture in the startup log line."""
    assert Settings(stub_mode=True, auth_required=False, readonly=True).safe_repr()["readonly"] is (
        True
    )
