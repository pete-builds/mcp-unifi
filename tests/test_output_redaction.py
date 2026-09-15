"""Redaction is enforced at the serialiser, not per tool.

Three rounds of per-tool ``redact`` wiring each left gaps a later reviewer
found (0.20.0, #125, #130), and a stub-mode sweep after the third still
counted 24 Network tools returning records with a secret-shaped key
unredacted. None of those records carries a secret on today's firmware,
which is exactly how the gap survived review; issue #124 then showed a
newer firmware adding OpenVPN key fields to a record type that had none.

So the rule moved to ``_common.format_json``, and this file pins it:

1. the serialiser itself redacts, at any depth;
2. the one deliberate exception, the preview-then-confirm ``token``, is
   restored after redaction and nothing else in the envelope is;
3. a tool that never called ``redact`` (``list_firewall_rules``) is covered;
4. a sweep over every tool whose arguments can be satisfied from the seeded
   stub state finds no leak. A new tool is covered the moment it registers,
   and a tool that bypasses ``format_json`` shows up here.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from fastmcp import FastMCP

from mcp_unifi.clients.access_stubs import AccessStubState
from mcp_unifi.clients.protect_stubs import ProtectStubState
from mcp_unifi.clients.stubs import StubState
from mcp_unifi.config import Settings
from mcp_unifi.modules.network._common import format_json
from mcp_unifi.modules.network._pending import (
    format_preview_envelope,
    get_pending_actions,
    reset_pending_actions,
)
from mcp_unifi.redaction import REDACTED_OUTPUT
from mcp_unifi.server import build_server

MARK = "sweep-secret-9f8e7d"


def _text(result: Any) -> str:
    return "".join(getattr(c, "text", "") for c in result.content)


def test_format_json_redacts_at_every_depth() -> None:
    out = json.loads(
        format_json(
            {
                "name": "Home",
                "x_passphrase": MARK,
                "nested": {
                    "api_key": MARK,
                    "peers": [{"x_preshared_key": MARK, "public_key": "p"}],
                },
            }
        )
    )
    assert out["name"] == "Home"
    assert out["x_passphrase"] == REDACTED_OUTPUT
    assert out["nested"]["api_key"] == REDACTED_OUTPUT
    assert out["nested"]["peers"][0]["x_preshared_key"] == REDACTED_OUTPUT
    assert out["nested"]["peers"][0]["public_key"] == "p"
    assert MARK not in json.dumps(out)


@pytest.fixture
def _fresh_registry() -> Iterator[None]:
    reset_pending_actions()
    yield
    reset_pending_actions()


@pytest.mark.usefixtures("_fresh_registry")
def test_preview_envelope_keeps_its_token_and_nothing_else() -> None:
    """The token is the one secret-shaped key a caller must read back."""

    async def _noop() -> str:
        return "{}"

    pending = get_pending_actions().put(
        action="delete_wlan",
        controller="default",
        resource={"_id": "w1", "name": "Home", "x_passphrase": MARK},
        executor=_noop,
    )
    out = json.loads(format_preview_envelope(pending))
    assert out["token"] == pending.token
    assert out["preview_id"] == pending.token[:8]
    assert out["resource"]["x_passphrase"] == REDACTED_OUTPUT
    assert out["resource"]["name"] == "Home"
    assert MARK not in json.dumps(out)


async def test_a_tool_that_never_called_redact_is_covered(
    stub_settings: Settings, stub_state: StubState
) -> None:
    """``list_firewall_rules`` has no ``redact`` call of its own. Before the
    serialiser change this returned the marker verbatim."""
    stub_state.firewall_rules[0]["x_probe_secret"] = MARK
    server = build_server(stub_settings, stub=stub_state)
    out = _text(await server.call_tool("list_firewall_rules", {}))
    assert MARK not in out
    assert REDACTED_OUTPUT in out


def _inject(obj: Any) -> None:
    """Add a secret-shaped key to every dict at every depth of a stub state."""
    if isinstance(obj, dict):
        obj["x_probe_secret"] = MARK
        for v in list(obj.values()):
            _inject(v)
    elif isinstance(obj, list):
        for v in obj:
            _inject(v)


def _first(records: list[dict[str, Any]], key: str = "_id") -> Any:
    return records[0].get(key) if records else None


async def test_every_callable_tool_redacts_secret_shaped_keys(
    monkeypatch: pytest.MonkeyPatch, stub_state: StubState
) -> None:
    """Sweep: inject a secret-shaped field into every stub record, call every
    tool whose required arguments the seeded state can satisfy, and fail on
    the first response that echoes the value. Tools with required arguments
    outside the id map are skipped, and the skip list is asserted so a tool
    cannot drop out of the sweep unnoticed.
    """
    for var in ("STUB_MODE", "MCP_TRANSPORT", "MCP_UNIFI_AUTH_TOKENS", "MCP_UNIFI_AUTH_REQUIRED"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("MCP_UNIFI_MODULES_ENABLED", "network,protect,access")
    protect_state = ProtectStubState()
    access_state = AccessStubState()
    for state in (stub_state, protect_state, access_state):
        for attr, val in vars(state).items():
            if not attr.startswith("_"):
                _inject(val)

    settings = Settings(stub_mode=True, log_format="text", auth_required=False)
    server: FastMCP = build_server(
        settings, stub=stub_state, protect_stub=protect_state, access_stub=access_state
    )
    ids: dict[str, Any] = {
        "network_id": _first(stub_state.networks),
        "wlan_id": _first(stub_state.wlans),
        "rule_id": _first(stub_state.firewall_rules),
        "group_id": _first(stub_state.firewall_groups),
        "route_id": _first(stub_state.routes),
        "filter_id": _first(stub_state.content_filters),
        "ddns_id": _first(stub_state.dynamic_dns),
        "profile_id": _first(stub_state.port_profiles),
        "lease_id": _first(stub_state.dhcp_leases),
        "forward_id": _first(stub_state.port_forwards),
        "traffic_rule_id": _first(stub_state.traffic_rules),
        "traffic_route_id": _first(stub_state.traffic_routes),
        "mac": _first(stub_state.clients, "mac"),
        "device_mac": _first(stub_state.devices, "mac"),
    }

    leaks: list[str] = []
    called: list[str] = []
    skipped: list[str] = []
    for tool in sorted(await server.list_tools(), key=lambda t: t.name):
        schema: dict[str, Any] = getattr(tool, "parameters", None) or {}
        args: dict[str, Any] = {}
        satisfiable = True
        for name in schema.get("required", []):
            if ids.get(name) is None:
                satisfiable = False
                break
            args[name] = ids[name]
        if not satisfiable:
            skipped.append(tool.name)
            continue
        if "dry_run" in schema.get("properties", {}):
            args["dry_run"] = True
        out = _text(await server.call_tool(tool.name, args))
        called.append(tool.name)
        if MARK in out:
            leaks.append(tool.name)

    assert not leaks, f"tool responses echoed a secret-shaped field: {leaks}"
    assert len(called) >= 80, f"sweep shrank to {len(called)} tools: {called}"
    # Every skipped tool must need an argument the id map does not carry. If
    # this fails, extend the map rather than the skip list.
    for name in skipped:
        assert name not in called
        assert name.startswith(
            (
                "create_",
                "update_",
                "set_",
                "toggle_",
                "delete_",
                "get_",
                "list_recordings",
                "provision_",
                "rename_",
                "restore_",
                "audit_network_drift",
                "confirm_",
            )
        ), f"unexpected tool skipped by the sweep: {name}"
