"""Tests for read-back verification of controller writes.

The failure shapes exercised here are the ones UniFi actually produces on the
10.x line, not hypotheticals: a field silently dropped from the stored record,
a field coerced to a different value, a field coerced to a different *type*
while still comparing equal, and a write whose read-back cannot be performed
at all.

The central assertion in every case is the same: the tool must not report a
write as successful when the controller did not store what was asked for.
"""

from __future__ import annotations

import httpx
import respx
from fastmcp import FastMCP

from mcp_unifi.verification import classify_write
from tests.network.conftest import BASE, _call

# ---------------------------------------------------------------------------
# classify_write — unit level
# ---------------------------------------------------------------------------


def test_persisted_when_value_changed_to_what_was_asked() -> None:
    block = classify_write({"name": "New"}, {"name": "Old"}, {"name": "New"})
    assert block["verified"] is True
    assert block["persisted_fields"] == ["name"]
    assert block["unchanged_fields"] == []


def test_unchanged_when_already_satisfied_is_not_a_failure() -> None:
    """Asking for a value something already holds is a satisfied request."""
    block = classify_write({"enabled": True}, {"enabled": True}, {"enabled": True})
    assert block["verified"] is True
    assert block["unchanged_fields"] == ["enabled"]
    assert block["persisted_fields"] == []


def test_dropped_field_is_reported_and_fails_verification() -> None:
    """The controller accepted the write and threw the field away."""
    block = classify_write(
        {"fwd_ip": "10.0.0.5", "enabled": False},
        {"enabled": True},
        {"enabled": False},
    )
    assert block["verified"] is False
    assert block["dropped_fields"] == ["fwd_ip"]
    assert block["persisted_fields"] == ["enabled"]
    # Some of it landed, so this is a mixed state, not a clean failure.
    assert block["partial_success"] is True
    assert block["mutation_applied"] is True


def test_coerced_value_is_reported_with_both_sides() -> None:
    """purpose="guest" landing as "corporate" is the issue-499 shape."""
    block = classify_write(
        {"purpose": "guest"},
        {"purpose": "corporate"},
        {"purpose": "corporate"},
    )
    assert block["verified"] is False
    assert block["coerced_fields"] == {"purpose": {"requested": "guest", "actual": "corporate"}}
    assert block["partial_success"] is False


def test_type_change_counts_as_coercion_even_when_values_compare_equal() -> None:
    """``True`` stored as ``1`` compares equal in Python but rewrote the record."""
    block = classify_write({"enabled": True}, {"enabled": False}, {"enabled": 1})
    assert block["verified"] is False
    assert "enabled" in block["coerced_fields"]
    assert block["coerced_fields"]["enabled"]["actual"] == 1


def test_secrets_are_unverifiable_never_verified() -> None:
    """A PSK reads back redacted, so no honest claim about it can be made."""
    block = classify_write(
        {"x_passphrase": "new-secret"},
        {"x_passphrase": "[REDACTED]"},
        {"x_passphrase": "[REDACTED]"},
    )
    assert block["unverifiable_fields"] == ["x_passphrase"]
    assert block["verified"] is False
    assert block["coerced_fields"] == {}


def test_failed_read_back_makes_everything_unverifiable() -> None:
    block = classify_write({"name": "New"}, {"name": "Old"}, None)
    assert block["verified"] is False
    assert block["unverifiable_fields"] == ["name"]
    assert "could not be read back" in block["verification_summary"]


def test_rejected_write_is_reported_as_nothing_changed() -> None:
    block = classify_write(
        {"name": "New"}, {"name": "Old"}, {"name": "Old"}, mutation_applied=False
    )
    assert block["mutation_applied"] is False
    assert block["verified"] is False
    assert "rejected" in block["verification_summary"]


def test_server_owned_keys_are_not_compared() -> None:
    """``_id`` echoing back is not a caller intent and must not read as coercion."""
    block = classify_write(
        {"_id": "abc", "site_id": "s", "name": "New"},
        {"name": "Old"},
        {"_id": "abc", "site_id": "s", "name": "New"},
    )
    assert block["verified"] is True
    assert block["persisted_fields"] == ["name"]


def test_summary_says_a_partial_write_is_not_a_rollback() -> None:
    """A caller compensating for a bad write must not assume it was undone."""
    block = classify_write({"a": 1, "b": 2}, {"a": 0, "b": 0}, {"a": 1})
    assert "NOT a rollback" in block["verification_summary"]


# ---------------------------------------------------------------------------
# End-to-end through the tools
# ---------------------------------------------------------------------------


@respx.mock
async def test_update_vlan_reports_controller_coercion(real_server: FastMCP) -> None:
    """The controller says ok, stores 'corporate', and the tool says so."""
    respx.get(f"{BASE}/rest/networkconf").mock(
        side_effect=[
            httpx.Response(200, json={"data": [{"_id": "n1", "purpose": "corporate"}]}),
            httpx.Response(200, json={"data": [{"_id": "n1", "purpose": "corporate"}]}),
        ]
    )
    respx.put(f"{BASE}/rest/networkconf/n1").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "n1", "purpose": "guest"}]})
    )
    result = await _call(
        real_server,
        "update_vlan",
        {"network_id": "n1", "updates": {"purpose": "guest"}},
    )
    verification = result["verification"]
    assert verification["verified"] is False
    assert verification["coerced_fields"]["purpose"]["actual"] == "corporate"


@respx.mock
async def test_verification_ignores_the_lying_put_response(real_server: FastMCP) -> None:
    """The PUT echo is the controller's intent, not its stored state.

    This is the whole reason verification re-reads rather than trusting the
    write response: here the PUT claims the field landed and the fresh GET
    proves it did not.
    """
    respx.get(f"{BASE}/rest/networkconf").mock(
        side_effect=[
            httpx.Response(200, json={"data": [{"_id": "n1", "vlan": 10}]}),
            httpx.Response(200, json={"data": [{"_id": "n1", "vlan": 10}]}),
        ]
    )
    respx.put(f"{BASE}/rest/networkconf/n1").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "n1", "vlan": 99}]})
    )
    result = await _call(
        real_server,
        "update_vlan",
        {"network_id": "n1", "updates": {"vlan": 99}},
    )
    assert result["verification"]["verified"] is False
    assert result["verification"]["coerced_fields"]["vlan"]["actual"] == 10


@respx.mock
async def test_update_port_forward_reports_dropped_field(real_server: FastMCP) -> None:
    """``fwd_ip`` silently dropped: the caller must not think the port moved."""
    respx.get(f"{BASE}/rest/portforward").mock(
        side_effect=[
            httpx.Response(200, json={"data": [{"_id": "pf1", "enabled": True}]}),
            httpx.Response(200, json={"data": [{"_id": "pf1", "enabled": False}]}),
        ]
    )
    respx.put(f"{BASE}/rest/portforward/pf1").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "pf1", "enabled": False}]})
    )
    result = await _call(
        real_server,
        "update_port_forward",
        {"forward_id": "pf1", "updates": {"enabled": False, "fwd_ip": "10.0.0.9"}},
    )
    verification = result["verification"]
    assert verification["dropped_fields"] == ["fwd_ip"]
    assert verification["persisted_fields"] == ["enabled"]
    assert verification["partial_success"] is True


@respx.mock
async def test_write_survives_a_failed_read_back(real_server: FastMCP) -> None:
    """Losing the controller after a successful write is not a failed write."""
    # A callable rather than a fixed list: the client retries 5xx, so the
    # post-write read makes an unknown number of attempts and all of them
    # must keep failing.
    reads = {"n": 0}

    def _read(_request: httpx.Request) -> httpx.Response:
        reads["n"] += 1
        if reads["n"] == 1:
            return httpx.Response(200, json={"data": [{"_id": "n1", "name": "Old"}]})
        return httpx.Response(500, text="controller went away")

    respx.get(f"{BASE}/rest/networkconf").mock(side_effect=_read)
    respx.put(f"{BASE}/rest/networkconf/n1").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "n1", "name": "New"}]})
    )
    result = await _call(
        real_server,
        "update_vlan",
        {"network_id": "n1", "updates": {"name": "New"}},
    )
    # No error envelope — the mutation did happen.
    assert "error" not in result
    assert result["verification"]["mutation_applied"] is True
    assert result["verification"]["unverifiable_fields"] == ["name"]
    assert result["verification"]["verified"] is False


async def test_verified_delta_reaches_the_audit_log(stub_server: FastMCP, stub_state) -> None:
    """The audit log records what was stored, not what was intended.

    This is what lets ``mcp-unifi-replay`` replay against real persisted
    state. It works because the verification block rides inside the tool's
    normal response envelope, which ``@audited`` already captures.
    """
    from mcp_unifi import audit

    events: list[audit.AuditEvent] = []

    class _Collector:
        async def write(self, event: audit.AuditEvent) -> None:
            events.append(event)

    log = audit.get_audit_log()
    original = log._sink
    log._sink = _Collector()
    try:
        net_id = stub_state.list_networks()[0]["_id"]
        await _call(
            stub_server,
            "update_vlan",
            {"network_id": net_id, "updates": {"name": "AuditedRename"}},
        )
    finally:
        log._sink = original

    update_events = [e for e in events if e.tool == "update_vlan"]
    assert update_events, "update_vlan emitted no audit event"
    verification = update_events[-1].result["verification"]
    assert verification["verified"] is True
    assert verification["persisted_fields"] == ["name"]
