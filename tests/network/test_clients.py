"""Tests for ``mcp_unifi.modules.network.clients``.

Split from the pre-Step-5 ``tests/test_tools.py``. Bodies are unchanged.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from fastmcp import FastMCP
from fastmcp.exceptions import ValidationError

from mcp_unifi.audit import AuditLog, FileSink, parse_jsonl, set_audit_log
from mcp_unifi.cli.replay import replay_events
from mcp_unifi.clients.stubs import StubState, make_stub_state
from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.config import Settings
from mcp_unifi.server import build_server
from tests.network.conftest import BASE, _call

# ---------------------------------------------------------------------------
# Stub mode
# ---------------------------------------------------------------------------


async def test_list_clients_stub(stub_server: FastMCP) -> None:
    """Stub mode should return a realistic mix of wireless and wired clients."""
    clients = await _call(stub_server, "list_clients")
    assert isinstance(clients, list)
    assert 3 <= len(clients) <= 5
    by_mac = {c["mac"]: c for c in clients}
    # Required fields on every client
    for c in clients:
        assert {"_id", "mac", "hostname", "ip", "is_wired", "last_seen"}.issubset(c)
    # At least one wireless client with signal/satisfaction
    wireless = [c for c in clients if not c["is_wired"]]
    assert wireless, "stub data should include at least one wireless client"
    assert all("signal" in c and "satisfaction" in c for c in wireless)
    # At least one wired client
    wired = [c for c in clients if c["is_wired"]]
    assert wired, "stub data should include at least one wired client"
    # Sanity: known seed MACs are present
    assert "aa:bb:cc:00:00:01" in by_mac


async def test_block_unblock_client_stub(stub_server: FastMCP) -> None:
    blocked = await _call(stub_server, "block_client", {"mac": "aa:bb:cc:00:00:01"})
    assert blocked["blocked"] is True
    unblocked = await _call(stub_server, "unblock_client", {"mac": "aa:bb:cc:00:00:01"})
    assert unblocked["blocked"] is False


async def test_block_client_unknown(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "block_client", {"mac": "00:00:00:00:00:00"})
    assert "not found" in result["error"]


async def test_unblock_client_unknown(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "unblock_client", {"mac": "00:00:00:00:00:00"})
    assert "not found" in result["error"]


async def test_reconnect_client_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "reconnect_client", {"mac": "aa:bb:cc:00:00:01"})
    assert result["reconnected"] is True


async def test_reconnect_client_unknown(stub_server: FastMCP) -> None:
    """An unknown MAC used to come back as ``{"reconnected": false}`` with no
    ``error`` key, unlike every other tool's not-found envelope (D11)."""
    result = await _call(stub_server, "reconnect_client", {"mac": "00:00:00:00:00:00"})
    assert result["error"] == "client 00:00:00:00:00:00 not found"
    assert "reconnected" not in result


@pytest.mark.parametrize(
    ("tool", "field", "value"),
    [
        ("block_client", "blocked", True),
        ("unblock_client", "blocked", False),
        ("reconnect_client", "reconnected", True),
    ],
)
@pytest.mark.parametrize("typed", ["AA:BB:CC:00:00:01", "aa-bb-cc-00-00-01"])
async def test_client_tools_find_the_client_whatever_the_mac_form(
    stub_server: FastMCP, tool: str, field: str, value: bool, typed: str
) -> None:
    result = await _call(stub_server, tool, {"mac": typed})
    assert result.get(field) is value, result


@pytest.mark.parametrize(
    ("tool", "connected"),
    [("block_client", False), ("unblock_client", False), ("reconnect_client", True)],
)
async def test_client_dry_run_says_whether_the_mac_is_known(
    stub_server: FastMCP, stub_state: StubState, tool: str, connected: bool
) -> None:
    """A dry run used to preview success for any MAC at all. The controller
    may legitimately accept a block for a MAC it has never seen, so the
    preview neither refuses nor promises: it reports what the controller
    knows and says when it cannot tell (D6)."""
    known = await _call(stub_server, tool, {"mac": "AA:BB:CC:00:00:01", "dry_run": True})
    assert known["dry_run"] is True
    assert known["client_known"] is True
    assert "note" not in known

    unknown = await _call(stub_server, tool, {"mac": "de:ad:be:ef:00:00", "dry_run": True})
    assert unknown["dry_run"] is True
    assert unknown["client_known"] is False
    assert "cannot tell" in unknown["note"]
    if connected:
        assert "not currently connected" in unknown["note"]
    assert stub_state.audit_log == []


# ---------------------------------------------------------------------------
# Real mode
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_list_clients(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/sta").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"_id": "c1", "mac": "aa:bb:cc:00:00:01", "is_wired": False}]},
        )
    )
    result = await _call(real_server, "list_clients")
    assert result[0]["_id"] == "c1"


@respx.mock
async def test_real_list_clients_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/sta").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "list_clients")
    assert "error" in result


@respx.mock
async def test_real_block_client(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/cmd/stamgr").mock(
        return_value=httpx.Response(200, json={"data": [{"mac": "aa:bb:cc:00:00:01"}]})
    )
    result = await _call(real_server, "block_client", {"mac": "aa:bb:cc:00:00:01"})
    assert result["mac"] == "aa:bb:cc:00:00:01"


@respx.mock
async def test_real_unblock_client(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/cmd/stamgr").mock(
        return_value=httpx.Response(200, json={"data": [{"mac": "aa:bb:cc:00:00:01"}]})
    )
    result = await _call(real_server, "unblock_client", {"mac": "aa:bb:cc:00:00:01"})
    assert result["mac"] == "aa:bb:cc:00:00:01"


@respx.mock
async def test_real_reconnect_client(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/cmd/stamgr").mock(return_value=httpx.Response(200, json={"data": []}))
    result = await _call(real_server, "reconnect_client", {"mac": "aa:bb:cc:00:00:01"})
    assert result["reconnected"] is True


@respx.mock
async def test_real_block_client_handles_error(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/cmd/stamgr").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "block_client", {"mac": "aa:bb:cc:00:00:01"})
    assert "error" in result


@respx.mock
@pytest.mark.parametrize(
    ("tool", "cmd"),
    [
        ("block_client", "block-sta"),
        ("unblock_client", "unblock-sta"),
        ("reconnect_client", "kick-sta"),
    ],
)
async def test_real_stamgr_commands_send_the_controller_mac_form(
    real_server: FastMCP, tool: str, cmd: str
) -> None:
    """The controller stores MACs lower case and colon separated; the
    command carries that form whatever the caller typed (D2)."""
    captured: dict[str, Any] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"data": [{"mac": "aa:bb:cc:00:00:01"}]})

    respx.post(f"{BASE}/cmd/stamgr").mock(side_effect=capture)
    await _call(real_server, tool, {"mac": "AA-BB-CC-00-00-01"})
    assert captured["body"] == {"cmd": cmd, "mac": "aa:bb:cc:00:00:01"}


@respx.mock
async def test_real_block_client_dry_run_looks_up_the_user_record(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/list/user").mock(
        return_value=httpx.Response(200, json={"data": [{"mac": "aa:bb:cc:00:00:01"}]})
    )
    stamgr = respx.post(f"{BASE}/cmd/stamgr").mock(return_value=httpx.Response(200))
    result = await _call(real_server, "block_client", {"mac": "AA:BB:CC:00:00:01", "dry_run": True})
    assert result["client_known"] is True
    assert not stamgr.called


# ---------------------------------------------------------------------------
# update_clients (issue #219): cosmetic name and note writes
# ---------------------------------------------------------------------------

_IPHONE = "aa:bb:cc:00:00:02"
_ECHO = "aa:bb:cc:00:00:04"


def _record(state: StubState, mac: str) -> dict[str, Any]:
    found = next(r for r in state.list_user_records() if r.get("mac") == mac)
    assert isinstance(found, dict)
    return found


def _user_list(*records: dict[str, Any]) -> httpx.Response:
    return httpx.Response(200, json={"meta": {"rc": "ok"}, "data": list(records)})


def _capture_puts(bodies: dict[str, Any]) -> Any:
    """respx side effect that records each PUT body by user id and echoes it."""

    def capture(request: httpx.Request) -> httpx.Response:
        user_id = request.url.path.rsplit("/", 1)[-1]
        bodies[user_id] = json.loads(request.content)
        return httpx.Response(200, json={"data": [{"_id": user_id, **bodies[user_id]}]})

    return capture


async def test_update_clients_renames_without_touching_anything_else_stub(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    before = dict(_record(stub_state, _IPHONE))
    result = await _call(
        stub_server, "update_clients", {"updates": [{"mac": _IPHONE, "name": "Pete's phone"}]}
    )
    assert result["updated"] == 1
    assert result["results"] == [
        {
            "mac": _IPHONE,
            "status": "updated",
            "changes": {"name": {"old": "iPhone 15", "new": "Pete's phone"}},
        }
    ]
    after = _record(stub_state, _IPHONE)
    assert after == {**before, "name": "Pete's phone"}
    assert "use_fixedip" not in after
    assert not any(lease.get("mac") == _IPHONE for lease in stub_state.list_dhcp_leases())


@respx.mock
async def test_real_update_clients_rename_of_an_unnamed_client_sends_name_and_noted(
    real_server: FastMCP,
) -> None:
    """The exact two-field change the issue reporter saw a UI rename make."""
    list_route = respx.get(f"{BASE}/list/user").mock(
        return_value=_user_list(
            {"_id": "u1", "mac": "aa:bb:cc:dd:ee:01", "noted": False, "hostname": "esp"}
        )
    )
    bodies: dict[str, Any] = {}
    respx.put(f"{BASE}/rest/user/u1").mock(side_effect=_capture_puts(bodies))
    result = await _call(
        real_server,
        "update_clients",
        {"updates": [{"mac": "AA-BB-CC-DD-EE-01", "name": "Garage sensor"}]},
    )
    assert bodies == {"u1": {"name": "Garage sensor", "noted": True}}
    assert result["results"][0]["changes"] == {
        "name": {"old": None, "new": "Garage sensor"},
        "noted": {"old": False, "new": True, "dependent": True},
    }
    assert list_route.call_count == 1


@respx.mock
async def test_real_update_clients_already_noted_sends_only_the_name(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/list/user").mock(
        return_value=_user_list(
            {"_id": "u1", "mac": "aa:bb:cc:dd:ee:01", "name": "Old", "noted": True}
        )
    )
    bodies: dict[str, Any] = {}
    respx.put(f"{BASE}/rest/user/u1").mock(side_effect=_capture_puts(bodies))
    await _call(
        real_server,
        "update_clients",
        {"updates": [{"mac": "aa:bb:cc:dd:ee:01", "name": "New"}]},
    )
    assert bodies == {"u1": {"name": "New"}}


@respx.mock
async def test_real_update_clients_clear_sends_empty_string_and_unsets_noted(
    real_server: FastMCP,
) -> None:
    respx.get(f"{BASE}/list/user").mock(
        return_value=_user_list(
            {"_id": "u1", "mac": "aa:bb:cc:dd:ee:01", "name": "Old", "noted": True},
            {
                "_id": "u2",
                "mac": "aa:bb:cc:dd:ee:02",
                "name": "Kept note",
                "note": "rack 2",
                "noted": True,
            },
        )
    )
    bodies: dict[str, Any] = {}
    respx.put(url__regex=r"/rest/user/u[12]$").mock(side_effect=_capture_puts(bodies))
    result = await _call(
        real_server,
        "update_clients",
        {
            "updates": [
                {"mac": "aa:bb:cc:dd:ee:01", "name": ""},
                {"mac": "aa:bb:cc:dd:ee:02", "name": "", "note": None},
            ]
        },
    )
    # Nothing left on u1, so noted flips; u2 still has its note, so it stays.
    assert bodies == {"u1": {"name": "", "noted": False}, "u2": {"name": ""}}
    assert result["results"][0]["changes"]["name"] == {"old": "Old", "new": None}


async def test_update_clients_clear_removes_the_key_stub(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    result = await _call(stub_server, "update_clients", {"updates": [{"mac": _ECHO, "name": ""}]})
    assert result["results"][0]["status"] == "updated"
    record = _record(stub_state, _ECHO)
    assert "name" not in record
    assert record["noted"] is False


async def test_update_clients_leaves_an_omitted_field_alone_stub(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    await _call(
        stub_server,
        "update_clients",
        {"updates": [{"mac": _IPHONE, "note": "work phone"}]},
    )
    record = _record(stub_state, _IPHONE)
    assert record["name"] == "iPhone 15"
    assert record["note"] == "work phone"


@respx.mock
async def test_real_update_clients_omitted_field_is_not_sent(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/list/user").mock(
        return_value=_user_list(
            {"_id": "u1", "mac": "aa:bb:cc:dd:ee:01", "name": "Keep me", "noted": True}
        )
    )
    bodies: dict[str, Any] = {}
    respx.put(f"{BASE}/rest/user/u1").mock(side_effect=_capture_puts(bodies))
    await _call(
        real_server,
        "update_clients",
        {"updates": [{"mac": "aa:bb:cc:dd:ee:01", "note": "rack 2"}]},
    )
    assert bodies == {"u1": {"note": "rack 2"}}


@respx.mock
async def test_real_update_clients_null_keeps_the_stored_value(real_server: FastMCP) -> None:
    """A client that fills every optional property sends ``"note": null`` on
    a plain rename. That is "keep", never "clear": only ``""`` clears."""
    respx.get(f"{BASE}/list/user").mock(
        return_value=_user_list(
            {
                "_id": "u1",
                "mac": "aa:bb:cc:dd:ee:01",
                "name": "Old",
                "note": "rack 2",
                "noted": True,
            }
        )
    )
    bodies: dict[str, Any] = {}
    respx.put(f"{BASE}/rest/user/u1").mock(side_effect=_capture_puts(bodies))
    result = await _call(
        real_server,
        "update_clients",
        {"updates": [{"mac": "aa:bb:cc:dd:ee:01", "name": "New", "note": None}]},
    )
    assert bodies == {"u1": {"name": "New"}}
    assert result["results"][0]["changes"] == {"name": {"old": "Old", "new": "New"}}


async def test_update_clients_null_keeps_the_stored_value_stub(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    await _call(stub_server, "update_clients", {"updates": [{"mac": _IPHONE, "note": "work"}]})
    await _call(
        stub_server,
        "update_clients",
        {"updates": [{"mac": _IPHONE, "name": "Pete's phone", "note": None}]},
    )
    record = _record(stub_state, _IPHONE)
    assert record["name"] == "Pete's phone"
    assert record["note"] == "work"


@respx.mock
async def test_real_update_clients_unchanged_sends_no_put(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/list/user").mock(
        return_value=_user_list(
            {"_id": "u1", "mac": "aa:bb:cc:dd:ee:01", "name": "Same", "noted": True}
        )
    )
    put_route = respx.put(url__regex=r"/rest/user/").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    result = await _call(
        real_server,
        "update_clients",
        {"updates": [{"mac": "aa:bb:cc:dd:ee:01", "name": "  Same  ", "note": None}]},
    )
    assert not put_route.called
    assert result["results"] == [{"mac": "aa:bb:cc:dd:ee:01", "status": "unchanged", "changes": {}}]
    assert result["unchanged"] == 1
    assert "error" not in result


async def test_update_clients_unknown_mac_alone_is_an_error_envelope(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    before = copy.deepcopy(stub_state.list_user_records())
    result = await _call(
        stub_server,
        "update_clients",
        {"updates": [{"mac": "de:ad:be:ef:00:00", "name": "ghost"}]},
    )
    assert "changed nothing" in result["error"]
    assert result["stub_mode"] is True
    assert result["not_found"] == 1
    assert result["results"] == [{"mac": "de:ad:be:ef:00:00", "status": "not_found", "changes": {}}]
    assert stub_state.list_user_records() == before


async def test_update_clients_unknown_mac_does_not_stop_the_rest(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    result = await _call(
        stub_server,
        "update_clients",
        {
            "updates": [
                {"mac": "de:ad:be:ef:00:00", "name": "ghost"},
                {"mac": _IPHONE, "name": "Found"},
            ]
        },
    )
    assert "error" not in result
    assert [r["status"] for r in result["results"]] == ["not_found", "updated"]
    assert (result["updated"], result["not_found"]) == (1, 1)
    assert _record(stub_state, _IPHONE)["name"] == "Found"


@respx.mock
async def test_real_update_clients_duplicate_mac_is_refused_before_any_call(
    real_server: FastMCP,
) -> None:
    list_route = respx.get(f"{BASE}/list/user").mock(return_value=_user_list())
    put_route = respx.put(url__regex=r"/rest/user/").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    result = await _call(
        real_server,
        "update_clients",
        {
            "updates": [
                {"mac": "aa:bb:cc:dd:ee:01", "name": "One"},
                {"mac": "AA-BB-CC-DD-EE-01", "note": "Two"},
            ]
        },
    )
    assert "more than once" in result["error"]
    assert not list_route.called
    assert not put_route.called


async def test_update_clients_duplicate_mac_writes_nothing_stub(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    before = copy.deepcopy(stub_state.list_user_records())
    result = await _call(
        stub_server,
        "update_clients",
        {
            "updates": [
                {"mac": _ECHO, "name": "A"},
                {"mac": _IPHONE, "name": "B"},
                {"mac": _ECHO.upper(), "name": "C"},
            ]
        },
    )
    assert "error" in result
    assert stub_state.list_user_records() == before


@respx.mock
async def test_real_update_clients_one_failed_put_does_not_stop_the_rest(
    real_server: FastMCP,
) -> None:
    respx.get(f"{BASE}/list/user").mock(
        return_value=_user_list(
            {"_id": "u1", "mac": "aa:bb:cc:dd:ee:01", "noted": False},
            {"_id": "u2", "mac": "aa:bb:cc:dd:ee:02", "noted": False},
            {"_id": "u3", "mac": "aa:bb:cc:dd:ee:03", "noted": False},
        )
    )
    bodies: dict[str, Any] = {}
    respx.put(f"{BASE}/rest/user/u1").mock(side_effect=_capture_puts(bodies))
    respx.put(f"{BASE}/rest/user/u2").mock(
        return_value=httpx.Response(
            400, json={"meta": {"rc": "error", "msg": "api.err.InvalidPayload"}, "data": []}
        )
    )
    respx.put(f"{BASE}/rest/user/u3").mock(side_effect=_capture_puts(bodies))
    result = await _call(
        real_server,
        "update_clients",
        {
            "updates": [
                {"mac": "aa:bb:cc:dd:ee:01", "name": "One"},
                {"mac": "aa:bb:cc:dd:ee:02", "name": "Two"},
                {"mac": "aa:bb:cc:dd:ee:03", "name": "Three"},
            ]
        },
    )
    assert "error" not in result
    assert [r["status"] for r in result["results"]] == ["updated", "failed", "updated"]
    assert "InvalidPayload" in result["results"][1]["error"]
    assert (result["updated"], result["failed"]) == (2, 1)
    assert "1 failed" in result["summary"]
    assert set(bodies) == {"u1", "u3"}


async def test_update_clients_every_write_failing_is_an_error_envelope_stub(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    stub_state.fail_next("update_user", UniFiError("UniFi API error 500: boom"))
    result = await _call(
        stub_server, "update_clients", {"updates": [{"mac": _IPHONE, "name": "X"}]}
    )
    assert "changed nothing" in result["error"]
    assert result["failed"] == 1
    assert result["results"][0]["error"] == "UniFi API error 500: boom"
    assert _record(stub_state, _IPHONE)["name"] == "iPhone 15"


async def test_update_clients_dry_run_shows_the_diff_and_writes_nothing_stub(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    before = copy.deepcopy(stub_state.list_user_records())
    result = await _call(
        stub_server,
        "update_clients",
        {
            "updates": [
                {"mac": _ECHO, "name": ""},
                {"mac": _IPHONE, "name": "iPhone 15"},
                {"mac": "de:ad:be:ef:00:00", "note": "x"},
            ],
            "dry_run": True,
        },
    )
    assert result["dry_run"] is True
    echo, iphone, ghost = result["would_update"]
    assert echo["status"] == "would_update"
    assert echo["changes"] == {
        "name": {"old": "Echo Dot", "new": None},
        "noted": {"old": True, "new": False, "dependent": True},
    }
    assert iphone == {"mac": _IPHONE, "client_known": True, "status": "unchanged", "changes": {}}
    assert ghost["client_known"] is False
    assert ghost["status"] == "not_found"
    assert result["summary"] == "Would update 1 of 3 clients (1 unchanged, 1 not found)"
    assert stub_state.list_user_records() == before


@respx.mock
async def test_real_update_clients_dry_run_sends_no_put(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/list/user").mock(
        return_value=_user_list({"_id": "u1", "mac": "aa:bb:cc:dd:ee:01", "noted": False})
    )
    put_route = respx.put(url__regex=r"/rest/user/").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    result = await _call(
        real_server,
        "update_clients",
        {"updates": [{"mac": "aa:bb:cc:dd:ee:01", "note": "n"}], "dry_run": True},
    )
    assert not put_route.called
    assert result["would_update"][0]["changes"]["noted"]["new"] is True


@pytest.mark.parametrize(
    ("item", "reason"),
    [
        ({"mac": _IPHONE, "name": "x", "use_fixedip": True}, "Extra inputs are not permitted"),
        ({"mac": _IPHONE, "name": "x", "network_id": "n1"}, "Extra inputs are not permitted"),
        ({"mac": _IPHONE}, "set at least one of name or note"),
        ({"mac": _IPHONE, "name": None, "note": None}, "set at least one of name or note"),
        ({"mac": "not-a-mac", "name": "x"}, "is not a MAC address"),
        ({"mac": _IPHONE, "name": "line\nbreak"}, "control characters"),
        ({"mac": _IPHONE, "note": "tab\there"}, "control characters"),
        ({"mac": _IPHONE, "name": "x" * 129}, "at most 128 characters"),
        ({"mac": _IPHONE, "note": "x" * 1025}, "at most 1024 characters"),
    ],
    ids=[
        "extra-key",
        "traffic-field",
        "sets-nothing",
        "only-nulls",
        "bad-mac",
        "newline",
        "tab",
        "name-too-long",
        "note-too-long",
    ],
)
async def test_update_clients_refuses_a_malformed_item(
    stub_server: FastMCP, stub_state: StubState, item: dict[str, Any], reason: str
) -> None:
    before = copy.deepcopy(stub_state.list_user_records())
    with pytest.raises(ValidationError, match=reason):
        await stub_server.call_tool("update_clients", {"updates": [item]})
    assert stub_state.list_user_records() == before


async def test_update_clients_strips_whitespace_and_takes_empty_as_clear(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    await _call(
        stub_server,
        "update_clients",
        {"updates": [{"mac": _IPHONE, "name": "  Spaced  "}, {"mac": _ECHO, "name": "   "}]},
    )
    assert _record(stub_state, _IPHONE)["name"] == "Spaced"
    assert "name" not in _record(stub_state, _ECHO)


@pytest.mark.parametrize("size", [0, 101])
async def test_update_clients_refuses_a_batch_outside_1_to_100(
    stub_server: FastMCP, size: int
) -> None:
    updates = [
        {"mac": f"02:00:00:00:{i // 256:02x}:{i % 256:02x}", "name": "x"} for i in range(size)
    ]
    with pytest.raises(ValidationError, match=r"at (least 1|most 100) item"):
        await stub_server.call_tool("update_clients", {"updates": updates})


async def test_update_clients_accepts_a_batch_of_100(stub_server: FastMCP) -> None:
    updates = [{"mac": f"02:00:00:00:00:{i:02x}", "name": "x"} for i in range(100)]
    result = await _call(stub_server, "update_clients", {"updates": updates, "dry_run": True})
    assert len(result["would_update"]) == 100


async def test_update_clients_schema_publishes_the_bounds(stub_server: FastMCP) -> None:
    tool = next(t for t in await stub_server.list_tools() if t.name == "update_clients")
    updates = tool.parameters["properties"]["updates"]
    assert (updates["minItems"], updates["maxItems"]) == (1, 100)
    item = updates["items"]
    assert item["additionalProperties"] is False
    assert item["required"] == ["mac"]
    bounds = {
        field: next(b["maxLength"] for b in item["properties"][field]["anyOf"] if "maxLength" in b)
        for field in ("name", "note")
    }
    assert bounds == {"name": 128, "note": 1024}


async def test_update_clients_is_refused_in_readonly_mode(stub_state: StubState) -> None:
    settings = Settings(
        stub_mode=True,
        log_format="text",
        mcp_transport="stdio",
        auth_required=False,
        readonly=True,
    )
    server = build_server(settings, stub=stub_state)
    assert "update_clients" not in {t.name for t in await server.list_tools()}
    before = copy.deepcopy(stub_state.list_user_records())
    result = await _call(server, "update_clients", {"updates": [{"mac": _IPHONE, "name": "X"}]})
    assert "read-only mode" in result["error"]
    assert stub_state.list_user_records() == before


async def test_update_clients_audit_event_records_the_updates_as_sent(
    stub_server: FastMCP, tmp_path: Path
) -> None:
    """One event per call, carrying each item as plain JSON (a clear as
    ``""``, a field sent as null dropped because null means "keep") and the
    per-MAC outcome in the result. ``note`` is not a secret and is not
    scrubbed."""
    log_path = tmp_path / "audit.jsonl"
    set_audit_log(AuditLog(sink=FileSink(log_path)))
    await _call(
        stub_server,
        "update_clients",
        {
            "updates": [
                {"mac": _ECHO, "name": ""},
                {"mac": _IPHONE, "name": None, "note": "work"},
            ]
        },
    )
    events = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert len(events) == 1
    event = events[0]
    assert event["tool"] == "update_clients"
    assert event["args"]["updates"] == [
        {"mac": _ECHO, "name": ""},
        {"mac": _IPHONE, "note": "work"},
    ]
    assert [(r["mac"], r["status"]) for r in event["result"]["results"]] == [
        (_ECHO, "updated"),
        (_IPHONE, "updated"),
    ]


async def test_update_clients_audit_event_replays_with_the_same_effect(
    stub_server: FastMCP, tmp_path: Path
) -> None:
    """The recorded args are the tool's real arguments, so the replay tool can
    re-run the call: a clear recorded as ``""`` replays as a clear."""
    log_path = tmp_path / "audit.jsonl"
    set_audit_log(AuditLog(sink=FileSink(log_path)))
    await _call(
        stub_server,
        "update_clients",
        {"updates": [{"mac": _ECHO, "name": ""}, {"mac": _IPHONE, "note": "work"}]},
    )
    events = parse_jsonl(log_path.read_text().splitlines())

    fresh = make_stub_state()
    settings = Settings(stub_mode=True, log_format="text", mcp_transport="stdio")
    results = await replay_events(
        events,
        stub_mode=True,
        target_controller=None,
        i_mean_it=False,
        server=build_server(settings, stub=fresh),
    )
    assert [(r.success, r.error) for r in results] == [(True, None)]
    assert "name" not in _record(fresh, _ECHO)
    assert _record(fresh, _IPHONE)["note"] == "work"
