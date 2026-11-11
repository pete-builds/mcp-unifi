"""Tests for ``mcp_unifi.modules.network.clients``.

Split from the pre-Step-5 ``tests/test_tools.py``. Bodies are unchanged.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import FastMCP

from mcp_unifi.clients.stubs import StubState
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
