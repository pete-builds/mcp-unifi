"""Tests for ``mcp_unifi.modules.network.clients``.

Split from the pre-Step-5 ``tests/test_tools.py``. Bodies are unchanged.
"""

from __future__ import annotations

import httpx
import respx
from fastmcp import FastMCP

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
    result = await _call(stub_server, "reconnect_client", {"mac": "00:00:00:00:00:00"})
    assert result["reconnected"] is False


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
