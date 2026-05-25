"""Tests for ``mcp_unifi.modules.network.port_forwards``.

Split from the pre-Step-5 ``tests/test_tools.py``. Bodies are unchanged.
"""

from __future__ import annotations

import httpx
import respx
from fastmcp import FastMCP

from mcp_unifi.clients.stubs import StubState
from tests.network.conftest import BASE, _call

# ---------------------------------------------------------------------------
# Stub mode
# ---------------------------------------------------------------------------


async def test_list_port_forwards_stub(stub_server: FastMCP) -> None:
    pfs = await _call(stub_server, "list_port_forwards")
    assert isinstance(pfs, list)
    assert pfs[0]["name"] == "HTTPS to NAS"


async def test_create_update_delete_port_forward_stub(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    created = await _call(
        stub_server,
        "create_port_forward",
        {
            "name": "SSH",
            "fwd": "192.168.1.10",
            "fwd_port": "22",
            "dst_port": "2222",
            "proto": "tcp",
        },
    )
    assert created["fwd_port"] == "22"

    updated = await _call(
        stub_server,
        "update_port_forward",
        {"forward_id": created["_id"], "updates": {"enabled": False}},
    )
    assert updated["enabled"] is False

    # v0.7.0: preview first, then confirm.
    preview = await _call(stub_server, "delete_port_forward", {"forward_id": created["_id"]})
    assert preview["preview"] is True
    assert preview["resource"]["_id"] == created["_id"]
    deleted = await _call(stub_server, "confirm_destructive_action", {"token": preview["token"]})
    assert deleted["deleted"] is True


async def test_update_port_forward_missing(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "update_port_forward",
        {"forward_id": "ghost", "updates": {"enabled": False}},
    )
    assert "not found" in result["error"]


async def test_delete_port_forward_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "delete_port_forward", {"forward_id": "ghost"})
    assert "error" in result
    assert "not found" in result["error"]


# ---------------------------------------------------------------------------
# Real mode
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_port_forward_crud(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/portforward").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "pf1"}]})
    )
    listed = await _call(real_server, "list_port_forwards")
    assert listed[0]["_id"] == "pf1"

    respx.post(f"{BASE}/rest/portforward").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "pf2"}]})
    )
    created = await _call(
        real_server,
        "create_port_forward",
        {"name": "X", "fwd": "10.0.0.5", "fwd_port": "80", "dst_port": "80"},
    )
    assert created["_id"] == "pf2"

    respx.put(f"{BASE}/rest/portforward/pf2").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "pf2", "enabled": False}]})
    )
    updated = await _call(
        real_server, "update_port_forward", {"forward_id": "pf2", "updates": {"enabled": False}}
    )
    assert updated["enabled"] is False

    # v0.7.0 delete_port_forward previews via list_port_forwards first.
    # The earlier respx.get(...) mock set up at the top of this test already
    # returns pf1 — pin a second route returning pf2 so the preview finds it.
    respx.get(f"{BASE}/rest/portforward").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "pf2", "name": "X"}]})
    )
    respx.delete(f"{BASE}/rest/portforward/pf2").mock(return_value=httpx.Response(200))
    preview = await _call(real_server, "delete_port_forward", {"forward_id": "pf2"})
    assert preview["preview"] is True
    deleted = await _call(real_server, "confirm_destructive_action", {"token": preview["token"]})
    assert deleted["deleted"] is True
