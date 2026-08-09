"""Tests for ``mcp_unifi.modules.network.wlans``.

Split from the pre-Step-5 ``tests/test_tools.py``. Bodies are unchanged.
"""

from __future__ import annotations

import json

import httpx
import respx
from fastmcp import FastMCP

from mcp_unifi.clients.stubs import StubState
from tests.network.conftest import BASE, _call

# ---------------------------------------------------------------------------
# Stub mode
# ---------------------------------------------------------------------------


async def test_list_wlans_stub(stub_server: FastMCP) -> None:
    wlans = await _call(stub_server, "list_wlans")
    assert wlans[0]["name"] == "Home"


async def test_create_wlan_redacts_passphrase(stub_server: FastMCP, stub_state: StubState) -> None:
    net_id = stub_state.list_networks()[0]["_id"]
    result = await _call(
        stub_server,
        "create_wlan",
        {
            "name": "TestSSID",
            "passphrase": "supersecret-do-not-leak",
            "network_id": net_id,
        },
    )
    assert result["x_passphrase"] == "[REDACTED]"
    assert "supersecret-do-not-leak" not in json.dumps(result)


async def test_create_wlan_open_security_omits_passphrase(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    net_id = stub_state.list_networks()[0]["_id"]
    result = await _call(
        stub_server,
        "create_wlan",
        {
            "name": "OpenSSID",
            "passphrase": "ignored",
            "network_id": net_id,
            "security": "open",
        },
    )
    assert "x_passphrase" not in result


async def test_update_wlan_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    wlan_id = stub_state.list_wlans()[0]["_id"]
    result = await _call(
        stub_server,
        "update_wlan",
        {"wlan_id": wlan_id, "updates": {"name": "Renamed", "hide_ssid": True}},
    )
    assert result["wlan"]["name"] == "Renamed"
    assert result["wlan"]["hide_ssid"] is True
    assert result["verification"]["verified"] is True
    assert set(result["verification"]["persisted_fields"]) == {"name", "hide_ssid"}


async def test_update_wlan_redacts_passphrase(stub_server: FastMCP, stub_state: StubState) -> None:
    """Updating x_passphrase via update_wlan should redact in the response."""
    wlan_id = stub_state.list_wlans()[0]["_id"]
    result = await _call(
        stub_server,
        "update_wlan",
        {"wlan_id": wlan_id, "updates": {"x_passphrase": "rotated-secret-xyz"}},
    )
    assert result["wlan"]["x_passphrase"] == "[REDACTED]"
    assert "rotated-secret-xyz" not in json.dumps(result)
    # A secret reads back redacted, so the write cannot be confirmed. Saying
    # "verified" here would be a lie the audit log then repeats.
    assert result["verification"]["unverifiable_fields"] == ["x_passphrase"]
    assert result["verification"]["verified"] is False


async def test_update_wlan_missing(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "update_wlan",
        {"wlan_id": "ghost", "updates": {"name": "X"}},
    )
    assert "not found" in result["error"]


async def test_delete_wlan_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    wlan_id = stub_state.list_wlans()[0]["_id"]
    # v0.7.0: preview first, then confirm.
    preview = await _call(stub_server, "delete_wlan", {"wlan_id": wlan_id})
    assert preview["preview"] is True
    assert preview["resource"]["_id"] == wlan_id
    assert stub_state.list_wlans() != []  # preview must not delete
    result = await _call(stub_server, "confirm_destructive_action", {"token": preview["token"]})
    assert result["deleted"] is True
    assert result["wlan_id"] == wlan_id
    assert stub_state.list_wlans() == []


async def test_delete_wlan_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "delete_wlan", {"wlan_id": "ghost"})
    assert "error" in result
    assert "not found" in result["error"]


# ---------------------------------------------------------------------------
# Real mode
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_list_wlans(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/wlanconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "w"}]})
    )
    result = await _call(real_server, "list_wlans")
    assert result[0]["_id"] == "w"


@respx.mock
async def test_real_create_wlan(real_server: FastMCP) -> None:
    respx.get("https://gateway.test:443/proxy/network/v2/api/site/default/apgroups").mock(
        return_value=httpx.Response(
            200,
            json=[{"_id": "apg-default", "attr_hidden_id": "default", "name": "Default"}],
        )
    )
    create_route = respx.post(f"{BASE}/rest/wlanconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "w1"}]})
    )
    result = await _call(
        real_server,
        "create_wlan",
        {"name": "S", "passphrase": "abcdefgh", "network_id": "n1"},
    )
    assert result["_id"] == "w1"
    # Confirm the controller actually received ap_group_ids + ap_group_mode.
    sent = json.loads(create_route.calls.last.request.content)
    assert sent["ap_group_ids"] == ["apg-default"]
    assert sent["ap_group_mode"] == "all"


@respx.mock
async def test_real_create_wlan_honours_explicit_ap_group_ids(real_server: FastMCP) -> None:
    """If the caller passes ap_group_ids, the tool must not auto-resolve."""
    apgroups_route = respx.get(
        "https://gateway.test:443/proxy/network/v2/api/site/default/apgroups"
    ).mock(return_value=httpx.Response(200, json=[]))
    create_route = respx.post(f"{BASE}/rest/wlanconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "w1"}]})
    )
    result = await _call(
        real_server,
        "create_wlan",
        {
            "name": "S",
            "passphrase": "abcdefgh",
            "network_id": "n1",
            "ap_group_ids": ["explicit-group-id"],
        },
    )
    assert result["_id"] == "w1"
    sent = json.loads(create_route.calls.last.request.content)
    assert sent["ap_group_ids"] == ["explicit-group-id"]
    assert not apgroups_route.called


@respx.mock
async def test_real_create_wlan_errors_when_no_ap_groups(real_server: FastMCP) -> None:
    """An empty apgroups response surfaces a clean error, not an opaque 400."""
    respx.get("https://gateway.test:443/proxy/network/v2/api/site/default/apgroups").mock(
        return_value=httpx.Response(200, json=[])
    )
    result = await _call(
        real_server,
        "create_wlan",
        {"name": "S", "passphrase": "abcdefgh", "network_id": "n1"},
    )
    assert "error" in result
    assert "no AP groups" in result["error"]


async def test_create_wlan_stub_includes_ap_group(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """Stub create_wlan auto-resolves and populates ap_group_ids."""
    net_id = stub_state.list_networks()[0]["_id"]
    result = await _call(
        stub_server,
        "create_wlan",
        {"name": "Test", "passphrase": "abcdefgh", "network_id": net_id},
    )
    assert "ap_group_ids" in result
    assert isinstance(result["ap_group_ids"], list)
    assert len(result["ap_group_ids"]) == 1
    assert result["ap_group_mode"] == "all"


async def test_list_ap_groups_stub(stub_server: FastMCP) -> None:
    groups = await _call(stub_server, "list_ap_groups")
    assert isinstance(groups, list)
    assert groups[0]["attr_hidden_id"] == "default"


@respx.mock
async def test_real_list_ap_groups(real_server: FastMCP) -> None:
    respx.get("https://gateway.test:443/proxy/network/v2/api/site/default/apgroups").mock(
        return_value=httpx.Response(
            200,
            json=[{"_id": "apg-default", "attr_hidden_id": "default", "name": "Default"}],
        )
    )
    result = await _call(real_server, "list_ap_groups")
    assert result[0]["_id"] == "apg-default"


@respx.mock
async def test_real_list_ap_groups_handles_500(real_server: FastMCP) -> None:
    respx.get("https://gateway.test:443/proxy/network/v2/api/site/default/apgroups").mock(
        return_value=httpx.Response(500, text="boom")
    )
    result = await _call(real_server, "list_ap_groups")
    assert "error" in result


@respx.mock
async def test_real_update_wlan(real_server: FastMCP) -> None:
    # Verification re-reads the collection before and after the write.
    respx.get(f"{BASE}/rest/wlanconf").mock(
        side_effect=[
            httpx.Response(200, json={"data": [{"_id": "w1", "name": "Old"}]}),
            httpx.Response(200, json={"data": [{"_id": "w1", "name": "Renamed"}]}),
        ]
    )
    respx.put(f"{BASE}/rest/wlanconf/w1").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "w1", "name": "Renamed"}]})
    )
    result = await _call(
        real_server,
        "update_wlan",
        {"wlan_id": "w1", "updates": {"name": "Renamed"}},
    )
    assert result["wlan"]["name"] == "Renamed"
    assert result["verification"]["verified"] is True
    assert result["verification"]["persisted_fields"] == ["name"]


@respx.mock
async def test_real_delete_wlan(real_server: FastMCP) -> None:
    # v0.7.0: preview first (list lookup), then confirm (actual DELETE).
    respx.get(f"{BASE}/rest/wlanconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "w1", "name": "X"}]})
    )
    respx.delete(f"{BASE}/rest/wlanconf/w1").mock(return_value=httpx.Response(200))
    preview = await _call(real_server, "delete_wlan", {"wlan_id": "w1"})
    assert preview["preview"] is True
    result = await _call(real_server, "confirm_destructive_action", {"token": preview["token"]})
    assert result["deleted"] is True
    assert result["wlan_id"] == "w1"


@respx.mock
async def test_real_update_wlan_handles_404(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/wlanconf").mock(return_value=httpx.Response(200, json={"data": []}))
    respx.put(f"{BASE}/rest/wlanconf/missing").mock(
        return_value=httpx.Response(404, text="not found")
    )
    result = await _call(
        real_server,
        "update_wlan",
        {"wlan_id": "missing", "updates": {"name": "X"}},
    )
    assert "error" in result


@respx.mock
async def test_real_delete_wlan_handles_409(real_server: FastMCP) -> None:
    # v0.7.0: 409 surfaces during confirm.
    respx.get(f"{BASE}/rest/wlanconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "w1", "name": "X"}]})
    )
    respx.delete(f"{BASE}/rest/wlanconf/w1").mock(return_value=httpx.Response(409, text="in use"))
    preview = await _call(real_server, "delete_wlan", {"wlan_id": "w1"})
    assert preview["preview"] is True
    result = await _call(real_server, "confirm_destructive_action", {"token": preview["token"]})
    assert "error" in result


@respx.mock
async def test_create_wlan_real_mode_handles_500(real_server: FastMCP) -> None:
    respx.get("https://gateway.test:443/proxy/network/v2/api/site/default/apgroups").mock(
        return_value=httpx.Response(
            200,
            json=[{"_id": "apg-default", "attr_hidden_id": "default", "name": "Default"}],
        )
    )
    respx.post(f"{BASE}/rest/wlanconf").mock(return_value=httpx.Response(500))
    result = await _call(
        real_server,
        "create_wlan",
        {"name": "S", "passphrase": "abcdefgh", "network_id": "n1"},
    )
    assert "error" in result


@respx.mock
async def test_list_wlans_real_mode_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/wlanconf").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "list_wlans")
    assert "error" in result


# ---------------------------------------------------------------------------
# Read-path secret redaction (regression, 2026-08-08)
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_list_wlans_redacts_passphrase_on_the_read_path(
    real_server: FastMCP,
) -> None:
    """REGRESSION: ``list_wlans`` leaked every WLAN's PSK in cleartext.

    Redaction was implemented for the audit log and for stub mode, but the
    real-mode READ path passed controller records straight through. So
    ``list_wlans`` returned ``x_passphrase`` in cleartext to the caller while
    ``update_wlan``'s docstring and the README both advertised redaction — in
    a public repository.

    This asserts on the *rendered tool output*, not on an internal helper:
    the leak was in what reached the caller.
    """
    respx.get(f"{BASE}/rest/wlanconf").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "_id": "w1",
                        "name": "Home",
                        "security": "wpapsk",
                        "x_passphrase": "correct-horse-battery-staple",
                    }
                ]
            },
        )
    )
    result = await _call(real_server, "list_wlans")

    assert "correct-horse-battery-staple" not in json.dumps(result)
    assert result[0]["x_passphrase"] == "[REDACTED]"
    # Non-secret fields must survive redaction untouched.
    assert result[0]["name"] == "Home"
    assert result[0]["_id"] == "w1"


@respx.mock
async def test_real_update_wlan_response_redacts_passphrase(
    real_server: FastMCP,
) -> None:
    """``update_wlan``'s docstring promised a redacted response; now it is true."""
    respx.get(f"{BASE}/rest/wlanconf").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"_id": "w1", "name": "Home", "x_passphrase": "leaked-on-write"}]},
        )
    )
    respx.put(f"{BASE}/rest/wlanconf/w1").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"_id": "w1", "name": "Home", "x_passphrase": "leaked-on-write"}]},
        )
    )
    result = await _call(
        real_server,
        "update_wlan",
        {"wlan_id": "w1", "updates": {"x_passphrase": "leaked-on-write"}},
    )
    assert "leaked-on-write" not in json.dumps(result)
    assert result["wlan"]["x_passphrase"] == "[REDACTED]"
