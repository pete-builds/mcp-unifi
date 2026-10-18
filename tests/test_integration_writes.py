"""Tests for ``mcp_unifi.clients.integration.IntegrationWrites`` (ADR 0008).

Routing rules under test:

- a translatable write goes to the Integration API, and the caller still gets
  the private record back (private ``_id``), resolved through ``external_id``;
- an untranslatable write, or ``write_api="private"``, never touches v1;
- a v1 4xx falls back to the private API, because the console changed nothing;
- a v1 404 on a collection marks it absent for the life of the process;
- a v1 5xx does NOT fall back: the write may have applied, and replaying it on
  the private API could apply it twice.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
import respx
from fastmcp import FastMCP

from mcp_unifi.clients.integration import IntegrationWrites
from mcp_unifi.clients.unifi import UniFiClient, UniFiError
from mcp_unifi.config import Settings
from mcp_unifi.server import build_server

ROOT = "https://gateway.test:443/proxy/network"
PRIV = f"{ROOT}/api/s/default"
V2 = f"{ROOT}/v2/api/site/default"
SITE = "88f7af54-98f8-306a-a1c7-c9349722b1f6"
INT = f"{ROOT}/integration/v1/sites/{SITE}"

NET_PRIV_ID = "650000000000000000000001"
NET_V1_ID = "11111111-2222-4333-8444-555555555555"
WLAN_PRIV_ID = "650000000000000000000002"
WLAN_V1_ID = "66666666-7777-4888-9999-000000000000"
AP_GROUP = "650000000000000000000003"
PASSPHRASE = "correct-horse-battery"


def _priv(records: list[dict[str, Any]]) -> httpx.Response:
    return httpx.Response(200, json={"meta": {"rc": "ok"}, "data": records})


NETWORK_RECORD = {
    "_id": NET_PRIV_ID,
    "external_id": NET_V1_ID,
    "name": "IoT",
    "purpose": "corporate",
    "vlan": 50,
}
WLAN_RECORD = {
    "_id": WLAN_PRIV_ID,
    "external_id": WLAN_V1_ID,
    "name": "iot",
    "networkconf_id": NET_PRIV_ID,
    "x_passphrase": PASSPHRASE,
}
V1_NETWORK = {
    "management": "GATEWAY",
    "id": NET_V1_ID,
    "name": "IoT",
    "enabled": True,
    "vlanId": 50,
    "metadata": {"origin": "USER_DEFINED"},
    "ipv4Configuration": {
        "autoScaleEnabled": False,
        "hostIpAddress": "10.20.30.1",
        "prefixLength": 24,
        "dhcpConfiguration": {
            "mode": "SERVER",
            "ipAddressRange": {"start": "10.20.30.100", "stop": "10.20.30.200"},
        },
    },
    "default": False,
}
V1_WLAN = {
    "type": "STANDARD",
    "id": WLAN_V1_ID,
    "name": "iot",
    "metadata": {"origin": "USER_DEFINED"},
    "enabled": True,
    "network": {"type": "SPECIFIC", "networkId": NET_V1_ID},
    "securityConfiguration": {"type": "WPA2_PERSONAL", "passphrase": PASSPHRASE},
    "hideName": False,
    "broadcastingFrequenciesGHz": [2.4, 5],
}

VLAN_PAYLOAD: dict[str, Any] = {
    "name": "cams",
    "purpose": "corporate",
    "vlan_enabled": True,
    "vlan": 77,
    "ip_subnet": "10.0.77.1/24",
    "dhcpd_enabled": True,
    "dhcpd_start": "10.0.77.6",
    "dhcpd_stop": "10.0.77.254",
    "enabled": True,
}
WLAN_PAYLOAD: dict[str, Any] = {
    "name": "cams",
    "enabled": True,
    "security": "wpapsk",
    "wpa_mode": "wpa2",
    "networkconf_id": NET_PRIV_ID,
    "is_guest": False,
    "hide_ssid": False,
    "wlan_band": "both",
    "ap_group_ids": [AP_GROUP],
    "ap_group_mode": "all",
    "x_passphrase": PASSPHRASE,
}


@pytest.fixture
async def client() -> AsyncIterator[UniFiClient]:
    c = UniFiClient(host="gateway.test", api_key="test-api-key-1234")
    yield c
    await c.aclose()


def _mock_site() -> respx.Route:
    return respx.get(f"{ROOT}/integration/v1/sites").mock(
        return_value=httpx.Response(
            200, json={"data": [{"id": SITE, "internalReference": "default", "name": "Default"}]}
        )
    )


def _mock_ap_groups() -> None:
    respx.get(f"{V2}/apgroups").mock(
        return_value=httpx.Response(
            200, json=[{"_id": AP_GROUP, "name": "All APs", "attr_hidden_id": "default"}]
        )
    )


# ---------------------------------------------------------------------------
# Networks
# ---------------------------------------------------------------------------


@respx.mock
async def test_create_network_goes_through_v1_and_returns_the_private_record(
    client: UniFiClient,
) -> None:
    _mock_site()
    v1_post = respx.post(f"{INT}/networks").mock(
        return_value=httpx.Response(201, json={"id": "new-uuid", "name": "cams"})
    )
    priv_post = respx.post(f"{PRIV}/rest/networkconf")
    created = {"_id": "new-private-id", "external_id": "new-uuid", "name": "cams"}
    respx.get(f"{PRIV}/rest/networkconf").mock(return_value=_priv([NETWORK_RECORD, created]))

    record = await IntegrationWrites(client).create_network(dict(VLAN_PAYLOAD))

    assert record == created
    assert v1_post.called and not priv_post.called
    sent = json.loads(v1_post.calls.last.request.content)
    assert sent["management"] == "GATEWAY"
    assert sent["vlanId"] == 77
    assert sent["ipv4Configuration"]["dhcpConfiguration"]["ipAddressRange"] == {
        "start": "10.0.77.6",
        "stop": "10.0.77.254",
    }


@respx.mock
async def test_guest_network_stays_private(client: UniFiClient) -> None:
    v1_post = respx.post(f"{INT}/networks")
    priv_post = respx.post(f"{PRIV}/rest/networkconf").mock(
        return_value=_priv([{"_id": "guest-id"}])
    )
    record = await IntegrationWrites(client).create_network(dict(VLAN_PAYLOAD, purpose="guest"))
    assert record == {"_id": "guest-id"}
    assert priv_post.called and not v1_post.called


@respx.mock
async def test_private_mode_never_touches_v1(client: UniFiClient) -> None:
    sites = _mock_site()
    v1_post = respx.post(f"{INT}/networks")
    respx.post(f"{PRIV}/rest/networkconf").mock(return_value=_priv([{"_id": "p"}]))
    await IntegrationWrites(client, "private").create_network(dict(VLAN_PAYLOAD))
    assert not v1_post.called and not sites.called


@respx.mock
async def test_v1_4xx_falls_back_to_private(
    client: UniFiClient, caplog: pytest.LogCaptureFixture
) -> None:
    _mock_site()
    respx.post(f"{INT}/networks").mock(
        return_value=httpx.Response(
            400, json={"code": "api.request.error", "message": "vlanId already in use"}
        )
    )
    priv_post = respx.post(f"{PRIV}/rest/networkconf").mock(return_value=_priv([{"_id": "p"}]))
    with caplog.at_level(logging.WARNING, logger="mcp_unifi.integration"):
        record = await IntegrationWrites(client).create_network(dict(VLAN_PAYLOAD))
    assert record == {"_id": "p"}
    assert priv_post.called
    warning = next(r for r in caplog.records if "refused" in r.getMessage())
    assert warning.__dict__["code"] == "api.request.error"


@respx.mock
async def test_v1_404_marks_the_route_absent(client: UniFiClient) -> None:
    _mock_site()
    v1_post = respx.post(f"{INT}/networks").mock(return_value=httpx.Response(404))
    respx.post(f"{PRIV}/rest/networkconf").mock(return_value=_priv([{"_id": "p"}]))
    writes = IntegrationWrites(client)
    await writes.create_network(dict(VLAN_PAYLOAD))
    await writes.create_network(dict(VLAN_PAYLOAD, vlan=78))
    assert v1_post.call_count == 1


@respx.mock
async def test_v1_5xx_does_not_fall_back(client: UniFiClient) -> None:
    _mock_site()
    respx.post(f"{INT}/networks").mock(return_value=httpx.Response(502, text="bad gateway"))
    priv_post = respx.post(f"{PRIV}/rest/networkconf")
    with pytest.raises(UniFiError, match="502"):
        await IntegrationWrites(client).create_network(dict(VLAN_PAYLOAD))
    assert not priv_post.called


@respx.mock
async def test_v1_timeout_does_not_fall_back(client: UniFiClient) -> None:
    _mock_site()
    respx.post(f"{INT}/networks").mock(side_effect=httpx.ReadTimeout("slow"))
    priv_post = respx.post(f"{PRIV}/rest/networkconf")
    with pytest.raises(UniFiError):
        await IntegrationWrites(client).create_network(dict(VLAN_PAYLOAD))
    assert not priv_post.called


@respx.mock
async def test_update_network_puts_the_merged_readback(client: UniFiClient) -> None:
    _mock_site()
    renamed = dict(NETWORK_RECORD, name="IoT-2")
    respx.get(f"{PRIV}/rest/networkconf").mock(
        side_effect=[_priv([NETWORK_RECORD]), _priv([renamed])]
    )
    respx.get(f"{INT}/networks/{NET_V1_ID}").mock(return_value=httpx.Response(200, json=V1_NETWORK))
    v1_put = respx.put(f"{INT}/networks/{NET_V1_ID}").mock(
        return_value=httpx.Response(200, json=dict(V1_NETWORK, name="IoT-2"))
    )
    priv_put = respx.put(f"{PRIV}/rest/networkconf/{NET_PRIV_ID}")

    record = await IntegrationWrites(client).update_network(NET_PRIV_ID, {"name": "IoT-2"})

    assert record == renamed
    assert not priv_put.called
    sent = json.loads(v1_put.calls.last.request.content)
    assert sent["name"] == "IoT-2"
    assert "id" not in sent and "metadata" not in sent and "default" not in sent
    assert sent["ipv4Configuration"] == V1_NETWORK["ipv4Configuration"]


@respx.mock
async def test_update_network_with_an_unmapped_key_stays_private(client: UniFiClient) -> None:
    _mock_site()
    respx.get(f"{PRIV}/rest/networkconf").mock(return_value=_priv([NETWORK_RECORD]))
    respx.get(f"{INT}/networks/{NET_V1_ID}").mock(return_value=httpx.Response(200, json=V1_NETWORK))
    v1_put = respx.put(f"{INT}/networks/{NET_V1_ID}")
    priv_put = respx.put(f"{PRIV}/rest/networkconf/{NET_PRIV_ID}").mock(
        return_value=_priv([NETWORK_RECORD])
    )
    await IntegrationWrites(client).update_network(NET_PRIV_ID, {"ipv6_interface_type": "pd"})
    assert priv_put.called and not v1_put.called


@respx.mock
async def test_delete_network_uses_the_external_id(client: UniFiClient) -> None:
    _mock_site()
    respx.get(f"{PRIV}/rest/networkconf").mock(return_value=_priv([NETWORK_RECORD]))
    v1_delete = respx.delete(f"{INT}/networks/{NET_V1_ID}").mock(return_value=httpx.Response(200))
    priv_delete = respx.delete(f"{PRIV}/rest/networkconf/{NET_PRIV_ID}")
    assert await IntegrationWrites(client).delete_network(NET_PRIV_ID) is True
    assert v1_delete.called and not priv_delete.called


@respx.mock
async def test_record_without_external_id_stays_private(client: UniFiClient) -> None:
    legacy = {k: v for k, v in NETWORK_RECORD.items() if k != "external_id"}
    respx.get(f"{PRIV}/rest/networkconf").mock(return_value=_priv([legacy]))
    priv_delete = respx.delete(f"{PRIV}/rest/networkconf/{NET_PRIV_ID}").mock(
        return_value=_priv([])
    )
    assert await IntegrationWrites(client).delete_network(NET_PRIV_ID) is True
    assert priv_delete.called


# ---------------------------------------------------------------------------
# WLANs
# ---------------------------------------------------------------------------


@respx.mock
async def test_create_wlan_goes_through_v1_and_never_logs_the_passphrase(
    client: UniFiClient, caplog: pytest.LogCaptureFixture
) -> None:
    _mock_site()
    _mock_ap_groups()
    respx.get(f"{PRIV}/rest/networkconf").mock(return_value=_priv([NETWORK_RECORD]))
    created = {"_id": "new-wlan", "external_id": "wlan-uuid", "name": "cams"}
    respx.get(f"{PRIV}/rest/wlanconf").mock(return_value=_priv([created]))
    v1_post = respx.post(f"{INT}/wifi/broadcasts").mock(
        return_value=httpx.Response(201, json={"id": "wlan-uuid"})
    )
    priv_post = respx.post(f"{PRIV}/rest/wlanconf")

    with caplog.at_level(logging.DEBUG):
        record = await IntegrationWrites(client).create_wlan(dict(WLAN_PAYLOAD))

    assert record == created
    assert v1_post.called and not priv_post.called
    sent = json.loads(v1_post.calls.last.request.content)
    assert sent["network"] == {"type": "SPECIFIC", "networkId": NET_V1_ID}
    assert sent["channel2gLockedTo6"] is False
    assert PASSPHRASE not in caplog.text


@respx.mock
async def test_wlan_on_specific_ap_groups_stays_private(client: UniFiClient) -> None:
    _mock_site()
    _mock_ap_groups()
    respx.get(f"{PRIV}/rest/networkconf").mock(return_value=_priv([NETWORK_RECORD]))
    v1_post = respx.post(f"{INT}/wifi/broadcasts")
    priv_post = respx.post(f"{PRIV}/rest/wlanconf").mock(return_value=_priv([{"_id": "w"}]))
    await IntegrationWrites(client).create_wlan(dict(WLAN_PAYLOAD, ap_group_ids=["upstairs"]))
    assert priv_post.called and not v1_post.called


@respx.mock
async def test_update_wlan_rename_through_v1(client: UniFiClient) -> None:
    _mock_site()
    renamed = dict(WLAN_RECORD, name="iot-2")
    respx.get(f"{PRIV}/rest/wlanconf").mock(side_effect=[_priv([WLAN_RECORD]), _priv([renamed])])
    respx.get(f"{INT}/wifi/broadcasts/{WLAN_V1_ID}").mock(
        return_value=httpx.Response(200, json=V1_WLAN)
    )
    v1_put = respx.put(f"{INT}/wifi/broadcasts/{WLAN_V1_ID}").mock(
        return_value=httpx.Response(200, json=dict(V1_WLAN, name="iot-2"))
    )
    record = await IntegrationWrites(client).update_wlan(WLAN_PRIV_ID, {"name": "iot-2"})
    assert record == renamed
    sent = json.loads(v1_put.calls.last.request.content)
    assert sent["name"] == "iot-2"
    assert sent["securityConfiguration"]["passphrase"] == PASSPHRASE


@respx.mock
async def test_delete_wlan_uses_the_external_id(client: UniFiClient) -> None:
    _mock_site()
    respx.get(f"{PRIV}/rest/wlanconf").mock(return_value=_priv([WLAN_RECORD]))
    v1_delete = respx.delete(f"{INT}/wifi/broadcasts/{WLAN_V1_ID}").mock(
        return_value=httpx.Response(200)
    )
    priv_delete = respx.delete(f"{PRIV}/rest/wlanconf/{WLAN_PRIV_ID}")
    assert await IntegrationWrites(client).delete_wlan(WLAN_PRIV_ID) is True
    assert v1_delete.called and not priv_delete.called


# ---------------------------------------------------------------------------
# Through the tool layer: create_vlan with write_api=auto
# ---------------------------------------------------------------------------


@pytest.fixture
async def auto_server(real_settings: Settings) -> AsyncIterator[FastMCP]:
    settings = real_settings.model_copy()
    settings.controllers = [
        c.model_copy(update={"write_api": "auto"}) for c in settings.controllers
    ]
    c = UniFiClient(host="gateway.test", api_key="test-api-key-1234")
    yield build_server(settings, unifi=c)
    await c.aclose()


@respx.mock
async def test_create_vlan_tool_routes_through_v1(auto_server: FastMCP) -> None:
    _mock_site()
    v1_post = respx.post(f"{INT}/networks").mock(
        return_value=httpx.Response(201, json={"id": "new-uuid"})
    )
    priv_post = respx.post(f"{PRIV}/rest/networkconf")
    created = {"_id": "new-private-id", "external_id": "new-uuid", "name": "cams", "vlan": 77}
    respx.get(f"{PRIV}/rest/networkconf").mock(return_value=_priv([created]))

    raw = await auto_server.call_tool(
        "create_vlan", {"name": "cams", "vlan_id": 77, "subnet": "10.0.77.0/24"}
    )
    result = json.loads(raw.content[0].text)

    assert result["_id"] == "new-private-id"
    assert v1_post.called and not priv_post.called
