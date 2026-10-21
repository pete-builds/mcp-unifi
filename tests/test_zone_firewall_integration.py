"""Tests for the Zone-Based Firewall half of ``IntegrationWrites`` (ADR 0009).

Rules under test:

- the firewall model is read from v1 ``firewall/zones``: 200 is zone-based, the
  400 ``zone-based-firewall-not-configured`` code is legacy (the answer Network
  10.6.106 gave live on 2026-10-17), 404 is a console without the route;
- ``write_api="private"`` reports ``disabled`` without sending a request, and
  refuses zone writes, since there is no private path for them;
- policy writes go to the documented v1 routes, and a v1 4xx is NOT replayed on
  the private API: the error reaches the caller with the console's message;
- the whole chain also holds end to end through the registered tool.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
import respx

from mcp_unifi.clients.integration import IntegrationRejectedError, IntegrationWrites
from mcp_unifi.clients.unifi import UniFiClient, UniFiError
from mcp_unifi.config import Settings
from mcp_unifi.server import build_server

ROOT = "https://gateway.test:443/proxy/network"
PRIV = f"{ROOT}/api/s/default"
SITE = "88f7af54-98f8-306a-a1c7-c9349722b1f6"
INT = f"{ROOT}/integration/v1/sites/{SITE}"

INTERNAL = "11111111-0000-4000-8000-000000000001"
EXTERNAL = "22222222-0000-4000-8000-000000000002"
NET_PRIV_ID = "6a1240635d0b83f118f710a2"
NET_V1_ID = "388c0df9-dca8-4f35-8a3f-2d00032af6db"
POLICY_ID = "33333333-0000-4000-8000-000000000003"

ZONES = [
    {"id": INTERNAL, "name": "Internal", "networkIds": [NET_V1_ID], "metadata": {}},
    {"id": EXTERNAL, "name": "External", "networkIds": [], "metadata": {}},
]
POLICY = {
    "id": POLICY_ID,
    "index": 10000,
    "metadata": {"origin": "USER_DEFINED"},
    "name": "Allow IoT to Plex",
    "enabled": True,
    "loggingEnabled": False,
    "action": {"type": "ALLOW", "allowReturnTraffic": True},
    "source": {"zoneId": INTERNAL},
    "destination": {"zoneId": INTERNAL},
    "ipProtocolScope": {"ipVersion": "IPV4"},
}


def _page(records: list[dict[str, Any]], total: int | None = None) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "data": records,
            "count": len(records),
            "offset": 0,
            "limit": 200,
            "totalCount": len(records) if total is None else total,
        },
    )


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


# ---------------------------------------------------------------------------
# Firewall model detection
# ---------------------------------------------------------------------------


@respx.mock
async def test_state_configured_on_200(client: UniFiClient) -> None:
    _mock_site()
    respx.get(f"{INT}/firewall/zones").mock(return_value=_page(ZONES))
    assert await IntegrationWrites(client).zone_firewall_state() == "configured"


@respx.mock
async def test_state_legacy_on_the_not_configured_code(client: UniFiClient) -> None:
    _mock_site()
    respx.get(f"{INT}/firewall/zones").mock(
        return_value=httpx.Response(
            400,
            json={
                "statusCode": 400,
                "code": "api.firewall.zone-based-firewall-not-configured",
                "message": "Zone-based firewall is not configured",
            },
        )
    )
    assert await IntegrationWrites(client).zone_firewall_state() == "legacy"


@respx.mock
async def test_state_unsupported_on_404(client: UniFiClient) -> None:
    _mock_site()
    respx.get(f"{INT}/firewall/zones").mock(
        return_value=httpx.Response(404, json={"code": "api.err.NotFound"})
    )
    assert await IntegrationWrites(client).zone_firewall_state() == "unsupported"


@respx.mock
async def test_state_unsupported_when_the_site_is_missing(client: UniFiClient) -> None:
    respx.get(f"{ROOT}/integration/v1/sites").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    assert await IntegrationWrites(client).zone_firewall_state() == "unsupported"


@respx.mock
async def test_state_disabled_under_private_sends_nothing(client: UniFiClient) -> None:
    sites = _mock_site()
    assert await IntegrationWrites(client, "private").zone_firewall_state() == "disabled"
    assert not sites.called


@respx.mock
async def test_state_raises_on_a_different_400(client: UniFiClient) -> None:
    _mock_site()
    respx.get(f"{INT}/firewall/zones").mock(
        return_value=httpx.Response(400, json={"code": "api.request.error"})
    )
    with pytest.raises(IntegrationRejectedError):
        await IntegrationWrites(client).zone_firewall_state()


@respx.mock
async def test_state_raises_on_5xx(client: UniFiClient) -> None:
    _mock_site()
    respx.get(f"{INT}/firewall/zones").mock(return_value=httpx.Response(502))
    with pytest.raises(UniFiError):
        await IntegrationWrites(client).zone_firewall_state()


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


@respx.mock
async def test_list_pages_until_total_count(client: UniFiClient) -> None:
    _mock_site()
    route = respx.get(f"{INT}/firewall/policies")
    route.side_effect = [
        _page([POLICY], total=2),
        _page([{**POLICY, "id": "second"}], total=2),
    ]
    records = await IntegrationWrites(client).list_firewall_policies()
    assert [r["id"] for r in records] == [POLICY_ID, "second"]
    offsets = [c.request.url.params["offset"] for c in route.calls]
    assert offsets == ["0", "1"]


@respx.mock
async def test_get_policy_404_is_none(client: UniFiClient) -> None:
    _mock_site()
    respx.get(f"{INT}/firewall/policies/{POLICY_ID}").mock(return_value=httpx.Response(404))
    assert await IntegrationWrites(client).get_firewall_policy(POLICY_ID) is None


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------


@respx.mock
async def test_create_posts_the_body_to_v1(client: UniFiClient) -> None:
    _mock_site()
    post = respx.post(f"{INT}/firewall/policies").mock(
        return_value=httpx.Response(201, json=POLICY)
    )
    body = {k: v for k, v in POLICY.items() if k not in {"id", "index", "metadata"}}
    created = await IntegrationWrites(client).create_firewall_policy(body)
    assert created["id"] == POLICY_ID
    assert json.loads(post.calls.last.request.content) == body


@respx.mock
async def test_create_4xx_is_not_replayed_on_the_private_api(client: UniFiClient) -> None:
    _mock_site()
    respx.post(f"{INT}/firewall/policies").mock(
        return_value=httpx.Response(
            400, json={"code": "api.request.error", "message": "schedule must not be null"}
        )
    )
    legacy = respx.post(f"{PRIV}/rest/firewallrule")
    with pytest.raises(IntegrationRejectedError) as excinfo:
        await IntegrationWrites(client).create_firewall_policy({"name": "x"})
    assert excinfo.value.detail == "schedule must not be null"
    assert not legacy.called


@respx.mock
async def test_create_without_an_id_is_an_error(client: UniFiClient) -> None:
    _mock_site()
    respx.post(f"{INT}/firewall/policies").mock(return_value=httpx.Response(201, json={}))
    with pytest.raises(UniFiError, match="no id"):
        await IntegrationWrites(client).create_firewall_policy({"name": "x"})


@respx.mock
async def test_update_puts_and_delete_deletes(client: UniFiClient) -> None:
    _mock_site()
    put = respx.put(f"{INT}/firewall/policies/{POLICY_ID}").mock(
        return_value=httpx.Response(200, json={**POLICY, "enabled": False})
    )
    delete = respx.delete(f"{INT}/firewall/policies/{POLICY_ID}").mock(
        return_value=httpx.Response(200)
    )
    writes = IntegrationWrites(client)
    updated = await writes.update_firewall_policy(POLICY_ID, {"enabled": False})
    assert updated["enabled"] is False
    assert json.loads(put.calls.last.request.content) == {"enabled": False}
    assert await writes.delete_firewall_policy(POLICY_ID) is True
    assert delete.called


@respx.mock
async def test_private_mode_refuses_zone_writes(client: UniFiClient) -> None:
    sites = _mock_site()
    with pytest.raises(UniFiError, match="write_api=private"):
        await IntegrationWrites(client, "private").create_firewall_policy({"name": "x"})
    assert not sites.called


async def test_policy_id_is_checked_as_a_path_segment(client: UniFiClient) -> None:
    writes = IntegrationWrites(client)
    writes._site_id = SITE
    with pytest.raises(UniFiError):
        await writes.delete_firewall_policy("../networks/x")


# ---------------------------------------------------------------------------
# End to end through the registered tool
# ---------------------------------------------------------------------------


@pytest.fixture
async def auto_server(real_settings: Settings) -> AsyncIterator[Any]:
    # ``real_settings`` clears the environment; this rebuilds it with the
    # default write_api, which the shared fixture pins to private.
    del real_settings
    settings = Settings(
        stub_mode=False,
        unifi_host="gateway.test",
        unifi_port=443,
        unifi_site="default",
        unifi_api_key="test-api-key-1234",
        unifi_write_api="auto",
        log_format="text",
        auth_required=False,
    )
    client = UniFiClient(host="gateway.test", api_key="test-api-key-1234")
    yield build_server(settings, unifi=client)
    await client.aclose()


@respx.mock
async def test_tool_creates_a_policy_with_translated_network_ids(auto_server: Any) -> None:
    _mock_site()
    respx.get(f"{INT}/firewall/zones").mock(return_value=_page(ZONES))
    respx.get(f"{PRIV}/rest/networkconf").mock(
        return_value=httpx.Response(
            200,
            json={
                "meta": {"rc": "ok"},
                "data": [{"_id": NET_PRIV_ID, "external_id": NET_V1_ID, "name": "IoT"}],
            },
        )
    )
    post = respx.post(f"{INT}/firewall/policies").mock(
        return_value=httpx.Response(201, json=POLICY)
    )
    raw = await auto_server.call_tool(
        "create_firewall_policy",
        {
            "name": "Allow IoT to Plex",
            "action": "allow",
            "source_zone": "internal",
            "destination_zone": "Internal",
            "protocol": "tcp",
            "source_network_ids": [NET_PRIV_ID],
            "destination_addresses": ["192.168.86.20"],
            "destination_ports": "32400",
        },
    )
    result = json.loads(raw.content[0].text)
    assert result["id"] == POLICY_ID
    sent = json.loads(post.calls.last.request.content)
    assert sent["source"]["zoneId"] == INTERNAL
    assert sent["source"]["trafficFilter"]["networkFilter"]["networkIds"] == [NET_V1_ID]
    assert sent["destination"]["trafficFilter"]["portFilter"]["items"] == [
        {"type": "PORT_NUMBER", "value": 32400}
    ]


@respx.mock
async def test_tool_on_a_legacy_site_writes_nothing(auto_server: Any) -> None:
    _mock_site()
    respx.get(f"{INT}/firewall/zones").mock(
        return_value=httpx.Response(
            400, json={"code": "api.firewall.zone-based-firewall-not-configured"}
        )
    )
    post = respx.post(f"{INT}/firewall/policies")
    raw = await auto_server.call_tool(
        "create_firewall_policy",
        {"name": "x", "action": "block", "source_zone": "Internal", "destination_zone": "External"},
    )
    result = json.loads(raw.content[0].text)
    assert "create_firewall_rule" in result["error"]
    assert not post.called
