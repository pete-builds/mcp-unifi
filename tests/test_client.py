"""Tests for the UniFi HTTP client (httpx mocked via respx)."""

from __future__ import annotations

import httpx
import pytest
import respx

from mcp_unifi.clients.unifi import UniFiClient, UniFiError

BASE = "https://gateway.test:443/proxy/network/api/s/default"


@pytest.fixture
async def client() -> UniFiClient:
    c = UniFiClient(host="gateway.test", api_key="test-key", verify_ssl=False)
    yield c
    await c.aclose()


# ---------------------------------------------------------------------------
# Read endpoints
# ---------------------------------------------------------------------------


@respx.mock
async def test_list_devices_unwraps_data(client: UniFiClient) -> None:
    respx.get(f"{BASE}/stat/device").mock(
        return_value=httpx.Response(200, json={"meta": {"rc": "ok"}, "data": [{"_id": "abc"}]})
    )
    result = await client.list_devices()
    assert result == [{"_id": "abc"}]


@respx.mock
async def test_list_networks_returns_empty_on_no_data(client: UniFiClient) -> None:
    respx.get(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(200, json={"meta": {"rc": "ok"}, "data": []})
    )
    assert await client.list_networks() == []


@respx.mock
async def test_list_wlans(client: UniFiClient) -> None:
    respx.get(f"{BASE}/rest/wlanconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "w1", "name": "Home"}]})
    )
    result = await client.list_wlans()
    assert result[0]["name"] == "Home"


@respx.mock
async def test_list_firewall_rules(client: UniFiClient) -> None:
    respx.get(f"{BASE}/rest/firewallrule").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "r1"}]})
    )
    assert (await client.list_firewall_rules())[0]["_id"] == "r1"


@respx.mock
async def test_list_port_profiles(client: UniFiClient) -> None:
    respx.get(f"{BASE}/rest/portconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "p1"}]})
    )
    assert (await client.list_port_profiles())[0]["_id"] == "p1"


# ---------------------------------------------------------------------------
# Write endpoints
# ---------------------------------------------------------------------------


@respx.mock
async def test_create_network_returns_first_record(client: UniFiClient) -> None:
    respx.post(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "n1", "name": "X"}]})
    )
    result = await client.create_network({"name": "X"})
    assert result == {"_id": "n1", "name": "X"}


@respx.mock
async def test_create_network_handles_dict_response(client: UniFiClient) -> None:
    respx.post(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(200, json={"_id": "n2", "name": "Y"})
    )
    result = await client.create_network({"name": "Y"})
    assert result == {"_id": "n2", "name": "Y"}


@respx.mock
async def test_create_network_handles_empty(client: UniFiClient) -> None:
    respx.post(f"{BASE}/rest/networkconf").mock(return_value=httpx.Response(200, json={"data": []}))
    assert await client.create_network({"name": "Z"}) == {}


@respx.mock
async def test_update_network_uses_put(client: UniFiClient) -> None:
    route = respx.put(f"{BASE}/rest/networkconf/n1").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "n1", "name": "P"}]})
    )
    result = await client.update_network("n1", {"name": "P"})
    assert route.called
    assert result["name"] == "P"


@respx.mock
async def test_delete_network(client: UniFiClient) -> None:
    respx.delete(f"{BASE}/rest/networkconf/n1").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    assert await client.delete_network("n1") is True


@respx.mock
async def test_create_wlan(client: UniFiClient) -> None:
    respx.post(f"{BASE}/rest/wlanconf").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "w1"}]})
    )
    result = await client.create_wlan({"name": "S"})
    assert result["_id"] == "w1"


@respx.mock
async def test_update_wlan_uses_put(client: UniFiClient) -> None:
    route = respx.put(f"{BASE}/rest/wlanconf/w1").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "w1", "name": "Renamed"}]})
    )
    result = await client.update_wlan("w1", {"name": "Renamed"})
    assert route.called
    assert result["name"] == "Renamed"


@respx.mock
async def test_delete_wlan(client: UniFiClient) -> None:
    respx.delete(f"{BASE}/rest/wlanconf/w1").mock(return_value=httpx.Response(200))
    assert await client.delete_wlan("w1") is True


@respx.mock
async def test_list_clients(client: UniFiClient) -> None:
    respx.get(f"{BASE}/stat/sta").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "c1", "mac": "aa:bb:cc:00:00:01"}]})
    )
    result = await client.list_clients()
    assert result[0]["_id"] == "c1"


@respx.mock
async def test_list_clients_empty(client: UniFiClient) -> None:
    respx.get(f"{BASE}/stat/sta").mock(return_value=httpx.Response(200, json={"data": []}))
    assert await client.list_clients() == []


@respx.mock
async def test_create_firewall_rule(client: UniFiClient) -> None:
    respx.post(f"{BASE}/rest/firewallrule").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "r1"}]})
    )
    result = await client.create_firewall_rule({"name": "X"})
    assert result["_id"] == "r1"


@respx.mock
async def test_delete_firewall_rule(client: UniFiClient) -> None:
    respx.delete(f"{BASE}/rest/firewallrule/r1").mock(return_value=httpx.Response(200))
    assert await client.delete_firewall_rule("r1") is True


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


@respx.mock
async def test_4xx_raises_unifi_error(client: UniFiClient) -> None:
    respx.get(f"{BASE}/stat/device").mock(return_value=httpx.Response(401, text="Unauthorized"))
    with pytest.raises(UniFiError) as exc:
        await client.list_devices()
    assert "401" in str(exc.value)


@respx.mock
async def test_5xx_raises_unifi_error(client: UniFiClient) -> None:
    respx.get(f"{BASE}/rest/networkconf").mock(return_value=httpx.Response(503, text="Down"))
    with pytest.raises(UniFiError):
        await client.list_networks()


@respx.mock
async def test_5xx_get_retries_then_succeeds(client: UniFiClient) -> None:
    """A transient 503 on an idempotent GET is retried until it succeeds."""
    route = respx.get(f"{BASE}/rest/networkconf").mock(
        side_effect=[
            httpx.Response(503, text="upgrading"),
            httpx.Response(503, text="upgrading"),
            httpx.Response(200, json={"data": [{"_id": "n1"}]}),
        ]
    )
    result = await client.list_networks()
    assert result == [{"_id": "n1"}]
    # 1 initial + MAX_5XX_RETRIES (2) = 3 total attempts.
    assert route.call_count == 3


@respx.mock
async def test_5xx_get_exhausts_retries_then_raises(client: UniFiClient) -> None:
    """A persistent 5xx on a GET raises after the retry budget is spent."""
    route = respx.get(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(503, text="down")
    )
    with pytest.raises(UniFiError):
        await client.list_networks()
    assert route.call_count == 3


@respx.mock
async def test_5xx_write_is_not_retried(client: UniFiClient) -> None:
    """A 5xx on a write (POST) must NOT be retried — a retried write could
    double-apply under the dry-run/confirm/rollback model."""
    route = respx.post(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(503, text="down")
    )
    with pytest.raises(UniFiError):
        await client.create_network({"name": "x"})
    assert route.call_count == 1


@respx.mock
async def test_5xx_put_is_not_retried(client: UniFiClient) -> None:
    """A 5xx on a PUT update is issued exactly once (no replay)."""
    route = respx.put(f"{BASE}/rest/networkconf/n1").mock(
        return_value=httpx.Response(500, text="boom")
    )
    with pytest.raises(UniFiError):
        await client.update_network("n1", {"name": "x"})
    assert route.call_count == 1


@respx.mock
async def test_connection_error_retries_then_raises(client: UniFiClient) -> None:
    respx.get(f"{BASE}/stat/device").mock(side_effect=httpx.ConnectError("nope"))
    with pytest.raises(UniFiError) as exc:
        await client.list_devices()
    assert "connection failed" in str(exc.value).lower()


@respx.mock
async def test_connection_error_succeeds_on_retry(client: UniFiClient) -> None:
    route = respx.get(f"{BASE}/stat/device").mock(
        side_effect=[httpx.ConnectError("nope"), httpx.Response(200, json={"data": []})]
    )
    result = await client.list_devices()
    assert result == []
    assert route.call_count == 2


@respx.mock
async def test_transport_error_raises_unifi_error(client: UniFiClient) -> None:
    respx.get(f"{BASE}/stat/device").mock(side_effect=httpx.ReadTimeout("slow"))
    with pytest.raises(UniFiError) as exc:
        await client.list_devices()
    assert "transport error" in str(exc.value).lower()


@respx.mock
async def test_204_no_content_returns_none(client: UniFiClient) -> None:
    respx.delete(f"{BASE}/rest/networkconf/n1").mock(return_value=httpx.Response(204))
    assert await client.delete_network("n1") is True


def test_client_sends_api_key_header() -> None:
    """The client must put the API key in the X-API-Key header, never the URL."""
    c = UniFiClient(host="gateway.test", api_key="secret")
    assert c._client.headers["X-API-Key"] == "secret"
    assert c._client.headers["Accept"] == "application/json"
