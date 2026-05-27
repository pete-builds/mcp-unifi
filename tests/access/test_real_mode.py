"""Real-mode tests for the Access client and tool error paths.

Mirrors ``tests/protect/test_real_mode.py``: we point an :class:`AccessClient`
at a fake host and assert on the mocked HTTP responses, so the client's
request-building, retry, and error-translation code is exercised end-to-end
without any real Access hardware. v0.10's stub-first ethos means this is the
substrate that prevents real-mode regressions until a community tester (or
future hardware purchase) validates against live UniFi Access.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

import httpx
import pytest
import respx
from fastmcp import FastMCP
from pydantic import SecretStr

from mcp_unifi.clients.access import AccessClient
from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.config import ControllerConfig, Settings
from mcp_unifi.server import build_server
from tests.access.conftest import _call

ACCESS_BASE = "https://access.test:12445/proxy/access/api/v2"


@pytest.fixture
def real_access_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[Settings]:
    """Real-mode settings pointing at a fake Access hub for respx mocking."""
    for var in (
        "STUB_MODE",
        "UNIFI_HOST",
        "UNIFI_API_KEY",
        "UNIFI_PORT",
        "UNIFI_SITE",
        "UNIFI_VERIFY_SSL",
        "UNIFI_ACCESS_HOST",
        "UNIFI_ACCESS_API_KEY",
        "UNIFI_ACCESS_PORT",
        "MCP_TRANSPORT",
        "MCP_HOST",
        "MCP_PORT",
        "LOG_LEVEL",
        "LOG_FORMAT",
        "MCP_UNIFI_CONTROLLERS_FILE",
        "MCP_UNIFI_AUTH_TOKENS",
        "MCP_UNIFI_AUTH_REQUIRED",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("MCP_UNIFI_MODULES_ENABLED", "access")
    yield Settings(
        stub_mode=False,
        log_format="text",
        auth_required=False,
        controllers=[
            ControllerConfig(
                name="default",
                host="gateway.test",
                api_key=SecretStr("test-api-key-real"),
                port=443,
                access_host="access.test",
                access_api_key=SecretStr("access-key-real"),
                access_port=12445,
            )
        ],
    )


@pytest.fixture
async def real_access_server(real_access_settings: Settings) -> AsyncIterator[FastMCP]:
    client = AccessClient(host="access.test", api_key="access-key-real", port=12445)
    server = build_server(real_access_settings, access=client)
    yield server
    await client.aclose()


# ---------------------------------------------------------------------------
# Tool happy paths
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_list_doors(real_access_server: FastMCP) -> None:
    route = respx.get(f"{ACCESS_BASE}/doors").mock(
        return_value=httpx.Response(200, json=[{"id": "d1", "name": "Front"}])
    )
    result = await _call(real_access_server, "list_doors")
    assert route.called
    assert isinstance(result, list)
    assert result[0]["id"] == "d1"


@respx.mock
async def test_real_get_door(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/doors/d1").mock(
        return_value=httpx.Response(200, json={"id": "d1", "name": "Front"})
    )
    result = await _call(real_access_server, "get_door", {"door_id": "d1"})
    assert result["id"] == "d1"


@respx.mock
async def test_real_get_door_not_found(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/doors/missing").mock(return_value=httpx.Response(200, json={}))
    result = await _call(real_access_server, "get_door", {"door_id": "missing"})
    assert "error" in result
    assert "not found" in result["error"]


@respx.mock
async def test_real_list_doors_500(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/doors").mock(return_value=httpx.Response(500, text="boom"))
    result = await _call(real_access_server, "list_doors")
    assert "error" in result
    assert result["stub_mode"] is False


@respx.mock
async def test_real_list_door_groups(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/door_groups").mock(
        return_value=httpx.Response(200, json=[{"id": "g1", "name": "All"}])
    )
    result = await _call(real_access_server, "list_door_groups")
    assert result[0]["id"] == "g1"


@respx.mock
async def test_real_list_access_policies(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/access_policies").mock(
        return_value=httpx.Response(200, json=[{"id": "p1", "active": True}])
    )
    result = await _call(real_access_server, "list_access_policies")
    assert result[0]["active"] is True


@respx.mock
async def test_real_get_access_policy(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/access_policies/p1").mock(
        return_value=httpx.Response(200, json={"id": "p1"})
    )
    result = await _call(real_access_server, "get_access_policy", {"policy_id": "p1"})
    assert result["id"] == "p1"


@respx.mock
async def test_real_list_credentials(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/credentials").mock(
        return_value=httpx.Response(200, json=[{"id": "c1", "type": "nfc"}])
    )
    result = await _call(real_access_server, "list_credentials")
    assert result[0]["type"] == "nfc"


@respx.mock
async def test_real_get_credential(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/credentials/c1").mock(
        return_value=httpx.Response(200, json={"id": "c1", "type": "nfc"})
    )
    result = await _call(real_access_server, "get_credential", {"credential_id": "c1"})
    assert result["id"] == "c1"


@respx.mock
async def test_real_audit_expiring_credentials(real_access_server: FastMCP) -> None:
    """Audit walks list_credentials client-side; mock that endpoint only."""
    import time

    now_ms = int(time.time() * 1000)
    respx.get(f"{ACCESS_BASE}/credentials").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"id": "c1", "type": "nfc", "expires_at": now_ms + 5 * 86_400 * 1000},
                {"id": "c2", "type": "pin", "expires_at": now_ms + 100 * 86_400 * 1000},
                {"id": "c3", "type": "mobile", "expires_at": None},
            ],
        )
    )
    result = await _call(real_access_server, "audit_expiring_credentials")
    assert result["count"] == 1
    assert result["credentials"][0]["id"] == "c1"


@respx.mock
async def test_real_list_visitors(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/visitors").mock(
        return_value=httpx.Response(200, json=[{"id": "v1", "full_name": "Guest"}])
    )
    result = await _call(real_access_server, "list_visitors")
    assert result[0]["id"] == "v1"


@respx.mock
async def test_real_get_visitor(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/visitors/v1").mock(
        return_value=httpx.Response(200, json={"id": "v1"})
    )
    result = await _call(real_access_server, "get_visitor", {"visitor_id": "v1"})
    assert result["id"] == "v1"


@respx.mock
async def test_real_list_access_events(real_access_server: FastMCP) -> None:
    respx.get(host="access.test", path__regex=r"^/proxy/access/api/v2/events.*").mock(
        return_value=httpx.Response(200, json=[{"id": "e1", "result": "granted"}])
    )
    result = await _call(real_access_server, "list_access_events")
    assert result[0]["id"] == "e1"


@respx.mock
async def test_real_list_access_events_500(real_access_server: FastMCP) -> None:
    respx.get(host="access.test", path__regex=r"^/proxy/access/api/v2/events.*").mock(
        return_value=httpx.Response(500, text="boom")
    )
    result = await _call(real_access_server, "list_access_events")
    assert "error" in result


@respx.mock
async def test_real_get_recent_access_events(real_access_server: FastMCP) -> None:
    respx.get(host="access.test", path__regex=r"^/proxy/access/api/v2/events.*").mock(
        return_value=httpx.Response(200, json=[{"id": "e1", "timestamp": 1, "result": "granted"}])
    )
    result = await _call(real_access_server, "get_recent_access_events", {"limit": 5})
    assert result[0]["id"] == "e1"


@respx.mock
async def test_real_summarize_access_activity(real_access_server: FastMCP) -> None:
    respx.get(host="access.test", path__regex=r"^/proxy/access/api/v2/events.*").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "id": "e1",
                    "result": "granted",
                    "door_id": "d1",
                    "door_name": "Front",
                    "user_id": "u1",
                    "user_name": "Alice",
                },
                {
                    "id": "e2",
                    "result": "denied",
                    "door_id": "d1",
                    "door_name": "Front",
                    "user_id": "u1",
                    "user_name": "Alice",
                },
            ],
        )
    )
    result = await _call(real_access_server, "summarize_access_activity")
    assert result["total"] == 2
    assert result["granted"] == 1
    assert result["denied"] == 1


@respx.mock
async def test_real_summarize_access_activity_500(real_access_server: FastMCP) -> None:
    respx.get(host="access.test", path__regex=r"^/proxy/access/api/v2/events.*").mock(
        return_value=httpx.Response(500, text="boom")
    )
    result = await _call(real_access_server, "summarize_access_activity")
    assert "error" in result


@respx.mock
async def test_real_list_failed_access_attempts(real_access_server: FastMCP) -> None:
    respx.get(host="access.test", path__regex=r"^/proxy/access/api/v2/events.*").mock(
        return_value=httpx.Response(200, json=[{"id": "e1", "result": "denied"}])
    )
    result = await _call(real_access_server, "list_failed_access_attempts")
    assert result[0]["result"] == "denied"


@respx.mock
async def test_real_list_access_devices(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/devices").mock(
        return_value=httpx.Response(200, json=[{"id": "dev1", "type": "hub"}])
    )
    result = await _call(real_access_server, "list_access_devices")
    assert result[0]["type"] == "hub"


@respx.mock
async def test_real_get_access_device(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/devices/dev1").mock(
        return_value=httpx.Response(200, json={"id": "dev1", "type": "reader"})
    )
    result = await _call(real_access_server, "get_access_device", {"device_id": "dev1"})
    assert result["type"] == "reader"


@respx.mock
async def test_real_get_access_device_not_found(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/devices/missing").mock(return_value=httpx.Response(200, json={}))
    result = await _call(real_access_server, "get_access_device", {"device_id": "missing"})
    assert "error" in result


@respx.mock
async def test_real_get_access_system_info(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/system/info").mock(
        return_value=httpx.Response(200, json={"version": "2.6.42"})
    )
    result = await _call(real_access_server, "get_access_system_info")
    assert result["version"] == "2.6.42"


@respx.mock
async def test_real_list_access_users(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/users").mock(
        return_value=httpx.Response(200, json=[{"id": "u1", "full_name": "Alice"}])
    )
    result = await _call(real_access_server, "list_access_users")
    assert result[0]["full_name"] == "Alice"


# ---------------------------------------------------------------------------
# 500-error coverage for the remaining tools (one assertion each so every
# tool's UniFiError branch is exercised end-to-end).
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_get_door_500(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/doors/d1").mock(return_value=httpx.Response(500, text="boom"))
    result = await _call(real_access_server, "get_door", {"door_id": "d1"})
    assert "error" in result


@respx.mock
async def test_real_list_door_groups_500(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/door_groups").mock(return_value=httpx.Response(500, text="boom"))
    result = await _call(real_access_server, "list_door_groups")
    assert "error" in result


@respx.mock
async def test_real_list_access_policies_500(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/access_policies").mock(
        return_value=httpx.Response(500, text="boom")
    )
    result = await _call(real_access_server, "list_access_policies")
    assert "error" in result


@respx.mock
async def test_real_get_access_policy_500(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/access_policies/p1").mock(
        return_value=httpx.Response(500, text="boom")
    )
    result = await _call(real_access_server, "get_access_policy", {"policy_id": "p1"})
    assert "error" in result


@respx.mock
async def test_real_list_credentials_500(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/credentials").mock(return_value=httpx.Response(500, text="boom"))
    result = await _call(real_access_server, "list_credentials")
    assert "error" in result


@respx.mock
async def test_real_get_credential_500(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/credentials/c1").mock(
        return_value=httpx.Response(500, text="boom")
    )
    result = await _call(real_access_server, "get_credential", {"credential_id": "c1"})
    assert "error" in result


@respx.mock
async def test_real_audit_expiring_credentials_500(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/credentials").mock(return_value=httpx.Response(500, text="boom"))
    result = await _call(real_access_server, "audit_expiring_credentials")
    assert "error" in result


@respx.mock
async def test_real_list_visitors_500(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/visitors").mock(return_value=httpx.Response(500, text="boom"))
    result = await _call(real_access_server, "list_visitors")
    assert "error" in result


@respx.mock
async def test_real_get_visitor_500(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/visitors/v1").mock(return_value=httpx.Response(500, text="boom"))
    result = await _call(real_access_server, "get_visitor", {"visitor_id": "v1"})
    assert "error" in result


@respx.mock
async def test_real_get_recent_access_events_500(real_access_server: FastMCP) -> None:
    respx.get(host="access.test", path__regex=r"^/proxy/access/api/v2/events.*").mock(
        return_value=httpx.Response(500, text="boom")
    )
    result = await _call(real_access_server, "get_recent_access_events")
    assert "error" in result


@respx.mock
async def test_real_list_failed_access_attempts_500(real_access_server: FastMCP) -> None:
    respx.get(host="access.test", path__regex=r"^/proxy/access/api/v2/events.*").mock(
        return_value=httpx.Response(500, text="boom")
    )
    result = await _call(real_access_server, "list_failed_access_attempts")
    assert "error" in result


@respx.mock
async def test_real_list_access_devices_500(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/devices").mock(return_value=httpx.Response(500, text="boom"))
    result = await _call(real_access_server, "list_access_devices")
    assert "error" in result


@respx.mock
async def test_real_get_access_device_500(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/devices/dev1").mock(return_value=httpx.Response(500, text="boom"))
    result = await _call(real_access_server, "get_access_device", {"device_id": "dev1"})
    assert "error" in result


@respx.mock
async def test_real_get_access_system_info_500(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/system/info").mock(return_value=httpx.Response(500, text="boom"))
    result = await _call(real_access_server, "get_access_system_info")
    assert "error" in result


@respx.mock
async def test_real_list_access_users_500(real_access_server: FastMCP) -> None:
    respx.get(f"{ACCESS_BASE}/users").mock(return_value=httpx.Response(500, text="boom"))
    result = await _call(real_access_server, "list_access_users")
    assert "error" in result


# ---------------------------------------------------------------------------
# AccessClient direct tests (transport + retry shape)
# ---------------------------------------------------------------------------


@respx.mock
async def test_client_retries_on_connect_error() -> None:
    """One ConnectError gets retried; the second attempt succeeds."""
    client = AccessClient(host="access.test", api_key="k", port=12445)
    try:
        route = respx.get(f"{ACCESS_BASE}/doors").mock(
            side_effect=[
                httpx.ConnectError("simulated"),
                httpx.Response(200, json=[{"id": "d1"}]),
            ]
        )
        result = await client.list_doors()
        assert route.call_count == 2
        assert result[0]["id"] == "d1"
    finally:
        await client.aclose()


@respx.mock
async def test_client_raises_after_two_connect_errors() -> None:
    """Both attempts fail => UniFiError surfaces to the caller."""
    client = AccessClient(host="access.test", api_key="k", port=12445)
    try:
        respx.get(f"{ACCESS_BASE}/doors").mock(
            side_effect=[
                httpx.ConnectError("first"),
                httpx.ConnectError("second"),
            ]
        )
        with pytest.raises(UniFiError):
            await client.list_doors()
    finally:
        await client.aclose()


@respx.mock
async def test_client_handles_empty_body() -> None:
    """A 204-style empty body yields None, normalised to []/{} by list/get."""
    client = AccessClient(host="access.test", api_key="k", port=12445)
    try:
        respx.get(f"{ACCESS_BASE}/doors").mock(return_value=httpx.Response(204, content=b""))
        assert await client.list_doors() == []
    finally:
        await client.aclose()


@respx.mock
async def test_client_http_error_wraps_uniferror() -> None:
    """Non-ConnectError httpx errors get wrapped into UniFiError."""
    client = AccessClient(host="access.test", api_key="k", port=12445)
    try:
        respx.get(f"{ACCESS_BASE}/doors").mock(side_effect=httpx.TimeoutException("slow"))
        with pytest.raises(UniFiError):
            await client.list_doors()
    finally:
        await client.aclose()


@respx.mock
async def test_client_list_events_builds_query_string() -> None:
    """list_events should emit start=, end=, limit= and the optional filters."""
    client = AccessClient(host="access.test", api_key="k", port=12445)
    try:
        captured: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            return httpx.Response(200, json=[])

        respx.get(host="access.test", path__regex=r"^/proxy/access/api/v2/events.*").mock(
            side_effect=handler
        )
        await client.list_events(1000, 2000, 25, result="denied", door_id="d1")
        url = captured["url"]
        assert "start=1000" in url
        assert "end=2000" in url
        assert "limit=25" in url
        assert "result=denied" in url
        assert "door_id=d1" in url
    finally:
        await client.aclose()


@respx.mock
async def test_client_list_events_omits_empty_filters() -> None:
    """Empty ``result`` and ``door_id`` should not appear in the query string."""
    client = AccessClient(host="access.test", api_key="k", port=12445)
    try:
        captured: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            return httpx.Response(200, json=[])

        respx.get(host="access.test", path__regex=r"^/proxy/access/api/v2/events.*").mock(
            side_effect=handler
        )
        await client.list_events(0, 1, 5)
        url = captured["url"]
        assert "result=" not in url
        assert "door_id=" not in url
    finally:
        await client.aclose()


@respx.mock
async def test_client_get_door_normalises_list_response() -> None:
    """Some Access endpoints occasionally return a 1-item list instead of a dict."""
    client = AccessClient(host="access.test", api_key="k", port=12445)
    try:
        respx.get(f"{ACCESS_BASE}/doors/d1").mock(
            return_value=httpx.Response(200, json=[{"id": "d1"}])
        )
        out = await client.get_door("d1")
        assert out == {"id": "d1"}
    finally:
        await client.aclose()


@respx.mock
async def test_client_get_door_handles_scalar_response() -> None:
    """An unexpected scalar coerces to {}, not a raise."""
    client = AccessClient(host="access.test", api_key="k", port=12445)
    try:
        respx.get(f"{ACCESS_BASE}/doors/d1").mock(return_value=httpx.Response(200, json=42))
        out = await client.get_door("d1")
        assert out == {}
    finally:
        await client.aclose()


@respx.mock
async def test_client_uses_x_api_key_header() -> None:
    """Every request must carry the X-API-Key header for the read surface."""
    client = AccessClient(host="access.test", api_key="secret-key", port=12445)
    try:
        captured: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["api_key"] = request.headers.get("x-api-key", "")
            return httpx.Response(200, json=[])

        respx.get(f"{ACCESS_BASE}/doors").mock(side_effect=handler)
        await client.list_doors()
        assert captured["api_key"] == "secret-key"
    finally:
        await client.aclose()
