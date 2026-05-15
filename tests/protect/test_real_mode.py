"""Real-mode tests for the Protect client and tool error paths.

Mirrors the respx-mocked tests in ``tests/network/`` — we point a
:class:`ProtectClient` at a fake host and assert on the mocked HTTP responses,
so the client's request-building, retry, and error-translation code is
exercised end-to-end.
"""

from __future__ import annotations

import base64
from collections.abc import AsyncIterator, Iterator

import httpx
import pytest
import respx
from fastmcp import FastMCP

from mcp_unifi.clients.protect import ProtectClient
from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.config import ControllerConfig, Settings
from mcp_unifi.server import build_server
from tests.protect.conftest import _call

PROTECT_BASE = "https://gateway.test:443/proxy/protect/api"


@pytest.fixture
def real_protect_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[Settings]:
    """Real-mode settings pointing at a fake gateway for respx mocking."""
    for var in (
        "STUB_MODE",
        "UNIFI_HOST",
        "UNIFI_API_KEY",
        "UNIFI_PORT",
        "UNIFI_SITE",
        "UNIFI_VERIFY_SSL",
        "MCP_HOST",
        "MCP_PORT",
        "LOG_LEVEL",
        "LOG_FORMAT",
        "MCP_UNIFI_CONTROLLERS_FILE",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("MCP_UNIFI_MODULES_ENABLED", "protect")
    yield Settings(
        stub_mode=False,
        log_format="text",
        controllers=[
            ControllerConfig(
                name="default",
                host="gateway.test",
                api_key="test-api-key-real",
                port=443,
            )
        ],
    )


@pytest.fixture
async def real_protect_server(
    real_protect_settings: Settings,
) -> AsyncIterator[FastMCP]:
    client = ProtectClient(
        host="gateway.test", api_key="test-api-key-real", port=443
    )
    server = build_server(real_protect_settings, protect=client)
    yield server
    await client.aclose()


# ---------------------------------------------------------------------------
# Real-mode happy paths exercising ProtectClient request-building
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_list_cameras(real_protect_server: FastMCP) -> None:
    route = respx.get(f"{PROTECT_BASE}/cameras").mock(
        return_value=httpx.Response(
            200,
            json=[{"id": "c1", "name": "Front", "isDoorbell": True}],
        )
    )
    result = await _call(real_protect_server, "list_cameras")
    assert route.called
    assert isinstance(result, list)
    assert result[0]["id"] == "c1"


@respx.mock
async def test_real_get_camera(real_protect_server: FastMCP) -> None:
    respx.get(f"{PROTECT_BASE}/cameras/c1").mock(
        return_value=httpx.Response(200, json={"id": "c1", "name": "Front"})
    )
    result = await _call(real_protect_server, "get_camera", {"camera_id": "c1"})
    assert result["id"] == "c1"


@respx.mock
async def test_real_get_camera_not_found(real_protect_server: FastMCP) -> None:
    """Empty dict response should surface as a 'not found' error."""
    respx.get(f"{PROTECT_BASE}/cameras/missing").mock(
        return_value=httpx.Response(200, json={})
    )
    result = await _call(
        real_protect_server, "get_camera", {"camera_id": "missing"}
    )
    assert "error" in result
    assert "not found" in result["error"]


@respx.mock
async def test_real_list_cameras_500(real_protect_server: FastMCP) -> None:
    respx.get(f"{PROTECT_BASE}/cameras").mock(
        return_value=httpx.Response(500, text="boom")
    )
    result = await _call(real_protect_server, "list_cameras")
    assert "error" in result
    assert result["stub_mode"] is False


@respx.mock
async def test_real_list_motion_events_500(real_protect_server: FastMCP) -> None:
    respx.get(host="gateway.test", path__regex=r"^/proxy/protect/api/events.*").mock(
        return_value=httpx.Response(500, text="boom")
    )
    result = await _call(real_protect_server, "list_motion_events")
    assert "error" in result


@respx.mock
async def test_real_list_smart_detections_500(real_protect_server: FastMCP) -> None:
    respx.get(host="gateway.test", path__regex=r"^/proxy/protect/api/events.*").mock(
        return_value=httpx.Response(500, text="boom")
    )
    result = await _call(
        real_protect_server, "list_smart_detections", {"detection_type": "person"}
    )
    assert "error" in result


@respx.mock
async def test_real_list_recordings_happy(real_protect_server: FastMCP) -> None:
    respx.get(
        host="gateway.test", path__regex=r"^/proxy/protect/api/recordings.*"
    ).mock(
        return_value=httpx.Response(
            200, json=[{"id": "r1", "camera": "c1", "start": 1, "end": 2}]
        )
    )
    result = await _call(
        real_protect_server, "list_recordings", {"camera_id": "c1"}
    )
    assert isinstance(result, list)
    assert result[0]["id"] == "r1"


@respx.mock
async def test_real_list_recordings_500(real_protect_server: FastMCP) -> None:
    respx.get(
        host="gateway.test", path__regex=r"^/proxy/protect/api/recordings.*"
    ).mock(return_value=httpx.Response(500, text="boom"))
    result = await _call(
        real_protect_server, "list_recordings", {"camera_id": "c1"}
    )
    assert "error" in result


@respx.mock
async def test_real_get_snapshot_returns_bytes(real_protect_server: FastMCP) -> None:
    jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\xff\xd9"
    respx.get(f"{PROTECT_BASE}/cameras/c1/snapshot").mock(
        return_value=httpx.Response(200, content=jpeg)
    )
    result = await _call(real_protect_server, "get_snapshot", {"camera_id": "c1"})
    assert result["format"] == "jpeg"
    assert base64.b64decode(result["data"]) == jpeg


@respx.mock
async def test_real_get_snapshot_500(real_protect_server: FastMCP) -> None:
    respx.get(f"{PROTECT_BASE}/cameras/c1/snapshot").mock(
        return_value=httpx.Response(500, text="boom")
    )
    result = await _call(real_protect_server, "get_snapshot", {"camera_id": "c1"})
    assert "error" in result


@respx.mock
async def test_real_get_event_thumbnail(real_protect_server: FastMCP) -> None:
    jpeg = b"\xff\xd8\xff\xd9"
    respx.get(f"{PROTECT_BASE}/events/e1/thumbnail").mock(
        return_value=httpx.Response(200, content=jpeg)
    )
    result = await _call(
        real_protect_server, "get_event_thumbnail", {"event_id": "e1"}
    )
    assert base64.b64decode(result["data"]) == jpeg


@respx.mock
async def test_real_get_event_thumbnail_500(real_protect_server: FastMCP) -> None:
    respx.get(f"{PROTECT_BASE}/events/e1/thumbnail").mock(
        return_value=httpx.Response(500, text="boom")
    )
    result = await _call(
        real_protect_server, "get_event_thumbnail", {"event_id": "e1"}
    )
    assert "error" in result


@respx.mock
async def test_real_set_recording_mode(real_protect_server: FastMCP) -> None:
    respx.patch(f"{PROTECT_BASE}/cameras/c1").mock(
        return_value=httpx.Response(
            200, json={"id": "c1", "recordingSettings": {"mode": "always"}}
        )
    )
    result = await _call(
        real_protect_server,
        "set_camera_recording_mode",
        {"camera_id": "c1", "mode": "always"},
    )
    assert result["recordingSettings"]["mode"] == "always"


@respx.mock
async def test_real_set_recording_mode_500(real_protect_server: FastMCP) -> None:
    respx.patch(f"{PROTECT_BASE}/cameras/c1").mock(
        return_value=httpx.Response(500, text="boom")
    )
    result = await _call(
        real_protect_server,
        "set_camera_recording_mode",
        {"camera_id": "c1", "mode": "always"},
    )
    assert "error" in result


@respx.mock
async def test_real_set_privacy_mode(real_protect_server: FastMCP) -> None:
    respx.patch(f"{PROTECT_BASE}/cameras/c1").mock(
        return_value=httpx.Response(
            200, json={"id": "c1", "privacyMask": {"enabled": True}}
        )
    )
    result = await _call(
        real_protect_server,
        "set_camera_privacy_mode",
        {"camera_id": "c1", "enabled": True},
    )
    assert result["privacyMask"]["enabled"] is True


@respx.mock
async def test_real_set_motion_sensitivity(real_protect_server: FastMCP) -> None:
    respx.patch(f"{PROTECT_BASE}/cameras/c1").mock(
        return_value=httpx.Response(
            200, json={"id": "c1", "motionSettings": {"sensitivity": 75}}
        )
    )
    result = await _call(
        real_protect_server,
        "set_motion_sensitivity",
        {"camera_id": "c1", "sensitivity": 75},
    )
    assert result["motionSettings"]["sensitivity"] == 75


@respx.mock
async def test_real_get_camera_500(real_protect_server: FastMCP) -> None:
    respx.get(f"{PROTECT_BASE}/cameras/c1").mock(
        return_value=httpx.Response(500, text="boom")
    )
    result = await _call(real_protect_server, "get_camera", {"camera_id": "c1"})
    assert "error" in result


@respx.mock
async def test_real_set_privacy_mode_500(real_protect_server: FastMCP) -> None:
    respx.patch(f"{PROTECT_BASE}/cameras/c1").mock(
        return_value=httpx.Response(500, text="boom")
    )
    result = await _call(
        real_protect_server,
        "set_camera_privacy_mode",
        {"camera_id": "c1", "enabled": True},
    )
    assert "error" in result


@respx.mock
async def test_real_set_motion_sensitivity_500(
    real_protect_server: FastMCP,
) -> None:
    respx.patch(f"{PROTECT_BASE}/cameras/c1").mock(
        return_value=httpx.Response(500, text="boom")
    )
    result = await _call(
        real_protect_server,
        "set_motion_sensitivity",
        {"camera_id": "c1", "sensitivity": 60},
    )
    assert "error" in result


@respx.mock
async def test_real_set_recording_mode_not_found(
    real_protect_server: FastMCP,
) -> None:
    """Empty body coerces to None in ProtectRealBackend.update_camera."""
    respx.patch(f"{PROTECT_BASE}/cameras/missing").mock(
        return_value=httpx.Response(200, json={})
    )
    result = await _call(
        real_protect_server,
        "set_camera_recording_mode",
        {"camera_id": "missing", "mode": "always"},
    )
    assert "error" in result
    assert "not found" in result["error"]


@respx.mock
async def test_real_list_doorbell_messages_500(real_protect_server: FastMCP) -> None:
    respx.get(f"{PROTECT_BASE}/cameras").mock(
        return_value=httpx.Response(500, text="boom")
    )
    result = await _call(real_protect_server, "list_doorbell_messages")
    assert "error" in result


# ---------------------------------------------------------------------------
# ProtectClient direct tests (transport + retry shape)
# ---------------------------------------------------------------------------


@respx.mock
async def test_client_retries_on_connect_error() -> None:
    """One ConnectError gets retried; the second attempt succeeds."""
    client = ProtectClient(host="gateway.test", api_key="k", port=443)
    try:
        # respx side_effect runs in order: first raises, second returns 200.
        route = respx.get(f"{PROTECT_BASE}/cameras").mock(
            side_effect=[
                httpx.ConnectError("simulated"),
                httpx.Response(200, json=[{"id": "c1"}]),
            ]
        )
        result = await client.list_cameras()
        assert route.call_count == 2
        assert result[0]["id"] == "c1"
    finally:
        await client.aclose()


@respx.mock
async def test_client_raises_after_two_connect_errors() -> None:
    """Both attempts fail => UniFiError surfaces to the caller."""
    client = ProtectClient(host="gateway.test", api_key="k", port=443)
    try:
        respx.get(f"{PROTECT_BASE}/cameras").mock(
            side_effect=[
                httpx.ConnectError("first"),
                httpx.ConnectError("second"),
            ]
        )
        with pytest.raises(UniFiError):
            await client.list_cameras()
    finally:
        await client.aclose()


@respx.mock
async def test_client_handles_empty_body() -> None:
    """A 204-style empty body yields None, normalised to []/{} by list/get."""
    client = ProtectClient(host="gateway.test", api_key="k", port=443)
    try:
        respx.get(f"{PROTECT_BASE}/cameras").mock(
            return_value=httpx.Response(204, content=b"")
        )
        assert await client.list_cameras() == []
    finally:
        await client.aclose()


@respx.mock
async def test_client_http_error_wraps_uniferror() -> None:
    """Non-ConnectError httpx errors get wrapped into UniFiError."""
    client = ProtectClient(host="gateway.test", api_key="k", port=443)
    try:
        respx.get(f"{PROTECT_BASE}/cameras").mock(
            side_effect=httpx.TimeoutException("slow")
        )
        with pytest.raises(UniFiError):
            await client.list_cameras()
    finally:
        await client.aclose()


@respx.mock
async def test_client_list_events_builds_query_string() -> None:
    """list_events should emit types[]=, start=, end=, limit= in the URL."""
    client = ProtectClient(host="gateway.test", api_key="k", port=443)
    try:
        captured: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            return httpx.Response(200, json=[])

        respx.get(host="gateway.test", path__regex=r"^/proxy/protect/api/events.*").mock(
            side_effect=handler
        )
        await client.list_events(["motion", "smartDetectZone"], 1000, 2000, 5)
        url = captured["url"]
        assert "types[]=motion" in url
        assert "types[]=smartDetectZone" in url
        assert "start=1000" in url
        assert "end=2000" in url
        assert "limit=5" in url
    finally:
        await client.aclose()


@respx.mock
async def test_client_get_snapshot_returns_bytes() -> None:
    client = ProtectClient(host="gateway.test", api_key="k", port=443)
    try:
        respx.get(f"{PROTECT_BASE}/cameras/c1/snapshot").mock(
            return_value=httpx.Response(200, content=b"\x00\x01")
        )
        result = await client.get_snapshot("c1")
        assert result == b"\x00\x01"
    finally:
        await client.aclose()


@respx.mock
async def test_client_get_snapshot_retries_on_connect_error() -> None:
    client = ProtectClient(host="gateway.test", api_key="k", port=443)
    try:
        respx.get(f"{PROTECT_BASE}/cameras/c1/snapshot").mock(
            side_effect=[
                httpx.ConnectError("simulated"),
                httpx.Response(200, content=b"\x00\x01"),
            ]
        )
        assert await client.get_snapshot("c1") == b"\x00\x01"
    finally:
        await client.aclose()


@respx.mock
async def test_client_get_snapshot_raises_after_two_failures() -> None:
    client = ProtectClient(host="gateway.test", api_key="k", port=443)
    try:
        respx.get(f"{PROTECT_BASE}/cameras/c1/snapshot").mock(
            side_effect=[
                httpx.ConnectError("first"),
                httpx.ConnectError("second"),
            ]
        )
        with pytest.raises(UniFiError):
            await client.get_snapshot("c1")
    finally:
        await client.aclose()


@respx.mock
async def test_client_get_snapshot_http_error_wraps() -> None:
    client = ProtectClient(host="gateway.test", api_key="k", port=443)
    try:
        respx.get(f"{PROTECT_BASE}/cameras/c1/snapshot").mock(
            side_effect=httpx.TimeoutException("slow")
        )
        with pytest.raises(UniFiError):
            await client.get_snapshot("c1")
    finally:
        await client.aclose()


@respx.mock
async def test_client_update_camera_patch() -> None:
    client = ProtectClient(host="gateway.test", api_key="k", port=443)
    try:
        respx.patch(f"{PROTECT_BASE}/cameras/c1").mock(
            return_value=httpx.Response(200, json={"id": "c1", "name": "Updated"})
        )
        out = await client.update_camera("c1", {"name": "Updated"})
        assert out["name"] == "Updated"
    finally:
        await client.aclose()


@respx.mock
async def test_client_get_camera_normalises_list_response() -> None:
    """Some Protect endpoints occasionally return a 1-item list instead of a dict."""
    client = ProtectClient(host="gateway.test", api_key="k", port=443)
    try:
        respx.get(f"{PROTECT_BASE}/cameras/c1").mock(
            return_value=httpx.Response(200, json=[{"id": "c1"}])
        )
        out = await client.get_camera("c1")
        assert out == {"id": "c1"}
    finally:
        await client.aclose()


@respx.mock
async def test_client_get_camera_handles_scalar_response() -> None:
    """An unexpected scalar coerces to {}, not a raise."""
    client = ProtectClient(host="gateway.test", api_key="k", port=443)
    try:
        respx.get(f"{PROTECT_BASE}/cameras/c1").mock(
            return_value=httpx.Response(200, json=42)
        )
        out = await client.get_camera("c1")
        assert out == {}
    finally:
        await client.aclose()


@respx.mock
async def test_client_list_recordings_query_string() -> None:
    client = ProtectClient(host="gateway.test", api_key="k", port=443)
    try:
        captured: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            return httpx.Response(200, json=[])

        respx.get(
            host="gateway.test", path__regex=r"^/proxy/protect/api/recordings.*"
        ).mock(side_effect=handler)
        await client.list_recordings("c1", 1000, 2000)
        url = captured["url"]
        assert "camera=c1" in url
        assert "start=1000" in url
        assert "end=2000" in url
    finally:
        await client.aclose()
