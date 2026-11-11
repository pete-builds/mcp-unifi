"""Tests for ``mcp_unifi.modules.network.console``.

The 0.18.0 console tools shipped without coverage. These tests exist because
the release they belong to was written to eliminate one defect class: **this
server reported failures as benign-looking successes.** A console tool that
answers an HTTP 500 with a tidy record of nulls is that same defect wearing a
different hat, so it gets a test rather than a promise.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from fastmcp import FastMCP
from pydantic import SecretStr

from mcp_unifi.clients.unifi_os import ProbeResult
from mcp_unifi.config import ControllerConfig, Settings
from mcp_unifi.modules.network.console import _classify
from mcp_unifi.server import build_server
from tests.network.conftest import _call

OS_BASE = "https://gateway.test:443"
SYSTEM = f"{OS_BASE}/api/system"
APPS = f"{OS_BASE}/api/apps"

_HEALTHY_SYSTEM = {
    "hardware": {"shortname": "UCGF"},
    "name": "Cloud Gateway Fiber",
    "mac": "aa:bb:cc:dd:ee:ff",
    "deviceState": "setup",
    "hasInternet": True,
    "cloudConnected": True,
    "remoteAccessEnabled": False,
    "isSsoEnabled": False,
}


@respx.mock
async def test_console_info_returns_identity_on_a_healthy_console(
    real_server: FastMCP,
) -> None:
    respx.get(SYSTEM).mock(return_value=httpx.Response(200, json=_HEALTHY_SYSTEM))
    respx.get(APPS).mock(return_value=httpx.Response(200, json={"apps": [], "controllers": []}))

    result = await _call(real_server, "get_console_info")

    assert result["model"] == "UCGF"
    assert result["name"] == "Cloud Gateway Fiber"
    assert result["has_internet"] is True
    assert result["installed_apps"] == {"apps": [], "controllers": []}


@respx.mock
async def test_console_info_reports_a_500_as_an_error_not_a_record_of_nulls(
    real_server: FastMCP,
) -> None:
    """REGRESSION: an HTTP error with a JSON body read as a successful record.

    ``ProbeResult.reachable`` is ``status is not None``, so *any* HTTP answer
    counts as reachable, 5xx included. The body of a 500 is still a dict, so
    every ``body.get(...)`` returned ``None`` and the tool emitted a
    well-formed record in which every field was null: the exact
    benign-looking-failure shape 0.18.0 was written to remove.
    """
    respx.get(SYSTEM).mock(
        return_value=httpx.Response(500, json={"code": "ISE", "message": "boom"})
    )
    respx.get(APPS).mock(return_value=httpx.Response(500, json={"code": "ISE"}))

    result = await _call(real_server, "get_console_info")

    assert "error" in result
    assert "500" in result["error"]
    assert "model" not in result


@respx.mock
async def test_console_info_reports_a_401_as_an_error(real_server: FastMCP) -> None:
    """A 401 carries a JSON body too, and must not read as an empty console."""
    respx.get(SYSTEM).mock(return_value=httpx.Response(401, json={"message": "Unauthorized"}))
    respx.get(APPS).mock(return_value=httpx.Response(401, json={"message": "Unauthorized"}))

    result = await _call(real_server, "get_console_info")

    assert "error" in result
    assert "401" in result["error"]


@respx.mock
async def test_console_info_reports_an_unreachable_console(real_server: FastMCP) -> None:
    respx.get(SYSTEM).mock(side_effect=httpx.ConnectError("connection refused"))
    respx.get(APPS).mock(side_effect=httpx.ConnectError("connection refused"))

    result = await _call(real_server, "get_console_info")

    assert "error" in result
    assert "unreachable" in result["error"]


@respx.mock
async def test_console_info_does_not_pass_off_a_failed_apps_probe_as_inventory(
    real_server: FastMCP,
) -> None:
    """A 500 from /api/apps must not be reported as the application inventory.

    The old code assigned ``apps.body`` whenever it was a dict, so an error
    body was handed back under ``installed_apps`` as though it were real.
    """
    respx.get(SYSTEM).mock(return_value=httpx.Response(200, json=_HEALTHY_SYSTEM))
    respx.get(APPS).mock(
        return_value=httpx.Response(503, json={"code": "UNAVAILABLE", "message": "starting"})
    )

    result = await _call(real_server, "get_console_info")

    # The console itself answered, so identity is still reported...
    assert result["model"] == "UCGF"
    # ...but the failed probe is named as failed, never silently nulled or
    # passed through as if it were the inventory.
    assert result["installed_apps"] is None
    assert "503" in result["installed_apps_error"]


@respx.mock
async def test_console_info_reports_a_non_json_body_as_an_error(real_server: FastMCP) -> None:
    respx.get(SYSTEM).mock(return_value=httpx.Response(200, text="<html>console shell</html>"))
    respx.get(APPS).mock(return_value=httpx.Response(200, json={}))

    result = await _call(real_server, "get_console_info")

    assert "error" in result
    assert "no JSON body" in result["error"]


# ---------------------------------------------------------------------------
# get_console_health: a failed corroboration probe is "unknown", not "down"
# ---------------------------------------------------------------------------

_CONSOLE_UP = ProbeResult("/api/system", status=200, body={})
# The documented HEALTHY envelope: it carries no readiness fields at all.
_STATUS_MINIMAL = ProbeResult(
    "/proxy/network/status", status=200, body={"meta": {"rc": "ok", "uuid": "x"}, "data": []}
)


@pytest.mark.parametrize(
    "serving",
    [
        pytest.param(ProbeResult("/stat/sysinfo", error="ReadTimeout: timed out"), id="timeout"),
        pytest.param(ProbeResult("/stat/sysinfo", status=404), id="404"),
        pytest.param(ProbeResult("/stat/sysinfo", status=401), id="401"),
        pytest.param(ProbeResult("/stat/sysinfo", status=403), id="403"),
        pytest.param(ProbeResult("/stat/sysinfo", status=429), id="429"),
    ],
)
def test_a_failed_corroboration_probe_is_inconclusive_not_an_outage(
    serving: ProbeResult,
) -> None:
    """REGRESSION: a probe that never answered was reported as ``network_app_down``.

    The status endpoint carried no readiness fields, so the verdict rested on
    the corroboration probe alone, and any probe that was not 2xx fell through
    to "DOWN". A timeout, a throttle or an auth failure on that one probe is
    the absence of evidence, not evidence the app is dead.
    """
    verdict = _classify(_CONSOLE_UP, _STATUS_MINIMAL, serving)
    assert verdict["state"] == "unknown"
    assert verdict["network_app"] == "unknown"
    assert "inconclusive" in verdict["summary"]
    # The probe's own failure is named, so the operator can see why.
    assert (serving.error or f"HTTP {serving.status}") in verdict["summary"]


@pytest.mark.parametrize("status", [500, 502, 503])
def test_a_corroboration_probe_that_answered_5xx_still_means_down(status: int) -> None:
    serving = ProbeResult("/stat/sysinfo", status=status)
    verdict = _classify(_CONSOLE_UP, _STATUS_MINIMAL, serving)
    assert verdict["state"] == "network_app_down"
    assert f"HTTP {status}" in verdict["summary"]


def test_a_status_envelope_that_declares_the_app_down_stands_without_the_probe() -> None:
    """The app's own self-report is evidence; a failed probe does not erase it."""
    status = ProbeResult(
        "/proxy/network/status",
        status=200,
        body={"meta": {"rc": "ok", "up": False, "server_running": False}, "data": []},
    )
    serving = ProbeResult("/stat/sysinfo", error="ReadTimeout: timed out")
    assert _classify(_CONSOLE_UP, status, serving)["state"] == "network_app_down"


def test_a_serving_probe_that_answered_ok_is_healthy() -> None:
    serving = ProbeResult("/stat/sysinfo", status=200, body={"data": [{"version": "10.5.67"}]})
    assert _classify(_CONSOLE_UP, _STATUS_MINIMAL, serving)["state"] == "healthy"


@respx.mock
async def test_get_console_health_reports_a_timed_out_probe_as_unknown(
    real_server: FastMCP,
) -> None:
    respx.get(SYSTEM).mock(return_value=httpx.Response(200, json=_HEALTHY_SYSTEM))
    respx.get(f"{OS_BASE}/proxy/network/status").mock(
        return_value=httpx.Response(200, json={"meta": {"rc": "ok", "uuid": "x"}, "data": []})
    )
    respx.get(f"{OS_BASE}/proxy/network/api/s/default/stat/sysinfo").mock(
        side_effect=httpx.ReadTimeout("timed out")
    )

    result = await _call(real_server, "get_console_health")

    assert result["state"] == "unknown"
    assert "ReadTimeout" in result["summary"]
    assert result["checks"][2]["error"].startswith("ReadTimeout")


# ---------------------------------------------------------------------------
# Controller alias: the console tools resolve ``default`` like every other tool
# ---------------------------------------------------------------------------


@pytest.fixture
def office_only_server(monkeypatch: pytest.MonkeyPatch) -> FastMCP:
    """Real-mode server whose only controller is named ``office``, not ``default``."""
    for var in (
        "STUB_MODE",
        "UNIFI_HOST",
        "UNIFI_API_KEY",
        "UNIFI_PORT",
        "UNIFI_SITE",
        "MCP_UNIFI_CONTROLLERS_FILE",
        "MCP_UNIFI_DEFAULT_CONTROLLER",
        "MCP_UNIFI_AUTH_TOKENS",
        "MCP_UNIFI_AUTH_REQUIRED",
    ):
        monkeypatch.delenv(var, raising=False)
    settings = Settings(
        stub_mode=False,
        log_format="text",
        auth_required=False,
        controllers=[
            ControllerConfig(
                name="office", host="office.test", api_key=SecretStr("office-key-1234"), port=443
            )
        ],
    )
    return build_server(settings)


@respx.mock
async def test_console_info_resolves_the_default_alias_to_the_only_controller(
    office_only_server: FastMCP,
) -> None:
    """REGRESSION: ``controller="default"`` was matched literally, so a deployment
    whose single controller is named ``office`` got "Unknown controller 'default'"
    from the console tools while every other tool worked."""
    respx.get("https://office.test:443/api/system").mock(
        return_value=httpx.Response(200, json=_HEALTHY_SYSTEM)
    )
    respx.get("https://office.test:443/api/apps").mock(
        return_value=httpx.Response(200, json={"apps": []})
    )

    result = await _call(office_only_server, "get_console_info")

    assert "error" not in result, result
    assert result["model"] == "UCGF"


@respx.mock
async def test_console_health_resolves_the_alias_and_names_an_unknown_controller(
    office_only_server: FastMCP,
) -> None:
    respx.get("https://office.test:443/api/system").mock(
        return_value=httpx.Response(200, json=_HEALTHY_SYSTEM)
    )
    respx.get("https://office.test:443/proxy/network/status").mock(
        return_value=httpx.Response(200, json={"meta": {"rc": "ok"}, "data": []})
    )
    respx.get("https://office.test:443/proxy/network/api/s/default/stat/sysinfo").mock(
        return_value=httpx.Response(200, json={"data": [{"version": "10.5.67"}]})
    )
    healthy = await _call(office_only_server, "get_console_health")
    assert healthy["state"] == "healthy"

    typo = await _call(office_only_server, "get_console_health", {"controller": "offcie"})
    assert "Unknown controller 'offcie'" in typo["error"]
