"""Tests for ``mcp_unifi.modules.network.console``.

The 0.18.0 console tools shipped without coverage. These tests exist because
the release they belong to was written to eliminate one defect class: **this
server reported failures as benign-looking successes.** A console tool that
answers an HTTP 500 with a tidy record of nulls is that same defect wearing a
different hat, so it gets a test rather than a promise.
"""

from __future__ import annotations

import httpx
import respx
from fastmcp import FastMCP

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
