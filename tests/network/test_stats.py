"""Tests for the Wave C stats & insights tools in
``mcp_unifi.modules.network.stats``.

Every tool here is read-only: get_system_info, get_gateway_stats,
get_device_stats, get_client_stats, get_client_sessions, get_anomalies.
Covers stub-mode shaping, not-found / validation envelopes, and real-mode
HTTP wiring (``/stat/sysinfo``, ``/stat/device``, ``/stat/sta``,
``POST /stat/session``, ``/stat/anomalies``).
"""

from __future__ import annotations

import time

import httpx
import respx
from fastmcp import FastMCP

from mcp_unifi.clients.stats_shape import (
    shape_client_stats,
    shape_device_stats,
    shape_gateway_stats,
    shape_session,
    shape_system_info,
)
from mcp_unifi.clients.stubs import StubState
from tests.network.conftest import BASE, _call

# ---------------------------------------------------------------------------
# Stub mode
# ---------------------------------------------------------------------------


async def test_get_system_info_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_system_info")
    assert result["version"] == "10.4.57"
    assert result["ubnt_device_type"] == "UDMA6A8"
    assert result["update_available"] is False


async def test_get_gateway_stats_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_gateway_stats")
    assert result["type"] == "ugw"
    assert result["cpu_pct"] == 11.7
    assert result["mem_pct"] == 82.3
    temps = {t["name"]: t["value"] for t in result["temperatures"]}
    assert temps["CPU"] == 51.8
    assert "tx_bytes" in result and "rx_bytes" in result


async def test_get_device_stats_stub(stub_server: FastMCP, stub_state: StubState) -> None:
    mac = "f4:e2:c6:00:00:02"  # the seeded AP
    result = await _call(stub_server, "get_device_stats", {"mac": mac})
    assert result["mac"] == mac
    assert result["type"] == "uap"
    assert result["cpu_pct"] == 6.4
    assert result["tx_retries"] == 185_271_001


async def test_get_device_stats_case_insensitive(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_device_stats", {"mac": "F4:E2:C6:00:00:02"})
    assert result["type"] == "uap"


async def test_get_device_stats_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_device_stats", {"mac": "00:00:00:00:00:00"})
    assert "error" in result
    assert "not found" in result["error"]


async def test_get_client_stats_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_client_stats", {"mac": "aa:bb:cc:00:00:01"})
    assert result["hostname"] == "petes-laptop"
    assert result["signal"] == -52
    assert result["is_wired"] is False
    assert "tx_bytes" in result


async def test_get_client_stats_wired(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_client_stats", {"mac": "aa:bb:cc:00:00:03"})
    assert result["is_wired"] is True
    # Wireless-only fields are dropped when absent.
    assert "signal" not in result


async def test_get_client_stats_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_client_stats", {"mac": "00:00:00:00:00:00"})
    assert "error" in result
    assert "not found" in result["error"]


async def test_get_client_sessions_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_client_sessions", {"hours": 48})
    assert isinstance(result, list)
    assert len(result) == 2
    # Newest first.
    assert result[0]["assoc_time"] >= result[1]["assoc_time"]
    assert "duration" in result[0]


async def test_get_client_sessions_filters_by_mac(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server, "get_client_sessions", {"mac": "aa:bb:cc:00:00:01", "hours": 48}
    )
    assert len(result) == 1
    assert result[0]["mac"] == "aa:bb:cc:00:00:01"


async def test_get_client_sessions_window_excludes_old(stub_server: FastMCP) -> None:
    # The second seeded session is ~24h old; a 2h window drops it.
    result = await _call(stub_server, "get_client_sessions", {"hours": 2})
    assert len(result) == 1


async def test_get_client_sessions_limit(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_client_sessions", {"hours": 48, "limit": 1})
    assert len(result) == 1


async def test_get_client_sessions_invalid_hours(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_client_sessions", {"hours": 0})
    assert "hours" in result["error"]


async def test_get_client_sessions_invalid_limit(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_client_sessions", {"limit": 0})
    assert "limit" in result["error"]


async def test_get_anomalies_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_anomalies")
    assert isinstance(result, list)
    assert result[0]["anomaly"] == "USER_HIGH_TCP_LATENCY"
    assert isinstance(result[0]["timestamps"], list)


# ---------------------------------------------------------------------------
# Shaping helpers (direct unit coverage of edge cases)
# ---------------------------------------------------------------------------


def test_shape_helpers_tolerate_non_dict() -> None:
    assert shape_system_info("not-a-dict") == {}  # type: ignore[arg-type]
    assert shape_gateway_stats(None) == {}  # type: ignore[arg-type]
    assert shape_device_stats([]) == {}  # type: ignore[arg-type]
    assert shape_client_stats(42) == {}  # type: ignore[arg-type]
    assert shape_session(None) == {}  # type: ignore[arg-type]


def test_shape_gateway_stats_handles_missing_sys_stats() -> None:
    out = shape_gateway_stats({"mac": "x", "type": "ugw"})
    assert out["mac"] == "x"
    # cpu/mem absent → dropped, not None.
    assert "cpu_pct" not in out
    assert "temperatures" not in out


def test_shape_gateway_stats_coerces_string_stats() -> None:
    out = shape_gateway_stats(
        {
            "type": "udm",
            "system-stats": {"cpu": "9.9", "mem": "70.0"},
            "temperatures": [{"name": "CPU", "type": "cpu", "value": "50.5"}],
        }
    )
    assert out["cpu_pct"] == 9.9
    assert out["temperatures"][0]["value"] == 50.5


def test_shape_device_stats_pulls_ap_retries() -> None:
    out = shape_device_stats(
        {"mac": "m", "type": "uap", "stat": {"ap": {"tx_retries": 5, "tx_packets": 9}}}
    )
    assert out["tx_retries"] == 5
    assert out["tx_packets"] == 9


# ---------------------------------------------------------------------------
# Real mode
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_get_system_info(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/sysinfo").mock(
        return_value=httpx.Response(
            200, json={"data": [{"version": "10.4.57", "ubnt_device_type": "UDMA6A8"}]}
        )
    )
    result = await _call(real_server, "get_system_info")
    assert result["version"] == "10.4.57"


@respx.mock
async def test_real_get_gateway_stats(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/device").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {"type": "uap", "mac": "ap"},
                    {
                        "type": "ugw",
                        "mac": "gw",
                        "system-stats": {"cpu": "12.0", "mem": "80.0"},
                        "temperatures": [{"name": "CPU", "type": "cpu", "value": 50}],
                        "tx_bytes": 100,
                        "rx_bytes": 200,
                    },
                ]
            },
        )
    )
    result = await _call(real_server, "get_gateway_stats")
    assert result["mac"] == "gw"
    assert result["cpu_pct"] == 12.0
    assert result["tx_bytes"] == 100


@respx.mock
async def test_real_get_gateway_stats_no_gateway(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/device").mock(
        return_value=httpx.Response(200, json={"data": [{"type": "uap", "mac": "ap"}]})
    )
    result = await _call(real_server, "get_gateway_stats")
    assert result == {}


@respx.mock
async def test_real_get_device_stats(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/device").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {"type": "uap", "mac": "aa:bb", "name": "AP", "uptime": 5},
                ]
            },
        )
    )
    result = await _call(real_server, "get_device_stats", {"mac": "aa:bb"})
    assert result["name"] == "AP"
    assert result["uptime"] == 5


@respx.mock
async def test_real_get_device_stats_missing(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/device").mock(return_value=httpx.Response(200, json={"data": []}))
    result = await _call(real_server, "get_device_stats", {"mac": "aa:bb"})
    assert "error" in result
    assert "not found" in result["error"]


@respx.mock
async def test_real_get_client_stats(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/sta").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"mac": "cc:dd", "hostname": "phone", "signal": -60}]},
        )
    )
    result = await _call(real_server, "get_client_stats", {"mac": "cc:dd"})
    assert result["hostname"] == "phone"
    assert result["signal"] == -60


@respx.mock
async def test_real_get_client_stats_missing(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/sta").mock(return_value=httpx.Response(200, json={"data": []}))
    result = await _call(real_server, "get_client_stats", {"mac": "cc:dd"})
    assert "error" in result


@respx.mock
async def test_real_get_client_sessions(real_server: FastMCP) -> None:
    captured: dict[str, object] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        import json as _json

        captured["body"] = _json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "data": [
                    {"mac": "cc:dd", "assoc_time": 100, "duration": 60, "rx_bytes": 9},
                    {"mac": "cc:dd", "assoc_time": 200, "duration": 30, "rx_bytes": 4},
                ]
            },
        )

    respx.post(f"{BASE}/stat/session").mock(side_effect=capture)
    result = await _call(real_server, "get_client_sessions", {"mac": "cc:dd", "hours": 24})
    # Newest-first ordering by assoc_time.
    assert result[0]["assoc_time"] == 200
    assert captured["body"]["type"] == "all"
    assert captured["body"]["mac"] == "cc:dd"
    assert captured["body"]["start"] < captured["body"]["end"]


@respx.mock
async def test_real_get_anomalies(real_server: FastMCP) -> None:
    now_ms = int(time.time()) * 1000
    respx.get(f"{BASE}/stat/anomalies").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [{"anomaly": "USER_DNS_LATENCY", "mac": "cc:dd", "timestamps": [now_ms]}]
            },
        )
    )
    result = await _call(real_server, "get_anomalies")
    assert result[0]["anomaly"] == "USER_DNS_LATENCY"


# ---------------------------------------------------------------------------
# Real mode — error envelopes (upstream 500)
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_get_system_info_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/sysinfo").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "get_system_info")
    assert "error" in result


@respx.mock
async def test_real_get_gateway_stats_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/device").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "get_gateway_stats")
    assert "error" in result


@respx.mock
async def test_real_get_device_stats_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/device").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "get_device_stats", {"mac": "aa:bb"})
    assert "error" in result


@respx.mock
async def test_real_get_client_stats_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/sta").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "get_client_stats", {"mac": "cc:dd"})
    assert "error" in result


@respx.mock
async def test_real_get_client_sessions_handles_500(real_server: FastMCP) -> None:
    respx.post(f"{BASE}/stat/session").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "get_client_sessions", {"mac": "cc:dd"})
    assert "error" in result


@respx.mock
async def test_real_get_anomalies_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/anomalies").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "get_anomalies")
    assert "error" in result
