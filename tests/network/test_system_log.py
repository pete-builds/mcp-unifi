"""Tests for the v2 system-log readers: ``list_events``, ``list_alarms``,
``list_threat_detections``.

THE BUG THESE GUARD
-------------------
UniFi Network 10.x removed ``/stat/event`` (404), ``/list/alarm`` (400
``api.err.InvalidObject``) and ``/stat/ips/event`` (404). An earlier version
of this server turned those answers into ``[]``, so "this controller cannot
show events" read as "nothing happened". Every test named ``*_is_an_error*``
below asserts the opposite: an upstream failure comes back as an ``error``
envelope naming the full path and the HTTP status, and never as an empty
list. Do not relax them to accept ``[]``.

FIXTURES
--------
The response bodies below are synthetic, shaped field for field on these
sources (see :mod:`mcp_unifi.clients.system_log` for the line references):

* system-log page envelope and entry fields: unpoller ``unifi``
  ``system_log.go`` (``SystemLogResponse``, ``SystemLogEntry``).
* system-log request body and the ``threatTypes`` filter: Art-of-WiFi
  ``UniFi-API-client`` ``get_system_log()``.
* ``threat-alert`` rows (``THREAT_BLOCKED_V3``, ``SRC_IP`` / ``DST_IP``
  parameters) and ``traffic-flows`` rows (``source`` / ``destination`` with
  ``port``, ``policies[].type == "INTRUSION_PREVENTION"``, ``ips.signature``):
  kcorr ``unifi-security-console`` ``server/unifi/threats.ts`` and its fake
  console, and MKippen ``ZeroProof`` ``schemas/threat.ts``.

None of them was captured from a live controller. Addresses are RFC 5737
documentation ranges and MACs are the RFC 7042 documentation block.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import FastMCP

from mcp_unifi.clients.system_log import (
    iso_utc,
    parse_page,
    render_message,
    system_log_body,
)
from mcp_unifi.clients.unifi import UniFiError
from tests.network.conftest import _call

V2 = "https://gateway.test:443/proxy/network/v2/api/site/default"
V2_PATH = "/proxy/network/v2/api/site/default"
LEGACY_PATH = "/proxy/network/api/s/default"

NOT_FOUND = {"meta": {"rc": "error", "msg": "api.err.NotFound"}, "data": []}
INVALID_OBJECT = {"meta": {"rc": "error", "msg": "api.err.InvalidObject"}, "data": []}
V2_NOT_FOUND = {"code": "api.err.NotFound", "message": "Not Found"}

NOW_MS = 1_795_000_000_000  # 2026-11-17, inside any test's window is irrelevant: tests
# mock the controller, which ignores timestamps.

# --- system-log/all page (unpoller SystemLogResponse / SystemLogEntry) ------
EVENTS_PAGE: dict[str, Any] = {
    "data": [
        {
            "id": "6740aa000000000000000001",
            "timestamp": NOW_MS - 3_600_000,
            "category": "INTERNET_AND_WAN",
            "subcategory": "WAN",
            "event": "WAN_FAILOVER",
            "key": "WAN_FAILOVER_V2",
            "severity": "HIGH",
            "status": "NEW",
            "type": "INTERNET",
            "title_raw": "WAN Failover",
            "message_raw": "{DEVICE} switched to backup WAN.",
            "show_on_dashboard": True,
            "target": "DEVICE",
            "parameters": {"DEVICE": {"id": "00:00:5e:00:53:01", "name": "Gateway"}},
        },
        {
            "id": "6740aa000000000000000002",
            "timestamp": NOW_MS - 60_000,
            "category": "CLIENT_DEVICES",
            "subcategory": "WIFI",
            "event": "CLIENT_CONNECTED",
            "key": "CLIENT_CONNECTED_WIRELESS",
            "severity": "LOW",
            "status": "NEW",
            "type": "CLIENT",
            "title_raw": "Client Connected",
            "message_raw": "{CLIENT} connected to {WLAN}.",
            "show_on_dashboard": False,
            "target": "CLIENT",
            "parameters": {
                "CLIENT": {"id": "00:00:5e:00:53:10", "name": "Test Laptop"},
                "WLAN": {"id": "6740aa0000000000000000ff", "name": "Home"},
            },
        },
    ],
    "page_number": 0,
    "total_element_count": 2,
    "total_page_count": 1,
}

# --- system-log/threat-alert page (kcorr / ZeroProof row shape) -------------
THREAT_ALERT_PAGE: dict[str, Any] = {
    "data": [
        {
            # Same detection as FLOW_BLOCKED below: dropped by the merge.
            "id": "6740bb000000000000000001",
            "timestamp": NOW_MS - 300_000 + 2_000,
            "category": "SECURITY",
            "subcategory": "SECURITY_INTRUSION_PREVENTION",
            "event": "THREAT_BLOCKED",
            "key": "THREAT_BLOCKED_V3",
            "type": "THREAT_DETECTION_AND_PREVENTION",
            "severity": "HIGH",
            "status": "NEW",
            "title_raw": "Threat Detected and Blocked",
            "message": "A network intrusion attempt from 192.0.2.20 to 198.51.100.7 "
            "has been detected and blocked.",
            "parameters": {
                "SRC_IP": {"id": "192.0.2.20", "name": "192.0.2.20"},
                "DST_IP": {"id": "198.51.100.7", "name": "198.51.100.7"},
            },
        },
        {
            # Alert-only detection (no matching flow).
            "id": "6740bb000000000000000002",
            "timestamp": NOW_MS - 7_200_000,
            "category": "SECURITY",
            "subcategory": "SECURITY_INTRUSION_PREVENTION",
            "event": "THREAT_DETECTED",
            "key": "THREAT_DETECTED_V3",
            "type": "THREAT_DETECTION_AND_PREVENTION",
            "severity": "MEDIUM",
            "status": "NEW",
            "title_raw": "Threat Detected",
            "parameters": {
                "SRC_IP": {"id": "203.0.113.9", "name": "203.0.113.9"},
                "DST_IP": {"id": "192.0.2.30", "name": "192.0.2.30"},
                "DST_CLIENT": {"id": "00:00:5e:00:53:30", "name": "Test Printer"},
            },
        },
    ],
    "page_number": 0,
    "total_element_count": 2,
    "total_page_count": 1,
}

# --- traffic-flows page filtered to INTRUSION_PREVENTION (kcorr shape) ------
FLOW_BLOCKED: dict[str, Any] = {
    "id": "6740cc000000000000000001",
    "time": NOW_MS - 300_000,
    "flow_start_time": NOW_MS - 300_000,
    "count": 1,
    "action": "blocked",
    "direction": "outgoing",
    "protocol": "TCP",
    "service": "HTTPS",
    "risk": "high",
    "source": {
        "ip": "192.0.2.20",
        "port": 51514,
        "mac": "00:00:5E:00:53:20",
        "client_name": "Media Server",
        "network_name": "Default",
    },
    "destination": {"ip": "198.51.100.7", "port": 443, "region": "US"},
    "policies": [
        {
            "id": "ips-1",
            "name": "ET CINS Active Threat Intelligence Poor Reputation IP",
            "type": "INTRUSION_PREVENTION",
            "internal_type": "SIGNATURE",
            "ips_category": "CIARMY",
        }
    ],
    "ips": {
        "signature": "ET CINS Active Threat Intelligence Poor Reputation IP group 7",
        "signature_id": 2403306,
        "category_name": "ciarmy",
        "signature_class": "misc-attack",
    },
}
FLOW_NOT_IPS: dict[str, Any] = {
    # A plain firewall block: must not be reported as an IPS detection even if
    # the controller ignored the policy_type filter.
    "id": "6740cc000000000000000002",
    "time": NOW_MS - 400_000,
    "action": "blocked",
    "protocol": "UDP",
    "source": {"ip": "192.0.2.40", "port": 5353},
    "destination": {"ip": "198.51.100.99", "port": 53},
    "policies": [{"id": "fw-1", "name": "Block DNS", "type": "FIREWALL"}],
}
FLOWS_PAGE: dict[str, Any] = {
    "data": [FLOW_BLOCKED, FLOW_NOT_IPS],
    "has_next": False,
    "page_number": 0,
    "total_element_count": 2,
    "total_page_count": 1,
}


def _capture(store: dict[str, Any], key: str, body: Any) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        store[key] = json.loads(request.content)
        return httpx.Response(200, json=body)

    return handler


def _assert_error_not_empty(result: Any) -> str:
    """The shape every failure must have: an error envelope, never a list."""
    assert result != [], "an upstream failure must never be reported as an empty result"
    assert isinstance(result, dict), f"expected an error envelope, got {type(result)}"
    assert "error" in result, result
    for key in ("events", "alarms", "detections"):
        assert key not in result, f"an error must not also carry an empty {key!r} list"
    error = result["error"]
    assert isinstance(error, str)
    assert "not an empty result" in error
    return error


# ---------------------------------------------------------------------------
# list_events
# ---------------------------------------------------------------------------


@respx.mock
async def test_list_events_reads_the_v2_system_log(real_server: FastMCP) -> None:
    captured: dict[str, Any] = {}
    respx.post(f"{V2}/system-log/all").mock(side_effect=_capture(captured, "body", EVENTS_PAGE))
    legacy = respx.get(path=f"{LEGACY_PATH}/stat/event")

    result = await _call(real_server, "list_events", {"limit": 50, "hours": 6})

    body = captured["body"]
    assert body["pageNumber"] == 0
    assert body["pageSize"] == 100
    assert body["timestampTo"] - body["timestampFrom"] == 6 * 3_600_000
    assert "threatTypes" not in body
    assert not legacy.called, "a working v2 route must not trigger the legacy fallback"

    assert result["source"] == f"POST {V2_PATH}/system-log/all"
    assert result["window"]["hours"] == 6
    assert result["total"] == 2
    assert result["returned"] == 2
    assert result["more_available"] is False
    # Newest first, controller fields kept, message rendered from parameters.
    first, second = result["events"]
    assert first["key"] == "CLIENT_CONNECTED_WIRELESS"
    assert first["message"] == "Test Laptop connected to Home."
    assert first["time"] == iso_utc(NOW_MS - 60_000)
    assert second["message"] == "Gateway switched to backup WAN."


@respx.mock
async def test_list_events_empty_window_is_a_real_empty_result(real_server: FastMCP) -> None:
    """A well-formed page with no rows is "nothing logged", and says where from."""
    respx.post(f"{V2}/system-log/all").mock(
        return_value=httpx.Response(
            200,
            json={"data": [], "page_number": 0, "total_element_count": 0, "total_page_count": 0},
        )
    )
    result = await _call(real_server, "list_events", {"limit": 5})
    assert result["events"] == []
    assert result["total"] == 0
    assert result["source"] == f"POST {V2_PATH}/system-log/all"


@respx.mock
async def test_list_events_404_is_an_error_not_an_empty_list(real_server: FastMCP) -> None:
    """REGRESSION: both routes absent must be an error naming both, never ``[]``.

    This is the bug: Network 10.x answers 404 on ``/stat/event`` and a
    swallowed 404 read as "no events". With the v2 route also absent (a
    controller this server cannot read at all) the caller must get one error
    that names each path and its status.
    """
    respx.post(f"{V2}/system-log/all").mock(return_value=httpx.Response(404, json=V2_NOT_FOUND))
    respx.get(path=f"{LEGACY_PATH}/stat/event").mock(
        return_value=httpx.Response(404, json=NOT_FOUND)
    )

    result = await _call(real_server, "list_events", {"limit": 5})

    error = _assert_error_not_empty(result)
    assert f"POST {V2_PATH}/system-log/all answered HTTP 404" in error
    assert f"GET {LEGACY_PATH}/stat/event" in error
    assert "answered HTTP 404: api.err.NotFound" in error


@pytest.mark.parametrize("status", [400, 401, 403, 500, 503])
@respx.mock
async def test_list_events_v2_failure_is_an_error_without_fallback(
    real_server: FastMCP, status: int
) -> None:
    """Only a missing route falls back. A 401 or a 500 on the v2 route is the
    real fault, and falling back to a legacy 404 would hide it."""
    respx.post(f"{V2}/system-log/all").mock(
        return_value=httpx.Response(status, json={"code": "api.err.Boom", "message": "boom"})
    )
    legacy = respx.get(path=f"{LEGACY_PATH}/stat/event")

    result = await _call(real_server, "list_events", {"limit": 5})

    error = _assert_error_not_empty(result)
    assert f"POST {V2_PATH}/system-log/all answered HTTP {status}" in error
    assert not legacy.called


@respx.mock
async def test_list_events_falls_back_to_legacy_when_v2_is_absent(real_server: FastMCP) -> None:
    respx.post(f"{V2}/system-log/all").mock(return_value=httpx.Response(404, json=V2_NOT_FOUND))
    respx.get(path=f"{LEGACY_PATH}/stat/event").mock(
        return_value=httpx.Response(200, json={"meta": {"rc": "ok"}, "data": [{"_id": "e1"}]})
    )
    result = await _call(real_server, "list_events", {"limit": 5})
    assert result["events"] == [{"_id": "e1"}]
    assert result["source"].startswith(f"GET {LEGACY_PATH}/stat/event")
    assert "legacy fallback" in result["source"]
    assert "HTTP 404" in result["source"]


@respx.mock
async def test_list_events_unrecognised_body_is_an_error(real_server: FastMCP) -> None:
    """A 200 that is not a system-log page is a failure to read, not "no events"."""
    respx.post(f"{V2}/system-log/all").mock(
        return_value=httpx.Response(200, json={"unexpected": True})
    )
    result = await _call(real_server, "list_events", {"limit": 5})
    error = _assert_error_not_empty(result)
    assert f"POST {V2_PATH}/system-log/all" in error
    assert "not a system-log page" in error


@respx.mock
async def test_list_events_transport_failure_is_an_error(real_server: FastMCP) -> None:
    respx.post(f"{V2}/system-log/all").mock(side_effect=httpx.ConnectError("refused"))
    result = await _call(real_server, "list_events", {"limit": 5})
    error = _assert_error_not_empty(result)
    assert f"POST {V2_PATH}/system-log/all" in error


@respx.mock
async def test_list_events_pages_until_the_controller_runs_out(real_server: FastMCP) -> None:
    def entry(i: int) -> dict[str, Any]:
        return {"id": f"e{i}", "timestamp": NOW_MS - i * 1000, "key": "K", "message_raw": "m"}

    pages = {
        0: {
            "data": [entry(i) for i in range(100)],
            "page_number": 0,
            "total_element_count": 130,
            "total_page_count": 2,
        },
        1: {
            "data": [entry(i) for i in range(100, 130)],
            "page_number": 1,
            "total_element_count": 130,
            "total_page_count": 2,
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=pages[json.loads(request.content)["pageNumber"]])

    route = respx.post(f"{V2}/system-log/all").mock(side_effect=handler)
    result = await _call(real_server, "list_events", {"limit": 1000})
    assert route.call_count == 2
    assert result["returned"] == 130
    assert result["more_available"] is False

    # A limit below what the controller holds says so instead of implying "all".
    result = await _call(real_server, "list_events", {"limit": 50})
    assert result["returned"] == 50
    assert result["more_available"] is True


async def test_list_events_rejects_out_of_range_hours(stub_server: FastMCP) -> None:
    for hours in (0, 721):
        result = await _call(stub_server, "list_events", {"hours": hours})
        assert "hours" in result["error"]


# ---------------------------------------------------------------------------
# list_alarms
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("shape", ["envelope", "bare_list"])
@respx.mock
async def test_list_alarms_reads_the_v2_critical_log(real_server: FastMCP, shape: str) -> None:
    """unpoller's endpoint catalogue calls ``critical`` an array; Art-of-WiFi
    reads ``total_element_count`` from it. Both shapes are accepted."""
    rows = [EVENTS_PAGE["data"][0]]
    body: Any = rows if shape == "bare_list" else {**EVENTS_PAGE, "data": rows}
    captured: dict[str, Any] = {}
    respx.post(f"{V2}/system-log/critical").mock(side_effect=_capture(captured, "body", body))
    legacy = respx.get(path=f"{LEGACY_PATH}/list/alarm")

    result = await _call(real_server, "list_alarms", {"limit": 5, "hours": 72})

    assert captured["body"]["timestampTo"] - captured["body"]["timestampFrom"] == 72 * 3_600_000
    assert result["source"] == f"POST {V2_PATH}/system-log/critical"
    assert [a["key"] for a in result["alarms"]] == ["WAN_FAILOVER_V2"]
    assert not legacy.called


@respx.mock
async def test_list_alarms_404_and_400_is_an_error_not_an_empty_list(
    real_server: FastMCP,
) -> None:
    """REGRESSION: ``/list/alarm`` answers 400 on Network 10.x."""
    respx.post(f"{V2}/system-log/critical").mock(
        return_value=httpx.Response(404, json=V2_NOT_FOUND)
    )
    respx.get(path=f"{LEGACY_PATH}/list/alarm").mock(
        return_value=httpx.Response(400, json=INVALID_OBJECT)
    )
    result = await _call(real_server, "list_alarms", {"limit": 5})
    error = _assert_error_not_empty(result)
    assert f"POST {V2_PATH}/system-log/critical answered HTTP 404" in error
    assert f"GET {LEGACY_PATH}/list/alarm?archived=false answered HTTP 400" in error
    assert "api.err.InvalidObject" in error


@respx.mock
async def test_list_alarms_archived_on_10x_is_an_error(real_server: FastMCP) -> None:
    v2 = respx.post(f"{V2}/system-log/critical")
    respx.get(path=f"{LEGACY_PATH}/list/alarm").mock(
        return_value=httpx.Response(400, json=INVALID_OBJECT)
    )
    result = await _call(real_server, "list_alarms", {"limit": 5, "archived": True})
    error = _assert_error_not_empty(result)
    assert "no archived state" in error
    assert f"GET {LEGACY_PATH}/list/alarm?archived=true answered HTTP 400" in error
    assert not v2.called


@respx.mock
async def test_list_alarms_legacy_fallback_keeps_the_archived_filter(
    real_server: FastMCP,
) -> None:
    respx.post(f"{V2}/system-log/critical").mock(
        return_value=httpx.Response(404, json=V2_NOT_FOUND)
    )
    respx.get(path=f"{LEGACY_PATH}/list/alarm").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"_id": "a1", "archived": False}, {"_id": "a2", "archived": True}]},
        )
    )
    result = await _call(real_server, "list_alarms", {"limit": 5})
    assert [a["_id"] for a in result["alarms"]] == ["a1"]
    assert "legacy fallback" in result["source"]

    result = await _call(real_server, "list_alarms", {"limit": 5, "archived": True})
    assert [a["_id"] for a in result["alarms"]] == ["a2"]


# ---------------------------------------------------------------------------
# list_threat_detections
# ---------------------------------------------------------------------------


def _mock_threat_sources(
    flows: httpx.Response | None = None, alerts: httpx.Response | None = None
) -> dict[str, Any]:
    captured: dict[str, Any] = {}
    if flows is None:
        respx.post(f"{V2}/traffic-flows").mock(side_effect=_capture(captured, "flows", FLOWS_PAGE))
    else:
        respx.post(f"{V2}/traffic-flows").mock(return_value=flows)
    if alerts is None:
        respx.post(f"{V2}/system-log/threat-alert").mock(
            side_effect=_capture(captured, "alerts", THREAT_ALERT_PAGE)
        )
    else:
        respx.post(f"{V2}/system-log/threat-alert").mock(return_value=alerts)
    return captured


@respx.mock
async def test_list_threat_detections_merges_flows_and_alerts(real_server: FastMCP) -> None:
    captured = _mock_threat_sources()

    result = await _call(real_server, "list_threat_detections", {"hours": 12})

    flows_body, alerts_body = captured["flows"], captured["alerts"]
    assert flows_body["policy_type"] == ["INTRUSION_PREVENTION"]
    assert flows_body["timestampTo"] - flows_body["timestampFrom"] == 12 * 3_600_000
    assert alerts_body["threatTypes"] == ["HONEYPOT", "THREAT"]
    assert alerts_body["timestampTo"] - alerts_body["timestampFrom"] == 12 * 3_600_000

    assert result["complete"] is True
    assert "warning" not in result
    flows_src, alerts_src = result["sources"]
    assert flows_src["endpoint"] == f"POST {V2_PATH}/traffic-flows"
    assert flows_src["rows_read"] == 2
    assert flows_src["rows_skipped_not_ips"] == 1
    assert alerts_src["endpoint"] == f"POST {V2_PATH}/system-log/threat-alert"

    # The flow, plus the alert-only detection; the duplicate alert is dropped
    # and the plain firewall flow is not an IPS detection.
    assert result["matched"] == 2
    blocked, detected = result["detections"]
    assert blocked == {
        "time": iso_utc(NOW_MS - 300_000),
        "timestamp_ms": NOW_MS - 300_000,
        "action": "blocked",
        "src_ip": "192.0.2.20",
        "src_port": 51514,
        "src_mac": "00:00:5e:00:53:20",
        "dst_ip": "198.51.100.7",
        "dst_port": 443,
        "dst_mac": None,
        "protocol": "TCP",
        "direction": "outgoing",
        "signature": "ET CINS Active Threat Intelligence Poor Reputation IP group 7",
        "signature_id": 2403306,
        "category": "ciarmy",
        "severity": "high",
        "client_name": "Media Server",
        "source": "traffic-flows",
        "id": "6740cc000000000000000001",
    }
    assert detected["source"] == "system-log/threat-alert"
    assert detected["action"] == "alerted"
    assert detected["src_ip"] == "203.0.113.9"
    assert detected["dst_ip"] == "192.0.2.30"
    assert detected["dst_port"] is None
    assert detected["signature"] == "Threat Detected"
    assert detected["client_name"] == "Test Printer"


@pytest.mark.parametrize(
    ("client", "expected_ids"),
    [
        ("192.0.2.20", ["6740cc000000000000000001"]),
        ("198.51.100.7", ["6740cc000000000000000001"]),
        ("00-00-5E-00-53-30", ["6740bb000000000000000002"]),
        ("192.0.2.99", []),
    ],
)
@respx.mock
async def test_list_threat_detections_client_filter(
    real_server: FastMCP, client: str, expected_ids: list[str]
) -> None:
    _mock_threat_sources()
    result = await _call(real_server, "list_threat_detections", {"client": client})
    assert [d["id"] for d in result["detections"]] == expected_ids
    assert result["client_filter"] == client
    assert result["complete"] is True


@respx.mock
async def test_list_threat_detections_404_is_an_error_not_an_empty_list(
    real_server: FastMCP,
) -> None:
    """REGRESSION: both IPS routes absent is an error naming both, never ``[]``."""
    _mock_threat_sources(
        flows=httpx.Response(404, json=V2_NOT_FOUND),
        alerts=httpx.Response(404, json=V2_NOT_FOUND),
    )
    result = await _call(real_server, "list_threat_detections", {})
    error = _assert_error_not_empty(result)
    assert f"POST {V2_PATH}/traffic-flows answered HTTP 404" in error
    assert f"POST {V2_PATH}/system-log/threat-alert answered HTTP 404" in error


@respx.mock
async def test_list_threat_detections_partial_failure_warns_first(real_server: FastMCP) -> None:
    """One source down: return what the other read, but lead with the gap."""
    _mock_threat_sources(flows=httpx.Response(400, json={"code": "api.err.BadRequest"}))
    raw = await real_server.call_tool("list_threat_detections", {})
    text = raw.content[0].text  # type: ignore[union-attr]
    result = json.loads(text)

    assert next(iter(result)) == "warning", "the warning must be the first thing a reader sees"
    assert f"POST {V2_PATH}/traffic-flows answered HTTP 400" in result["warning"]
    assert "not proof that nothing was blocked" in result["warning"]
    assert result["complete"] is False
    assert result["sources"][0]["ok"] is False
    assert result["sources"][1]["ok"] is True
    # Both alerts survive: with no flows there is nothing to dedupe against.
    assert result["matched"] == 2


@respx.mock
async def test_list_threat_detections_rejects_a_bad_client_without_calling(
    real_server: FastMCP,
) -> None:
    flows = respx.post(f"{V2}/traffic-flows")
    result = await _call(real_server, "list_threat_detections", {"client": "media-server"})
    assert "IP address or a MAC address" in result["error"]
    assert not flows.called


async def test_list_threat_detections_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "list_threat_detections", {"hours": 24})
    assert result["complete"] is True
    # Seed: one flow, three alerts, one of which repeats the flow.
    assert result["matched"] == 3
    assert result["detections"][0]["source"] == "traffic-flows"
    assert result["detections"][0]["action"] == "blocked"
    assert {d["action"] for d in result["detections"]} == {"blocked", "alerted"}

    one_hour = await _call(stub_server, "list_threat_detections", {"hours": 1})
    assert one_hour["matched"] == 2

    filtered = await _call(stub_server, "list_threat_detections", {"client": "aa:bb:cc:00:00:04"})
    assert [d["client_name"] for d in filtered["detections"]] == ["Echo Dot"]


async def test_list_threat_detections_rejects_out_of_range_args(stub_server: FastMCP) -> None:
    assert "hours" in (await _call(stub_server, "list_threat_detections", {"hours": 0}))["error"]
    assert "limit" in (await _call(stub_server, "list_threat_detections", {"limit": 0}))["error"]


async def test_descriptions_promise_errors_not_empty_lists(stub_server: FastMCP) -> None:
    """The manifest is generated from these. Each must tell a reader that a
    failure is an error and an empty list is a real "nothing happened"."""
    tools = {t.name: t for t in await stub_server.list_tools()}
    for name in ("list_events", "list_alarms", "list_threat_detections"):
        flat = " ".join((tools[name].description or "").split())
        assert "error naming" in flat, name
        assert "system-log" in flat, name


# ---------------------------------------------------------------------------
# Shaping helpers
# ---------------------------------------------------------------------------


def test_system_log_body_matches_art_of_wifi() -> None:
    assert system_log_body("all", 1, 2, 0) == {
        "pageNumber": 0,
        "pageSize": 100,
        "timestampFrom": 1,
        "timestampTo": 2,
    }
    assert system_log_body("threat-alert", 1, 2, 3)["threatTypes"] == ["HONEYPOT", "THREAT"]


def test_parse_page_rejects_unrecognised_bodies() -> None:
    for body in ({"data": "nope"}, {"items": []}, "text", None, 7):
        with pytest.raises(UniFiError, match="not a system-log page"):
            parse_page(body, "POST /x")


def test_parse_page_reads_has_next_and_page_counts() -> None:
    rows = [{"id": "a"}]
    assert parse_page({"data": rows, "has_next": True}, "x") == (rows, None, True)
    assert parse_page(
        {"data": rows, "page_number": 0, "total_page_count": 2, "total_element_count": 9}, "x"
    ) == (rows, 9, True)
    assert parse_page({"data": [], "has_next": True}, "x") == ([], None, False)


def test_render_message_fills_placeholders_and_keeps_unknown_ones() -> None:
    entry = {
        "message_raw": "{CLIENT} left {WLAN} via {AP}.",
        "parameters": {"CLIENT": {"id": "00:00:5e:00:53:01"}, "WLAN": {"name": "Home"}},
    }
    assert render_message(entry) == "00:00:5e:00:53:01 left Home via {AP}."
    assert render_message({"title_raw": "Title only"}) == "Title only"
