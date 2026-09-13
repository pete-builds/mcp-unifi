"""Tests for ``mcp_unifi.modules.network.observability``.

Split from the pre-Step-5 ``tests/test_tools.py``. Bodies are unchanged.
"""

from __future__ import annotations

import httpx
import respx
from fastmcp import FastMCP

from mcp_unifi.clients.stubs import StubState
from tests.network.conftest import BASE, _call

# ---------------------------------------------------------------------------
# Stub mode
# ---------------------------------------------------------------------------


async def test_get_site_health_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_site_health")
    subsystems = {h["subsystem"] for h in result}
    assert {"wan", "lan", "wlan"} <= subsystems


async def test_get_wan_status_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_wan_status")
    assert result["subsystem"] == "wan"
    assert "xput_up" in result and "xput_down" in result


async def test_list_events_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "list_events", {"limit": 1})
    assert len(result) <= 1


async def test_list_events_invalid_limit(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "list_events", {"limit": 0})
    assert "limit" in result["error"]


async def test_list_alarms_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "list_alarms", {"limit": 50, "archived": False})
    assert isinstance(result, list)


async def test_list_alarms_invalid_limit(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "list_alarms", {"limit": 0})
    assert "limit" in result["error"]


async def test_speedtest_round_trip_stub(stub_server: FastMCP) -> None:
    triggered = await _call(stub_server, "trigger_speedtest")
    assert triggered["started"] is True
    results = await _call(stub_server, "get_speedtest_results", {"limit": 5})
    assert len(results) >= 1


async def test_get_speedtest_results_invalid_limit(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_speedtest_results", {"limit": 0})
    assert "limit" in result["error"]


async def test_list_top_talkers_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "list_top_talkers", {"limit": 3})
    assert len(result) <= 3
    if result:
        assert result[0]["total_bytes"] >= result[-1]["total_bytes"]


async def test_list_top_talkers_invalid_limit(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "list_top_talkers", {"limit": 0})
    assert "limit" in result["error"]


async def test_audit_open_ports_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "audit_open_ports")
    assert "port_forwards" in result
    assert "wan_accept_rules" in result
    assert "wan_accept_policies" in result
    assert "summary" in result
    # The seed carries one legacy rule and one RESPOND_ONLY zone policy, so
    # the controller reads as running both models, and the return-traffic
    # policy is excluded but counted rather than hidden.
    assert result["firewall_model"] == "mixed"
    assert result["wan_zone_resolved"] is True
    assert result["wan_accept_policies"] == []
    assert result["return_traffic_policies_excluded"] == 1
    assert "firewall_policies_error" not in result
    # The seed has one HTTPS->NAS forward and one established/related WAN_IN
    # rule (filtered out). Audit should surface the forward, no accept rules.
    assert len(result["port_forwards"]) >= 1
    assert all(
        not (r.get("state_established") and r.get("state_related"))
        for r in result["wan_accept_rules"]
    )


async def test_audit_open_ports_flags_wan_accept_rule(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    stub_state.create_firewall_rule(
        {
            "name": "Open SSH from anywhere",
            "ruleset": "WAN_IN",
            "rule_index": 2100,
            "action": "accept",
            "enabled": True,
            "protocol": "tcp",
        }
    )
    result = await _call(stub_server, "audit_open_ports")
    names = [r["name"] for r in result["wan_accept_rules"]]
    assert "Open SSH from anywhere" in names


def _policy(
    name: str,
    *,
    src: str,
    dst: str,
    action: str = "ALLOW",
    enabled: bool = True,
    predefined: bool = False,
    connection_state_type: str = "ALL",
) -> dict[str, object]:
    endpoint = {
        "matching_target": "ANY",
        "port_matching_type": "ANY",
        "match_opposite_ports": False,
    }
    return {
        "_id": name.lower().replace(" ", "-"),
        "name": name,
        "action": action,
        "enabled": enabled,
        "predefined": predefined,
        "connection_state_type": connection_state_type,
        "index": 20000,
        "protocol": "all",
        "source": {"zone_id": src, **endpoint},
        "destination": {"zone_id": dst, **endpoint},
    }


def _zone_ids(stub_state: StubState) -> dict[str, str]:
    return {z["zone_key"]: z["_id"] for z in stub_state.list_firewall_zones()}


async def test_audit_open_ports_flags_wan_allow_policy(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """Issue #112: a Zone-Based Firewall site must not read as 0 WAN accepts."""
    zones = _zone_ids(stub_state)
    stub_state.firewall_policies.append(
        _policy("Open SSH from WAN", src=zones["wan"], dst=zones["lan"])
    )
    result = await _call(stub_server, "audit_open_ports")
    flagged = {p["name"]: p for p in result["wan_accept_policies"]}
    assert "Open SSH from WAN" in flagged
    assert flagged["Open SSH from WAN"]["source_zone"] == "WAN"
    assert flagged["Open SSH from WAN"]["destination_zone"] == "LAN"
    assert "1 WAN allow policy(ies)" in result["summary"]


async def test_audit_open_ports_ignores_non_exposing_policies(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    zones = _zone_ids(stub_state)
    stub_state.firewall_policies.extend(
        [
            _policy("LAN to WAN", src=zones["lan"], dst=zones["wan"]),
            _policy("Disabled WAN allow", src=zones["wan"], dst=zones["lan"], enabled=False),
            _policy("WAN block", src=zones["wan"], dst=zones["lan"], action="BLOCK"),
        ]
    )
    result = await _call(stub_server, "audit_open_ports")
    assert result["wan_accept_policies"] == []


async def test_audit_open_ports_says_when_wan_zone_is_unresolved(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """Policies with no identifiable WAN zone are reported as unclassified, not clean."""
    stub_state.firewall_zones.clear()
    stub_state.firewall_policies.append(_policy("Mystery", src="zone-x", dst="zone-y"))
    result = await _call(stub_server, "audit_open_ports")
    assert result["wan_zone_resolved"] is False
    assert result["wan_accept_policies"] == []
    assert "WAN zone unresolved" in result["summary"]


# ---------------------------------------------------------------------------
# Real mode
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_get_site_health(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/health").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {"subsystem": "wan", "status": "ok"},
                    {"subsystem": "lan", "status": "ok"},
                ]
            },
        )
    )
    result = await _call(real_server, "get_site_health")
    assert {h["subsystem"] for h in result} == {"wan", "lan"}


@respx.mock
async def test_real_get_wan_status_extracts_wan(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/health").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {"subsystem": "lan", "status": "ok"},
                    {"subsystem": "wan", "status": "ok", "wan_ip": "1.2.3.4"},
                ]
            },
        )
    )
    result = await _call(real_server, "get_wan_status")
    assert result["subsystem"] == "wan"
    assert result["wan_ip"] == "1.2.3.4"


@respx.mock
async def test_real_get_wan_status_unknown_when_missing(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/health").mock(
        return_value=httpx.Response(200, json={"data": [{"subsystem": "lan", "status": "ok"}]})
    )
    result = await _call(real_server, "get_wan_status")
    assert result["status"] == "unknown"


@respx.mock
async def test_real_list_events_404_is_an_error_not_an_empty_list(
    real_server: FastMCP,
) -> None:
    """REGRESSION (2026-08-08): a 404 must NOT be reported as "no events".

    The event-log route is absent on Network 10.5.67 (``GET /stat/event`` →
    404 ``api.err.NotFound``, re-probed live on a settled controller). The
    client used to swallow that and return ``[]``, so ``list_events`` answered
    "no events found" when the truth was "this controller cannot report
    events at all". That fabricated negative cost real debugging time during
    the 2026-08-08 outage: an empty list is indistinguishable from a quiet
    network.

    The tool must now surface an explicit error. Asserting on the *absence*
    of a benign empty result is the whole point of this test — do not relax
    it to ``result == []``.
    """
    respx.get(f"{BASE}/stat/event").mock(
        return_value=httpx.Response(
            404, json={"meta": {"rc": "error", "msg": "api.err.NotFound"}, "data": []}
        )
    )
    result = await _call(real_server, "list_events", {"limit": 5})

    assert result != [], "a missing route must never be reported as an empty result"
    assert isinstance(result, dict), f"expected an error envelope, got {type(result)}"
    assert "error" in result
    assert "not available on this UniFi Network version" in result["error"]


@respx.mock
async def test_real_list_alarms_400_is_an_error_not_an_empty_list(
    real_server: FastMCP,
) -> None:
    """REGRESSION (2026-08-08): the alarm route regressed on 10.5.67.

    ``GET /list/alarm`` worked on 10.4.57 and now answers 400
    ``api.err.InvalidObject``. "Zero alarms" and "I cannot read alarms" must
    not look identical to the caller.
    """
    respx.get(f"{BASE}/list/alarm").mock(
        return_value=httpx.Response(
            400, json={"meta": {"rc": "error", "msg": "api.err.InvalidObject"}, "data": []}
        )
    )
    result = await _call(real_server, "list_alarms", {"limit": 5})

    assert result != [], "a broken route must never be reported as zero alarms"
    assert isinstance(result, dict)
    assert "error" in result
    assert "not available on this UniFi Network version" in result["error"]


@respx.mock
async def test_real_list_events_forward_compat(real_server: FastMCP) -> None:
    """If a firmware restores ``GET /stat/event``, records flow through."""
    respx.get(f"{BASE}/stat/event").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "e1"}]})
    )
    result = await _call(real_server, "list_events", {"limit": 5})
    assert result[0]["_id"] == "e1"


@respx.mock
async def test_real_list_alarms(real_server: FastMCP) -> None:
    """On a UCG-Fiber (Network 10.4.57) alarms come from
    ``GET /list/alarm?archived=<bool>`` (HTTP 200, probed live 2026-06-03). The
    old ``POST /stat/alarm`` form 404s and is abandoned. The active query keeps
    only non-archived records via the defensive client-side filter."""
    respx.get(f"{BASE}/list/alarm").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {"_id": "a1", "archived": False, "user": "aa:bb:cc:dd:ee:ff"},
                    {"_id": "a2", "archived": True},
                ]
            },
        )
    )
    result = await _call(real_server, "list_alarms", {"limit": 5, "archived": False})
    # Only the active alarm survives the archived filter.
    assert [r["_id"] for r in result] == ["a1"]
    assert result[0]["user"] == "aa:bb:cc:dd:ee:ff"


@respx.mock
async def test_real_list_alarms_archived(real_server: FastMCP) -> None:
    """Archived query returns only archived alarms."""
    respx.get(f"{BASE}/list/alarm").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {"_id": "a1", "archived": False},
                    {"_id": "a2", "archived": True},
                ]
            },
        )
    )
    result = await _call(real_server, "list_alarms", {"limit": 5, "archived": True})
    assert [r["_id"] for r in result] == ["a2"]


@respx.mock
async def test_real_trigger_speedtest(real_server: FastMCP) -> None:
    import json as _json

    captured: dict = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = _json.loads(request.content)
        return httpx.Response(200, json={"data": [{"started": True}]})

    respx.post(f"{BASE}/cmd/devmgr").mock(side_effect=capture)
    result = await _call(real_server, "trigger_speedtest")
    assert captured["body"]["cmd"] == "speedtest"
    assert result["started"] is True


@respx.mock
async def test_real_get_speedtest_results(real_server: FastMCP) -> None:
    """Verified against UCG-Fiber fw 5.1.12.33296: the legacy
    ``GET /stat/report/archive.speedtest?_limit=...`` form returns sparse
    records that only carry ``_id``/``oid``/``o``. The real call uses
    ``POST`` with an ``attrs`` projection and the controller returns
    ``xput_upload`` (not the older ``xput_up``); the client normalises
    it to ``xput_up`` so callers see the documented field name.
    """
    import json as _json

    captured: dict = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = _json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "_id": "s1",
                        "time": 1779800888000,
                        "xput_upload": 950.0,
                        "xput_download": 2100.0,
                        "latency": 12,
                        "server": {"city": "New York", "provider": "GSL"},
                    },
                    {
                        "_id": "s2",
                        "time": 1779804597000,
                        "xput_upload": 920.0,
                        "xput_download": 2090.0,
                        "latency": 11,
                    },
                ]
            },
        )

    respx.post(f"{BASE}/stat/report/archive.speedtest").mock(side_effect=capture)
    result = await _call(real_server, "get_speedtest_results", {"limit": 3})
    assert len(result) == 2
    # The client must project the attrs list onto the POST body.
    assert "xput_upload" in captured["body"]["attrs"]
    assert captured["body"]["limit"] == 3
    # And it must surface both the canonical and back-compat field names so
    # existing callers (and the documented contract) keep working.
    assert result[0]["xput_upload"] == 950.0
    assert result[0]["xput_up"] == 950.0
    assert result[0]["xput_download"] == 2100.0


@respx.mock
async def test_real_list_top_talkers(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/sitedpi").mock(
        return_value=httpx.Response(
            200, json={"data": [{"mac": "aa", "rx_bytes": 100}, {"mac": "bb", "rx_bytes": 50}]}
        )
    )
    result = await _call(real_server, "list_top_talkers", {"limit": 1})
    assert len(result) == 1


@respx.mock
async def test_real_audit_open_ports(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/firewallrule").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "_id": "r1",
                        "ruleset": "WAN_IN",
                        "action": "accept",
                        "enabled": True,
                        "name": "Boilerplate",
                        "state_established": True,
                        "state_related": True,
                    },
                    {
                        "_id": "r2",
                        "ruleset": "WAN_IN",
                        "action": "accept",
                        "enabled": True,
                        "name": "Open SSH",
                    },
                ]
            },
        )
    )
    respx.get(f"{BASE}/rest/portforward").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"_id": "pf1", "enabled": True, "name": "HTTPS to NAS"}]},
        )
    )
    respx.get(f"{V2}/firewall-policies").mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{V2}/firewall/zone").mock(return_value=httpx.Response(200, json=[]))
    result = await _call(real_server, "audit_open_ports")
    assert len(result["port_forwards"]) == 1
    names = [r["name"] for r in result["wan_accept_rules"]]
    assert names == ["Open SSH"]
    assert result["firewall_model"] == "legacy"


V2 = BASE.replace("/api/s/default", "/v2/api/site/default")

_ZONES = [
    {"_id": "z-lan", "name": "LAN", "zone_key": "lan", "default_zone": True},
    {"_id": "z-wan", "name": "WAN", "zone_key": "wan", "default_zone": True},
]


@respx.mock
async def test_real_audit_open_ports_zone_based_site(real_server: FastMCP) -> None:
    """Issue #112 as reported: legacy rulesets empty, policy lives in v2.

    Policy shapes mirror captured controller data: the return-traffic
    boilerplate is ``predefined`` AND ``RESPOND_ONLY``; the zone matrix's
    "Allow All Traffic" is ``predefined`` with ``connection_state_type ALL``.
    Only the first is boilerplate. The second, sourced from the WAN zone, is
    the worst thing this audit can find and must never be filtered as
    "predefined, ignore".
    """
    respx.get(f"{BASE}/rest/firewallrule").mock(return_value=httpx.Response(200, json={"data": []}))
    respx.get(f"{BASE}/rest/portforward").mock(return_value=httpx.Response(200, json={"data": []}))
    respx.get(f"{V2}/firewall/zone").mock(return_value=httpx.Response(200, json=_ZONES))
    respx.get(f"{V2}/firewall-policies").mock(
        return_value=httpx.Response(
            200,
            json=[
                _policy(
                    "Allow Return Traffic",
                    src="z-wan",
                    dst="z-lan",
                    predefined=True,
                    connection_state_type="RESPOND_ONLY",
                ),
                _policy("Allow All Traffic", src="z-wan", dst="z-lan", predefined=True),
                _policy("Open SSH", src="z-wan", dst="z-lan"),
                _policy("Block IoT", src="z-lan", dst="z-wan", action="BLOCK"),
            ],
        )
    )
    result = await _call(real_server, "audit_open_ports")
    assert result["wan_accept_rules"] == []
    flagged = {p["name"]: p for p in result["wan_accept_policies"]}
    assert set(flagged) == {"Allow All Traffic", "Open SSH"}
    assert flagged["Allow All Traffic"]["predefined"] is True
    assert result["firewall_model"] == "zone-based"
    assert result["return_traffic_policies_excluded"] == 1
    assert "2 WAN allow policy(ies)" in result["summary"]


@respx.mock
async def test_real_audit_open_ports_resolves_external_zone_by_name(real_server: FastMCP) -> None:
    """UniFi's default name for the internet-facing zone is "External"; a
    record with no ``zone_key`` must still classify by that name."""
    respx.get(f"{BASE}/rest/firewallrule").mock(return_value=httpx.Response(200, json={"data": []}))
    respx.get(f"{BASE}/rest/portforward").mock(return_value=httpx.Response(200, json={"data": []}))
    respx.get(f"{V2}/firewall/zone").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"_id": "z-int", "name": "Internal", "default_zone": True},
                {"_id": "z-ext", "name": "External", "default_zone": True},
            ],
        )
    )
    respx.get(f"{V2}/firewall-policies").mock(
        return_value=httpx.Response(
            200,
            json=[_policy("Allow All Traffic", src="z-ext", dst="z-int", predefined=True)],
        )
    )
    result = await _call(real_server, "audit_open_ports")
    assert result["wan_zone_resolved"] is True
    assert [p["name"] for p in result["wan_accept_policies"]] == ["Allow All Traffic"]
    assert result["wan_accept_policies"][0]["source_zone"] == "External"


@respx.mock
async def test_real_audit_open_ports_carries_v2_failure(real_server: FastMCP) -> None:
    """A failed zone-based read is reported, never turned into a clean WAN."""
    respx.get(f"{BASE}/rest/firewallrule").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [{"_id": "r2", "ruleset": "WAN_IN", "action": "accept", "name": "Open SSH"}]
            },
        )
    )
    respx.get(f"{BASE}/rest/portforward").mock(return_value=httpx.Response(200, json={"data": []}))
    respx.get(f"{V2}/firewall-policies").mock(return_value=httpx.Response(500, text="boom"))
    result = await _call(real_server, "audit_open_ports")
    assert "error" not in result
    assert [r["name"] for r in result["wan_accept_rules"]] == ["Open SSH"]
    assert "500" in result["firewall_policies_error"]
    assert "FAILED" in result["summary"]


@respx.mock
async def test_real_get_site_health_handles_500(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/health").mock(return_value=httpx.Response(500))
    result = await _call(real_server, "get_site_health")
    assert "error" in result
