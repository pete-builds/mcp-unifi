"""``backup_config`` and ``restore_config`` carry Zone-Based Firewall policies.

Since Network 11 migrated every site to the Zone-Based Firewall, a backup that
left policies out (they sat in ``not_included``) backed up nobody's firewall.
These tests run against a stub shaped like the live Network 11.0.99 probe of
2026-11-27 (:func:`seed_live_zone_site`): six built-in zones, ten operator
policies including one name held four times across zone pairs, an
address-matching policy, and predefined policies including a port-forward one.

The restore target is a second stub with the same zones and networks by name
but different ids everywhere, so a policy that kept a source id would point at
nothing.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from fastmcp import FastMCP

from mcp_unifi.clients.stubs import StubState
from mcp_unifi.clients.zone_firewall_stubs import ECOWITT, seed_live_zone_site
from mcp_unifi.clients.zone_policy import USER_DEFINED
from mcp_unifi.config import Settings
from mcp_unifi.server import build_server
from tests.network.conftest import _call

USER_NAMES = sorted(
    [
        ECOWITT,
        ECOWITT,
        ECOWITT,
        ECOWITT,
        "Allow TRUSTED to MGMT",
        "Block IoT to TRUSTED",
        "Allow MGMT DNS",
        "Block Guest to Internal",
        "Allow Vpn to Internal",
        "Allow Dewfront web",
    ]
)
PREDEFINED_NAMES = {
    "Allow Port Forward Plex",
    "Allow Return Traffic",
    "Block Invalid Traffic",
    "Allow All Traffic",
}


@pytest.fixture
def source_state() -> StubState:
    state = StubState()
    seed_live_zone_site(state)
    return state


@pytest.fixture
def source_server(stub_settings: Settings, source_state: StubState) -> FastMCP:
    return build_server(stub_settings, stub=source_state)


@pytest.fixture
def target_state() -> StubState:
    """Same zones and networks by name, no operator policies, every id different."""
    state = StubState()
    seed_live_zone_site(state, user_policies=False)
    return state


@pytest.fixture
def target_server(stub_settings: Settings, target_state: StubState) -> FastMCP:
    return build_server(stub_settings, stub=target_state)


class WriteSpy:
    """Count every v1 policy write the restore sends to the target."""

    def __init__(self, state: StubState) -> None:
        self.calls: list[tuple[str, Any]] = []
        fw = state.zone_firewall
        for method in ("create_policy", "update_policy", "delete_policy"):
            original = getattr(fw, method)

            def _spy(*args: Any, _m: str = method, _o: Any = original) -> Any:
                self.calls.append((_m, args))
                return _o(*args)

            setattr(fw, method, _spy)


def _user_v1(state: StubState) -> list[dict[str, Any]]:
    return [
        p
        for p in state.zone_firewall.policies
        if isinstance(p.get("metadata"), dict) and p["metadata"].get("origin") == USER_DEFINED
    ]


def _zone_name(state: StubState, v1_zone_id: str) -> str:
    return next(n for n, zid in state.zone_firewall.zone_ids.items() if zid == v1_zone_id)


def _v1_net(state: StubState, name: str) -> str:
    net = next(n for n in state.networks if n.get("name") == name)
    return str(net["external_id"])


async def _backup(server: FastMCP) -> dict[str, Any]:
    return await _call(server, "backup_config", {})


async def _apply(server: FastMCP, envelope: dict[str, Any]) -> dict[str, Any]:
    preview = await _call(server, "restore_config", {"backup_json": json.dumps(envelope)})
    assert preview.get("preview") is True, preview
    return await _call(server, "confirm_destructive_action", {"token": preview["token"]})


async def _dry(server: FastMCP, envelope: dict[str, Any]) -> dict[str, Any]:
    return await _call(
        server, "restore_config", {"backup_json": json.dumps(envelope), "dry_run": True}
    )


def _policy_actions(plan: list[dict[str, Any]], kind: str | None = None) -> list[dict[str, Any]]:
    return [
        a
        for a in plan
        if a["type"] == "firewall_policies" and (kind is None or a["action"] == kind)
    ]


# ---------------------------------------------------------------------------
# Backup
# ---------------------------------------------------------------------------


async def test_backup_carries_every_user_policy_and_no_predefined_one(
    source_server: FastMCP,
) -> None:
    envelope = await _backup(source_server)
    policies = envelope["resources"]["firewall_policies"]
    assert sorted(p["name"] for p in policies) == USER_NAMES
    assert not PREDEFINED_NAMES & {p["name"] for p in policies}
    assert "firewall_policies" not in envelope["not_included"]
    assert "firewall_zones" not in envelope["not_included"]


async def test_backup_stores_policies_portably(
    source_server: FastMCP, source_state: StubState
) -> None:
    """Zones and networks by name; runtime counters and controller ids dropped."""
    envelope = await _backup(source_server)
    policies = envelope["resources"]["firewall_policies"]
    for policy in policies:
        for dropped in (
            "_id",
            "hits",
            "last_hit",
            "origin_id",
            "origin_type",
            "predefined",
            "report_flow_supported",
        ):
            assert dropped not in policy, (policy["name"], dropped)
        for side in ("source", "destination"):
            assert "zone_id" not in policy[side]
            assert "network_ids" not in policy[side]
            assert policy[side]["zone_name"]

    trusted = next(p for p in policies if p["name"] == "Allow TRUSTED to MGMT")
    assert trusted["source"]["network_names"] == ["TRUSTED"]
    assert trusted["destination"]["network_names"] == ["MGMT"]
    assert trusted["source"]["zone_name"] == "Internal"

    dests = sorted(p["destination"]["zone_name"] for p in policies if p["name"] == ECOWITT)
    assert dests == ["External", "Hotspot", "Internal", "Vpn"]

    zones = {z["name"]: z for z in envelope["resources"]["firewall_zones"]}
    assert set(zones) == {"Internal", "External", "Gateway", "Vpn", "Hotspot"}
    assert all(z["built_in"] is True for z in zones.values())
    assert zones["Internal"]["zone_key"] == "internal"
    assert {"TRUSTED", "MGMT", "IoT", "Default"} <= set(zones["Internal"]["network_names"])
    assert zones["Hotspot"]["network_names"] == ["Guest"]
    dump = json.dumps(envelope["resources"]["firewall_policies"]) + json.dumps(zones)
    assert not [n["_id"] for n in source_state.networks if str(n["_id"]) in dump]
    assert not [z["_id"] for z in source_state.firewall_zones if str(z["_id"]) in dump]


async def test_legacy_site_backup_carries_no_policies(stub_server: FastMCP) -> None:
    """A site still on legacy rulesets has no operator zone policies to carry."""
    envelope = await _backup(stub_server)
    assert envelope["resources"]["firewall_policies"] == []
    assert envelope["resources"]["firewall_zones"] == []


# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------


async def test_round_trip_recreates_policies_with_the_targets_ids(
    source_server: FastMCP,
    source_state: StubState,
    target_server: FastMCP,
    target_state: StubState,
) -> None:
    envelope = await _backup(source_server)
    result = await _apply(target_server, envelope)
    assert "error" not in result, result

    created = _user_v1(target_state)
    assert sorted(p["name"] for p in created) == USER_NAMES

    target_zone_ids = set(target_state.zone_firewall.zone_ids.values())
    source_zone_ids = set(source_state.zone_firewall.zone_ids.values())
    for policy in created:
        for side in ("source", "destination"):
            assert policy[side]["zoneId"] in target_zone_ids
            assert policy[side]["zoneId"] not in source_zone_ids

    trusted = next(p for p in created if p["name"] == "Allow TRUSTED to MGMT")
    src_filter = trusted["source"]["trafficFilter"]["networkFilter"]["networkIds"]
    dst_filter = trusted["destination"]["trafficFilter"]["networkFilter"]["networkIds"]
    assert src_filter == [_v1_net(target_state, "TRUSTED")]
    assert dst_filter == [_v1_net(target_state, "MGMT")]
    assert src_filter != [_v1_net(source_state, "TRUSTED")]
    assert trusted["action"] == {"type": "ALLOW", "allowReturnTraffic": False}

    web = next(p for p in created if p["name"] == "Allow Dewfront web")
    assert web["enabled"] is False
    assert web["loggingEnabled"] is True
    assert web["ipProtocolScope"]["protocolFilter"]["protocol"] == {"name": "TCP"}
    assert web["destination"]["trafficFilter"]["portFilter"]["items"] == [
        {"type": "PORT_NUMBER", "value": 80},
        {"type": "PORT_NUMBER", "value": 443},
    ]

    # A second run finds nothing to do.
    again = await _dry(target_server, envelope)
    assert not [
        a for a in _policy_actions(again["would_apply"]) if a["action"] in ("create", "update")
    ]


async def test_duplicate_names_across_zone_pairs_restore_as_distinct_policies(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    envelope = await _backup(source_server)
    await _apply(target_server, envelope)
    ecowitt = [p for p in _user_v1(target_state) if p["name"] == ECOWITT]
    assert len(ecowitt) == 4
    assert len({p["id"] for p in ecowitt}) == 4
    assert {_zone_name(target_state, p["source"]["zoneId"]) for p in ecowitt} == {"Internal"}
    assert sorted(_zone_name(target_state, p["destination"]["zoneId"]) for p in ecowitt) == [
        "External",
        "Hotspot",
        "Internal",
        "Vpn",
    ]
    for policy in ecowitt:
        src = policy["source"]["trafficFilter"]
        assert src["type"] == "IP_ADDRESS"
        assert src["ipAddressFilter"]["items"] == [{"type": "SUBNET", "value": "10.0.50.117/32"}]
        assert policy["destination"]["trafficFilter"]["portFilter"]["items"] == [
            {"type": "PORT_NUMBER", "value": 3700}
        ]


async def test_restore_without_dry_run_previews_and_writes_nothing(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    """The first call is a preview behind a confirm token; dry_run=True too."""
    envelope = await _backup(source_server)
    spy = WriteSpy(target_state)
    before = copy.deepcopy(target_state.zone_firewall.policies)

    preview = await _call(target_server, "restore_config", {"backup_json": json.dumps(envelope)})
    assert preview.get("preview") is True
    assert len(_policy_actions(preview["resource"]["plan"], "create")) == 10

    dry = await _dry(target_server, envelope)
    assert len(_policy_actions(dry["would_apply"], "create")) == 10

    assert spy.calls == []
    assert target_state.zone_firewall.policies == before


async def test_a_predefined_policy_with_a_backed_up_identity_is_never_touched(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    fw = target_state.zone_firewall
    internal = fw.zone_ids["Internal"]
    predefined = {
        "id": "predefined-1",
        "name": "Allow TRUSTED to MGMT",
        "enabled": False,
        "action": {"type": "BLOCK"},
        "source": {"zoneId": internal},
        "destination": {"zoneId": internal},
        "ipProtocolScope": {"ipVersion": "IPV4"},
        "loggingEnabled": False,
        "index": 20000,
        "metadata": {"origin": "SYSTEM_DEFINED"},
    }
    fw.policies.append(copy.deepcopy(predefined))
    spy = WriteSpy(target_state)

    envelope = await _backup(source_server)
    dry = await _dry(target_server, envelope)
    mine = [a for a in _policy_actions(dry["would_apply"]) if a["name"] == predefined["name"]]
    assert [a["action"] for a in mine] == ["blocked"]
    assert "controller-managed" in mine[0]["reason"]

    result = await _apply(target_server, envelope)
    assert "error" not in result, result
    assert next(p for p in fw.policies if p["id"] == "predefined-1") == predefined
    touched = [args for method, args in spy.calls if method != "create_policy"]
    assert touched == []
    assert "Allow TRUSTED to MGMT" not in {p["name"] for p in _user_v1(target_state)}
    assert len(_user_v1(target_state)) == 9


async def test_a_changed_user_policy_is_updated_only_where_it_differs(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    envelope = await _backup(source_server)
    await _apply(target_server, envelope)
    victim = next(p for p in _user_v1(target_state) if p["name"] == "Block IoT to TRUSTED")
    victim["enabled"] = False
    spy = WriteSpy(target_state)

    dry = await _dry(target_server, envelope)
    updates = _policy_actions(dry["would_apply"], "update")
    assert [(a["name"], a["changes"]) for a in updates] == [("Block IoT to TRUSTED", ["enabled"])]
    assert not _policy_actions(dry["would_apply"], "create")

    result = await _apply(target_server, envelope)
    assert "error" not in result, result
    assert [m for m, _ in spy.calls] == ["update_policy"]
    after = next(p for p in _user_v1(target_state) if p["name"] == "Block IoT to TRUSTED")
    assert after["enabled"] is True
    assert after["id"] == victim["id"]


async def test_user_policies_the_backup_lacks_are_reported_not_deleted(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    fw = target_state.zone_firewall
    extra = fw.create_policy(
        {
            "name": "Lab only",
            "enabled": True,
            "loggingEnabled": False,
            "action": {"type": "BLOCK"},
            "source": {"zoneId": fw.zone_ids["Dmz"]},
            "destination": {"zoneId": fw.zone_ids["Internal"]},
            "ipProtocolScope": {"ipVersion": "IPV4"},
        }
    )
    envelope = await _backup(source_server)
    dry = await _dry(target_server, envelope)
    mine = [a for a in _policy_actions(dry["would_apply"]) if a["name"] == "Lab only"]
    assert [a["action"] for a in mine] == ["skip"]
    assert "never deletes" in mine[0]["reason"]

    await _apply(target_server, envelope)
    assert any(p["id"] == extra["id"] for p in fw.policies)


async def test_missing_network_or_zone_on_the_target_blocks_that_policy_only(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    envelope = await _backup(source_server)
    # Hand-trimmed to the firewall, so no network section recreates IoT.
    envelope["resources"] = {
        k: envelope["resources"][k] for k in ("firewall_policies", "firewall_zones")
    }
    target_state.networks = [n for n in target_state.networks if n.get("name") != "IoT"]
    lab = next(
        p for p in envelope["resources"]["firewall_policies"] if p["name"] == "Allow MGMT DNS"
    )
    lab["destination"]["zone_name"] = "Lab"
    envelope["resources"]["firewall_zones"].append(
        {"name": "Lab", "zone_key": None, "built_in": False, "network_names": []}
    )
    spy = WriteSpy(target_state)

    dry = await _dry(target_server, envelope)
    blocked = {a["name"]: a["reason"] for a in _policy_actions(dry["would_apply"], "blocked")}
    assert set(blocked) == {"Block IoT to TRUSTED", "Allow MGMT DNS"}
    assert "'IoT'" in blocked["Block IoT to TRUSTED"]
    assert "custom zone" in blocked["Allow MGMT DNS"]
    assert any("blocked" in w for w in dry["warnings"])

    await _apply(target_server, envelope)
    sent = {args[0]["name"] for method, args in spy.calls if method == "create_policy"}
    assert sent == set(USER_NAMES) - {"Block IoT to TRUSTED", "Allow MGMT DNS"}
    assert len(_user_v1(target_state)) == 8


async def test_a_policy_the_v1_body_cannot_express_is_blocked_not_approximated(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    envelope = await _backup(source_server)
    policies = envelope["resources"]["firewall_policies"]
    sched = next(p for p in policies if p["name"] == "Allow Vpn to Internal")
    sched["schedule"] = {"mode": "CUSTOM", "repeat_on_days": ["mon"], "time_all_day": False}
    region = next(p for p in policies if p["name"] == "Block Guest to Internal")
    region["source"]["matching_target"] = "REGION"
    spy = WriteSpy(target_state)

    dry = await _dry(target_server, envelope)
    blocked = {a["name"]: a["reason"] for a in _policy_actions(dry["would_apply"], "blocked")}
    assert "schedule" in blocked["Allow Vpn to Internal"]
    assert "REGION" in blocked["Block Guest to Internal"]

    await _apply(target_server, envelope)
    sent = {args[0]["name"] for method, args in spy.calls if method == "create_policy"}
    assert not sent & {"Allow Vpn to Internal", "Block Guest to Internal"}


async def test_old_backup_without_a_policy_section_writes_no_policy(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    envelope = await _backup(source_server)
    del envelope["resources"]["firewall_policies"]
    del envelope["resources"]["firewall_zones"]
    spy = WriteSpy(target_state)

    dry = await _dry(target_server, envelope)
    assert not _policy_actions(dry["would_apply"])
    assert any("no firewall_policies section" in w for w in dry["warnings"])

    result = await _apply(target_server, envelope)
    assert "error" not in result, result
    assert spy.calls == []
    assert _user_v1(target_state) == []


async def test_a_legacy_target_skips_policies_and_writes_none(
    source_server: FastMCP, stub_server: FastMCP, stub_state: StubState
) -> None:
    envelope = await _backup(source_server)
    spy = WriteSpy(stub_state)
    dry = await _dry(stub_server, envelope)
    skipped = _policy_actions(dry["would_apply"], "skip")
    assert len(skipped) == 10
    assert "legacy" in skipped[0]["reason"]
    assert any("zone polic" in w for w in dry["warnings"])

    await _apply(stub_server, envelope)
    assert spy.calls == []


async def test_a_failed_policy_create_rolls_back_the_policies_already_created(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    envelope = await _backup(source_server)
    fw = target_state.zone_firewall
    original = fw.create_policy
    calls = {"n": 0}

    def _third_fails(body: dict[str, Any]) -> dict[str, Any]:
        calls["n"] += 1
        if calls["n"] == 3:
            from mcp_unifi.clients.errors import UniFiError

            raise UniFiError("UniFi Integration returned 400: boom")
        return original(body)

    fw.create_policy = _third_fails  # type: ignore[method-assign]
    result = await _apply(target_server, envelope)
    assert "boom" in result["error"]
    rolled = [r for r in result["rolled_back"] if r["type"] == "firewall_policies"]
    assert len(rolled) == 2 and all(r["deleted"] for r in rolled)
    assert _user_v1(target_state) == []


async def test_a_group_reference_is_backed_up_by_name_and_blocked_on_restore(
    source_server: FastMCP,
    source_state: StubState,
    target_server: FastMCP,
    target_state: StubState,
) -> None:
    """The v1 body builder has no group filter, so a group match is not
    approximated as a whole-zone match; the backup still names the group."""
    group = source_state.firewall_groups[0]
    policy = next(p for p in source_state.firewall_policies if p["name"] == "Block IoT to TRUSTED")
    policy["destination"] = {
        **policy["destination"],
        "matching_target": "IP",
        "matching_target_type": "OBJECT",
        "ip_group_id": group["_id"],
        "network_ids": [],
    }
    envelope = await _backup(source_server)
    backed = next(
        p for p in envelope["resources"]["firewall_policies"] if p["name"] == "Block IoT to TRUSTED"
    )
    assert backed["destination"]["ip_group_name"] == group["name"]
    assert "ip_group_id" not in backed["destination"]
    assert group["_id"] not in json.dumps(backed)

    dry = await _dry(target_server, envelope)
    blocked = {a["name"]: a["reason"] for a in _policy_actions(dry["would_apply"], "blocked")}
    assert "ip_group_name" in blocked["Block IoT to TRUSTED"]


async def test_a_reference_the_backup_cannot_name_is_blocked_on_restore(
    source_server: FastMCP, source_state: StubState, target_server: FastMCP
) -> None:
    policy = next(p for p in source_state.firewall_policies if p["name"] == "Allow TRUSTED to MGMT")
    policy["source"]["network_ids"] = ["gone-network"]
    envelope = await _backup(source_server)
    backed = next(
        p
        for p in envelope["resources"]["firewall_policies"]
        if p["name"] == "Allow TRUSTED to MGMT"
    )
    assert any("gone-network" in u for u in backed["unresolved"])

    dry = await _dry(target_server, envelope)
    blocked = {a["name"]: a["reason"] for a in _policy_actions(dry["would_apply"], "blocked")}
    assert "gone-network" in blocked["Allow TRUSTED to MGMT"]


async def test_a_network_this_restore_creates_blocks_the_policy_until_a_second_run(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    """Policies are resolved against the site as it is when the plan is made,
    so the confirm token commits exactly the bodies the preview showed."""
    target_state.networks = [n for n in target_state.networks if n.get("name") != "IoT"]
    envelope = await _backup(source_server)
    dry = await _dry(target_server, envelope)
    assert [a["name"] for a in dry["would_apply"] if a["type"] == "networks"] == ["IoT"]
    blocked = {a["name"]: a["reason"] for a in _policy_actions(dry["would_apply"], "blocked")}
    assert "run restore_config again" in blocked["Block IoT to TRUSTED"]

    await _apply(target_server, envelope)
    assert "Block IoT to TRUSTED" not in {p["name"] for p in _user_v1(target_state)}
    for net in target_state.networks:
        if net.get("name") == "IoT":
            net["external_id"] = "iot-v1-id"
    await _apply(target_server, envelope)
    iot = next(p for p in _user_v1(target_state) if p["name"] == "Block IoT to TRUSTED")
    assert iot["source"]["trafficFilter"]["networkFilter"]["networkIds"] == ["iot-v1-id"]
