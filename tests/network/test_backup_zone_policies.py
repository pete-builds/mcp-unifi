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
    preview = await _call(
        server, "restore_config", {"backup_json": json.dumps(envelope), "dry_run": False}
    )
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

    # A second run finds nothing to do: every policy matches its own record,
    # including the four that share a name across zone pairs.
    again = await _dry(target_server, envelope)
    assert not [
        a
        for a in _policy_actions(again["would_apply"])
        if a["action"] in ("create", "update", "blocked")
    ], _policy_actions(again["would_apply"])


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
    """dry_run=False is a preview behind a confirm token; dry_run=True too."""
    envelope = await _backup(source_server)
    spy = WriteSpy(target_state)
    before = copy.deepcopy(target_state.zone_firewall.policies)

    preview = await _call(
        target_server, "restore_config", {"backup_json": json.dumps(envelope), "dry_run": False}
    )
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
    assert sent == set(USER_NAMES) - set(blocked)
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


# ---------------------------------------------------------------------------
# Review round 1 (#265): what an update resets, duplicates, guards, order,
# stale previews, and the dry_run default
# ---------------------------------------------------------------------------


async def _restored_target(source_server: FastMCP, target_server: FastMCP) -> dict[str, Any]:
    """Back up the source, restore it onto the target, return the envelope."""
    envelope = await _backup(source_server)
    result = await _apply(target_server, envelope)
    assert "error" not in result, result
    return envelope


def _target_policy(state: StubState, name: str) -> dict[str, Any]:
    return next(p for p in _user_v1(state) if p["name"] == name)


async def test_restore_defaults_to_a_dry_run_that_mints_no_token(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    envelope = await _backup(source_server)
    spy = WriteSpy(target_state)
    result = await _call(target_server, "restore_config", {"backup_json": json.dumps(envelope)})
    assert result.get("dry_run") is True
    assert "token" not in result
    assert result.get("preview") is not True
    assert len(_policy_actions(result["would_apply"], "create")) == 10
    assert spy.calls == []


async def test_an_update_clears_a_description_the_backup_does_not_have(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    envelope = await _restored_target(source_server, target_server)
    _target_policy(target_state, "Block IoT to TRUSTED")["description"] = "temporary hole"

    dry = await _dry(target_server, envelope)
    updates = _policy_actions(dry["would_apply"], "update")
    assert [(a["name"], a["changes"]) for a in updates] == [
        ("Block IoT to TRUSTED", ["description"])
    ]
    await _apply(target_server, envelope)
    assert _target_policy(target_state, "Block IoT to TRUSTED").get("description", "") == ""


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("connectionStateFilter", ["NEW"]),
        ("ipsecFilter", {"type": "MATCH_IPSEC"}),
    ],
)
async def test_an_update_resets_a_filter_the_backup_does_not_have(
    source_server: FastMCP,
    target_server: FastMCP,
    target_state: StubState,
    key: str,
    value: Any,
) -> None:
    """The backup's policy matches every connection state and no IPsec; a
    target that narrowed either is put back, not reported as a match."""
    envelope = await _restored_target(source_server, target_server)
    _target_policy(target_state, "Block IoT to TRUSTED")[key] = value

    dry = await _dry(target_server, envelope)
    updates = _policy_actions(dry["would_apply"], "update")
    assert [(a["name"], a["changes"]) for a in updates] == [("Block IoT to TRUSTED", [key])]
    assert key not in updates[0]["payload"]

    await _apply(target_server, envelope)
    assert key not in _target_policy(target_state, "Block IoT to TRUSTED")


async def test_a_target_schedule_holds_the_policy_back_instead_of_matching(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    """A business-hours BLOCK on the site against an always-on BLOCK in the
    backup used to read as a match. This server cannot write a v1 schedule,
    so the policy is held back with the reason."""
    envelope = await _restored_target(source_server, target_server)
    victim = _target_policy(target_state, "Block IoT to TRUSTED")
    victim["schedule"] = {"mode": "EVERY_DAY", "timeRangeStart": "09:00", "timeRangeEnd": "17:00"}
    before = copy.deepcopy(victim)
    spy = WriteSpy(target_state)

    dry = await _dry(target_server, envelope)
    mine = [a for a in _policy_actions(dry["would_apply"]) if a["name"] == "Block IoT to TRUSTED"]
    assert [a["action"] for a in mine] == ["blocked"]
    assert "schedule" in mine[0]["reason"]
    assert any("Block IoT to TRUSTED" in w and "schedule" in w for w in dry["warnings"])

    await _apply(target_server, envelope)
    assert spy.calls == []
    assert _target_policy(target_state, "Block IoT to TRUSTED") == before


async def test_an_update_keeps_an_always_schedule_the_site_reports(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    """A schedule already equal to the backup's (ALWAYS) is sent back as the
    site has it, rather than dropped from the PUT."""
    envelope = await _restored_target(source_server, target_server)
    victim = _target_policy(target_state, "Block IoT to TRUSTED")
    victim["schedule"] = {"mode": "ALWAYS"}
    victim["enabled"] = False

    dry = await _dry(target_server, envelope)
    updates = _policy_actions(dry["would_apply"], "update")
    assert [(a["name"], a["changes"]) for a in updates] == [("Block IoT to TRUSTED", ["enabled"])]
    await _apply(target_server, envelope)
    after = _target_policy(target_state, "Block IoT to TRUSTED")
    assert after["enabled"] is True
    assert after["schedule"] == {"mode": "ALWAYS"}


async def test_an_identity_twice_in_the_backup_is_held_back_even_on_an_empty_target(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    envelope = await _backup(source_server)
    policies = envelope["resources"]["firewall_policies"]
    twin = copy.deepcopy(next(p for p in policies if p["name"] == "Allow TRUSTED to MGMT"))
    twin["action"] = "BLOCK"
    policies.append(twin)

    dry = await _dry(target_server, envelope)
    mine = [a for a in _policy_actions(dry["would_apply"]) if a["name"] == "Allow TRUSTED to MGMT"]
    assert [a["action"] for a in mine] == ["blocked"]
    assert "2 in the backup" in mine[0]["reason"]

    await _apply(target_server, envelope)
    assert "Allow TRUSTED to MGMT" not in {p["name"] for p in _user_v1(target_state)}


@pytest.mark.parametrize(
    ("where", "key", "value", "words"),
    [
        ("source", "match_opposite_networks", True, "match_opposite_networks"),
        ("destination", "match_opposite_ips", True, "match_opposite_ips"),
        ("destination", "match_opposite_ports", True, "match_opposite_ports"),
        (None, "icmp_typename", "ECHO_REQUEST", "icmp_typename"),
        (None, "icmp_v6_typename", "ECHO_REQUEST", "icmp_v6_typename"),
        (None, "match_ip_sec", True, "match_ip_sec"),
        (None, "match_opposite_protocol", True, "match_opposite_protocol"),
    ],
)
async def test_a_match_the_v1_body_would_widen_is_held_back(
    source_server: FastMCP,
    target_server: FastMCP,
    target_state: StubState,
    where: str | None,
    key: str,
    value: Any,
    words: str,
) -> None:
    """Negated matches, ICMP types, IPsec and a negated protocol have no place
    in the v1 body this server builds; writing without them would match more."""
    envelope = await _backup(source_server)
    spec = next(
        p for p in envelope["resources"]["firewall_policies"] if p["name"] == "Block IoT to TRUSTED"
    )
    (spec[where] if where else spec)[key] = value
    spy = WriteSpy(target_state)

    dry = await _dry(target_server, envelope)
    mine = [a for a in _policy_actions(dry["would_apply"]) if a["name"] == "Block IoT to TRUSTED"]
    assert [a["action"] for a in mine] == ["blocked"]
    assert words in mine[0]["reason"]

    await _apply(target_server, envelope)
    sent = {args[0]["name"] for method, args in spy.calls if method == "create_policy"}
    assert "Block IoT to TRUSTED" not in sent


async def test_custom_connection_states_are_written_as_the_backup_has_them(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    """An ESTABLISHED/RELATED-only ALLOW must never come back as all-states."""
    envelope = await _backup(source_server)
    spec = next(
        p
        for p in envelope["resources"]["firewall_policies"]
        if p["name"] == "Allow Vpn to Internal"
    )
    spec["connection_state_type"] = "CUSTOM"
    spec["connection_states"] = ["ESTABLISHED", "RELATED"]
    await _apply(target_server, envelope)
    restored = _target_policy(target_state, "Allow Vpn to Internal")
    assert restored["connectionStateFilter"] == ["ESTABLISHED", "RELATED"]


async def test_both_ip_versions_restore_as_both(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    envelope = await _backup(source_server)
    spec = next(
        p
        for p in envelope["resources"]["firewall_policies"]
        if p["name"] == "Allow Vpn to Internal"
    )
    spec["ip_version"] = "BOTH"
    await _apply(target_server, envelope)
    restored = _target_policy(target_state, "Allow Vpn to Internal")
    assert restored["ipProtocolScope"]["ipVersion"] == "IPV4_AND_IPV6"


async def test_a_network_this_restore_deletes_holds_its_policies_back(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    envelope = await _backup(source_server)
    envelope["resources"]["networks"] = [
        n for n in envelope["resources"]["networks"] if n.get("name") != "IoT"
    ]
    spy = WriteSpy(target_state)

    dry = await _dry(target_server, envelope)
    assert [
        a["name"] for a in dry["would_apply"] if a["type"] == "networks" and a["action"] == "delete"
    ] == ["IoT"]
    blocked = {a["name"]: a["reason"] for a in _policy_actions(dry["would_apply"], "blocked")}
    assert "deleted by this restore" in blocked["Block IoT to TRUSTED"]

    await _apply(target_server, envelope)
    sent = {args[0]["name"] for method, args in spy.calls if method == "create_policy"}
    assert "Block IoT to TRUSTED" not in sent


async def test_a_failed_create_reverts_an_update_already_applied(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    envelope = await _restored_target(source_server, target_server)
    fw = target_state.zone_firewall
    # The Internal -> Internal Ecowitt policy (index 10000) is planned before
    # "Block IoT to TRUSTED" (index 10002): an update, then a create.
    internal = fw.zone_ids["Internal"]
    updated = next(
        p
        for p in _user_v1(target_state)
        if p["name"] == ECOWITT and p["destination"]["zoneId"] == internal
    )
    updated["enabled"] = False
    fw.policies = [p for p in fw.policies if p.get("name") != "Block IoT to TRUSTED"]

    def _fails(body: dict[str, Any]) -> dict[str, Any]:
        from mcp_unifi.clients.errors import UniFiError

        raise UniFiError("UniFi Integration returned 400: boom")

    fw.create_policy = _fails  # type: ignore[method-assign]
    result = await _apply(target_server, envelope)
    assert "boom" in result["error"]
    assert [a["result"] for a in result["partial"] if a.get("result") == "updated"] == ["updated"]
    reverted = [r for r in result["rolled_back"] if r.get("reverted") is not None]
    assert reverted == [{"type": "firewall_policies", "id": updated["id"], "reverted": True}]
    assert next(p for p in fw.policies if p["id"] == updated["id"])["enabled"] is False


async def test_creating_into_a_zone_pair_with_other_user_policies_warns_about_order(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    """First match wins, and a created policy lands after the ones already in
    its zone pair, so a restored BLOCK can sit below an ALLOW."""
    fw = target_state.zone_firewall
    fw.create_policy(
        {
            "name": "Lab allow",
            "enabled": True,
            "loggingEnabled": False,
            "action": {"type": "ALLOW", "allowReturnTraffic": True},
            "source": {"zoneId": fw.zone_ids["Internal"]},
            "destination": {"zoneId": fw.zone_ids["Internal"]},
            "ipProtocolScope": {"ipVersion": "IPV4"},
        }
    )
    envelope = await _backup(source_server)
    dry = await _dry(target_server, envelope)
    order = [w for w in dry["warnings"] if "order" in w]
    assert len(order) == 1
    assert "Internal -> Internal" in order[0]
    assert "Internal -> Hotspot" not in order[0]


async def test_matched_policies_in_a_different_order_are_reported(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    envelope = await _restored_target(source_server, target_server)
    allow = _target_policy(target_state, "Allow TRUSTED to MGMT")
    block = _target_policy(target_state, "Block IoT to TRUSTED")
    allow["index"], block["index"] = block["index"], allow["index"]

    dry = await _dry(target_server, envelope)
    order = [w for w in dry["warnings"] if "order" in w]
    assert len(order) == 1
    assert "Internal -> Internal" in order[0]

    clean = await _restored_target(source_server, target_server)
    allow["index"], block["index"] = block["index"], allow["index"]
    again = await _dry(target_server, clean)
    assert not [w for w in again["warnings"] if "order" in w]


async def test_a_policy_edited_after_the_preview_is_refused_at_confirm(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    envelope = await _restored_target(source_server, target_server)
    victim = _target_policy(target_state, "Block IoT to TRUSTED")
    victim["enabled"] = False

    preview = await _call(
        target_server, "restore_config", {"backup_json": json.dumps(envelope), "dry_run": False}
    )
    assert [a["name"] for a in _policy_actions(preview["resource"]["plan"], "update")] == [
        "Block IoT to TRUSTED"
    ]
    # Someone edits the policy between the preview and the confirm.
    victim["loggingEnabled"] = True
    edited = copy.deepcopy(victim)
    spy = WriteSpy(target_state)

    result = await _call(target_server, "confirm_destructive_action", {"token": preview["token"]})
    assert "error" not in result, result
    mine = [a for a in result["applied"] if a.get("name") == "Block IoT to TRUSTED"]
    assert [a["result"] for a in mine] == ["refused"]
    assert "changed since the preview" in mine[0]["reason"]
    assert spy.calls == []
    assert _target_policy(target_state, "Block IoT to TRUSTED") == edited
    assert "1 refused" in result["summary"]
    assert any("Block IoT to TRUSTED" in w and "refused" in w for w in result["warnings"]), result[
        "warnings"
    ]


# ---------------------------------------------------------------------------
# Review round 2 (#265): zone membership, the post-update readback, the
# refused count, and schedule spellings
# ---------------------------------------------------------------------------


def _add_target_lan(state: StubState, name: str) -> None:
    state.networks.append(
        {
            "_id": f"{name}-private",
            "external_id": f"{name}-v1",
            "name": name,
            "purpose": "corporate",
            "ip_subnet": "10.9.9.1/24",
            "enabled": True,
        }
    )


ZONE_WIDE = ("Block Hotspot to Internal", "Allow web from anywhere")


def _add_zone_wide_policies(state: StubState) -> None:
    """Two v2 operator policies with a side matching a whole zone: one fully
    zone-wide, one whose source is all of External with a port-only filter."""
    from mcp_unifi.clients.zone_firewall_stubs import _v2_endpoint, _v2_policy

    zone = {z["name"]: z["_id"] for z in state.firewall_zones}
    state.firewall_policies.extend(
        [
            _v2_policy(
                ZONE_WIDE[0],
                "BLOCK",
                _v2_endpoint(zone["Hotspot"], side="source"),
                _v2_endpoint(zone["Internal"], side="destination"),
                index=10010,
            ),
            _v2_policy(
                ZONE_WIDE[1],
                "ALLOW",
                _v2_endpoint(zone["External"], side="source", port="443"),
                _v2_endpoint(zone["Internal"], side="destination", ips=["192.168.86.20"]),
                index=10011,
                protocol="tcp",
            ),
        ]
    )


@pytest.mark.parametrize("extra_lan", [False, True], ids=["same-members", "extra-member"])
async def test_a_zone_wide_policy_is_backed_up_but_never_restored(
    source_server: FastMCP,
    source_state: StubState,
    target_server: FastMCP,
    target_state: StubState,
    extra_lan: bool,
) -> None:
    """Whatever the target zone holds, identical or not: restore cannot prove
    a zone matched by name covers the same networks, so it never writes one."""
    _add_zone_wide_policies(source_state)
    if extra_lan:
        _add_target_lan(target_state, "Lab")
    envelope = await _backup(source_server)
    backed = {p["name"]: p for p in envelope["resources"]["firewall_policies"]}
    assert backed[ZONE_WIDE[0]]["source"]["matching_target"] == "ANY"
    assert backed[ZONE_WIDE[1]]["source"]["port"] == "443"
    spy = WriteSpy(target_state)

    dry = await _dry(target_server, envelope)
    blocked = {a["name"]: a["reason"] for a in _policy_actions(dry["would_apply"], "blocked")}
    assert set(blocked) == set(ZONE_WIDE)
    assert "every network in zone 'Hotspot'" in blocked[ZONE_WIDE[0]]
    assert "every network in zone 'External'" in blocked[ZONE_WIDE[1]]
    for reason in blocked.values():
        assert "create_firewall_policy" in reason

    await _apply(target_server, envelope)
    sent = {args[0]["name"] for method, args in spy.calls if method == "create_policy"}
    assert sent == set(USER_NAMES)


async def test_backup_counts_zone_members_it_cannot_name(
    source_server: FastMCP, source_state: StubState
) -> None:
    internal = next(z for z in source_state.firewall_zones if z["name"] == "Internal")
    internal["network_ids"] = [*internal["network_ids"], "ghost-network-id"]
    envelope = await _backup(source_server)
    zones = {z["name"]: z for z in envelope["resources"]["firewall_zones"]}
    assert zones["Internal"]["unnamed_members"] == 1
    assert zones["Hotspot"]["unnamed_members"] == 0
    assert "ghost-network-id" not in json.dumps(zones)


async def test_two_target_networks_with_one_name_hold_back_a_policy_naming_it(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    _add_target_lan(target_state, "MGMT")
    envelope = await _backup(source_server)
    dry = await _dry(target_server, envelope)
    blocked = {a["name"]: a["reason"] for a in _policy_actions(dry["would_apply"], "blocked")}
    assert set(blocked) == {"Allow TRUSTED to MGMT", "Allow MGMT DNS"}
    for reason in blocked.values():
        assert "2 networks on the site are named 'MGMT'" in reason


async def test_unreadable_zone_membership_holds_back_only_network_scoped_sides(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    """With Internal's member list missing, nothing proves a named network
    sits in it; address-only policies are unaffected."""
    fw = target_state.zone_firewall
    original = fw.zones

    def _no_members(networks: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out = original(networks)
        for zone in out:
            if zone["name"] == "Internal":
                del zone["networkIds"]
        return out

    fw.zones = _no_members  # type: ignore[method-assign]
    envelope = await _backup(source_server)
    dry = await _dry(target_server, envelope)
    blocked = {a["name"]: a["reason"] for a in _policy_actions(dry["would_apply"], "blocked")}
    assert set(blocked) == {
        "Allow TRUSTED to MGMT",
        "Block IoT to TRUSTED",
        "Allow MGMT DNS",
        "Allow Vpn to Internal",
    }
    created = {a["name"] for a in _policy_actions(dry["would_apply"], "create")}
    assert ECOWITT in created and "Allow Dewfront web" in created


async def test_zone_members_the_site_cannot_name_never_block_a_provable_match(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    fw = target_state.zone_firewall
    original = fw.zones

    def _with_ghost(networks: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out = original(networks)
        for zone in out:
            zone["networkIds"] = [*zone["networkIds"], "ghost-v1-id"]
        return out

    fw.zones = _with_ghost  # type: ignore[method-assign]
    envelope = await _backup(source_server)
    dry = await _dry(target_server, envelope)
    assert not _policy_actions(dry["would_apply"], "blocked")
    assert len(_policy_actions(dry["would_apply"], "create")) == 10


async def test_a_network_scoped_side_is_held_back_when_its_network_sits_in_another_zone(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    """On the target TRUSTED is a guest LAN, so it sits in Hotspot, not Internal."""
    trusted = next(n for n in target_state.networks if n.get("name") == "TRUSTED")
    trusted["purpose"] = "guest"
    envelope = await _backup(source_server)
    spy = WriteSpy(target_state)

    dry = await _dry(target_server, envelope)
    blocked = {a["name"]: a["reason"] for a in _policy_actions(dry["would_apply"], "blocked")}
    for name in ("Allow TRUSTED to MGMT", "Block IoT to TRUSTED", "Allow Vpn to Internal"):
        assert "'TRUSTED'" in blocked[name] and "not in" in blocked[name]
    # MGMT is still in Internal: a policy naming only MGMT there restores.
    assert "Allow MGMT DNS" not in blocked

    await _apply(target_server, envelope)
    sent = {args[0]["name"] for method, args in spy.calls if method == "create_policy"}
    assert "Allow MGMT DNS" in sent
    assert not sent & {"Allow TRUSTED to MGMT", "Block IoT to TRUSTED", "Allow Vpn to Internal"}


async def test_identical_zone_membership_holds_nothing_back(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    envelope = await _backup(source_server)
    dry = await _dry(target_server, envelope)
    assert not _policy_actions(dry["would_apply"], "blocked")
    assert len(_policy_actions(dry["would_apply"], "create")) == 10


async def test_a_console_that_keeps_an_omitted_filter_rolls_the_whole_restore_back(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState
) -> None:
    """The reset-by-omission assumption is checked by re-reading the policy.
    A console that merges a PUT instead of replacing it keeps the filter, and
    the restore must fail and undo both the earlier create and the update."""
    envelope = await _restored_target(source_server, target_server)
    fw = target_state.zone_firewall
    hotspot = fw.zone_ids["Hotspot"]
    gone = next(
        p
        for p in _user_v1(target_state)
        if p["name"] == ECOWITT and p["destination"]["zoneId"] == hotspot
    )
    fw.policies = [p for p in fw.policies if p["id"] != gone["id"]]
    victim = _target_policy(target_state, "Block IoT to TRUSTED")
    victim["connectionStateFilter"] = ["NEW"]
    before = copy.deepcopy(victim)

    def _merging_put(policy_id: str, body: dict[str, Any]) -> dict[str, Any]:
        for i, policy in enumerate(fw.policies):
            if policy.get("id") == policy_id:
                fw.policies[i] = {**policy, **body}
                return fw.policies[i]
        raise AssertionError(policy_id)

    fw.update_policy = _merging_put  # type: ignore[method-assign]
    dry = await _dry(target_server, envelope)
    kinds = [(a["action"], a["name"]) for a in _policy_actions(dry["would_apply"])]
    assert kinds.index(("create", ECOWITT)) < kinds.index(("update", "Block IoT to TRUSTED"))

    result = await _apply(target_server, envelope)
    assert "connectionStateFilter" in result["error"]
    rolled = [r for r in result["rolled_back"] if r["type"] == "firewall_policies"]
    assert {"type": "firewall_policies", "id": victim["id"], "reverted": True} in rolled
    assert any(r.get("deleted") is True for r in rolled)
    assert not [
        p
        for p in _user_v1(target_state)
        if p["name"] == ECOWITT and p["destination"]["zoneId"] == hotspot
    ]
    assert _target_policy(target_state, "Block IoT to TRUSTED") == before


@pytest.mark.parametrize("schedule", ["ALWAYS", "always", {"mode": "always"}])
async def test_an_always_schedule_in_any_spelling_does_not_hold_back(
    source_server: FastMCP, target_server: FastMCP, target_state: StubState, schedule: Any
) -> None:
    envelope = await _restored_target(source_server, target_server)
    victim = _target_policy(target_state, "Block IoT to TRUSTED")
    victim["schedule"] = schedule
    victim["enabled"] = False

    dry = await _dry(target_server, envelope)
    mine = [a for a in _policy_actions(dry["would_apply"]) if a["name"] == "Block IoT to TRUSTED"]
    assert [(a["action"], a.get("changes")) for a in mine] == [("update", ["enabled"])]


@pytest.mark.parametrize(
    ("schedule", "quoted"),
    [
        ({"type": "ALWAYS"}, "{'type': 'ALWAYS'}"),
        ({"mode": None}, "{'mode': None}"),
        ("WEEKDAYS", "'WEEKDAYS'"),
    ],
)
async def test_an_unrecognised_schedule_holds_back_quoting_what_the_site_returned(
    source_server: FastMCP,
    target_server: FastMCP,
    target_state: StubState,
    schedule: Any,
    quoted: str,
) -> None:
    envelope = await _restored_target(source_server, target_server)
    _target_policy(target_state, "Block IoT to TRUSTED")["schedule"] = schedule
    dry = await _dry(target_server, envelope)
    mine = [a for a in _policy_actions(dry["would_apply"]) if a["name"] == "Block IoT to TRUSTED"]
    assert [a["action"] for a in mine] == ["blocked"]
    assert quoted in mine[0]["reason"]
    assert "mode None" not in mine[0]["reason"]


# ---------------------------------------------------------------------------
# Review round 4 (#265): blank address lists, destination-only zone-wide
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ips", "port"),
    [([""], ""), (["   "], ""), ([" "], "443")],
    ids=["empty", "spaces", "space-plus-port"],
)
async def test_an_address_side_with_only_blank_entries_is_held_back(
    source_server: FastMCP,
    target_server: FastMCP,
    target_state: StubState,
    ips: list[str],
    port: str,
) -> None:
    """Blank entries are dropped when the body is built, which used to leave
    a source with no filter (or a port-only one): a zone-wide policy."""
    envelope = await _backup(source_server)
    spec = next(
        p for p in envelope["resources"]["firewall_policies"] if p["name"] == "Allow Dewfront web"
    )
    spec["source"]["ips"] = ips
    if port:
        spec["source"]["port"] = port
        spec["source"]["port_matching_type"] = "SPECIFIC"
    spy = WriteSpy(target_state)

    dry = await _dry(target_server, envelope)
    mine = [a for a in _policy_actions(dry["would_apply"]) if a["name"] == "Allow Dewfront web"]
    assert [a["action"] for a in mine] == ["blocked"], mine
    assert "source" in mine[0]["reason"] and "blank" in mine[0]["reason"]
    assert not [
        a
        for a in _policy_actions(dry["would_apply"], "create")
        if "trafficFilter" not in a["payload"]["source"]
        or a["payload"]["source"]["trafficFilter"].get("type") == "PORT"
    ]

    await _apply(target_server, envelope)
    sent = {args[0]["name"] for method, args in spy.calls if method == "create_policy"}
    assert "Allow Dewfront web" not in sent


async def test_a_policy_zone_wide_only_on_its_destination_is_held_back(
    source_server: FastMCP,
    source_state: StubState,
    target_server: FastMCP,
    target_state: StubState,
) -> None:
    from mcp_unifi.clients.zone_firewall_stubs import _v2_endpoint, _v2_policy

    zone = {z["name"]: z["_id"] for z in source_state.firewall_zones}
    trusted = next(n["_id"] for n in source_state.networks if n.get("name") == "TRUSTED")
    source_state.firewall_policies.append(
        _v2_policy(
            "Allow TRUSTED to all Internal",
            "ALLOW",
            _v2_endpoint(zone["Internal"], side="source", networks=[trusted]),
            _v2_endpoint(zone["Internal"], side="destination"),
            index=10020,
        )
    )
    envelope = await _backup(source_server)
    spy = WriteSpy(target_state)

    dry = await _dry(target_server, envelope)
    blocked = {a["name"]: a["reason"] for a in _policy_actions(dry["would_apply"], "blocked")}
    assert set(blocked) == {"Allow TRUSTED to all Internal"}
    assert (
        "destination matches every network in zone 'Internal'"
        in blocked["Allow TRUSTED to all Internal"]
    )

    await _apply(target_server, envelope)
    sent = {args[0]["name"] for method, args in spy.calls if method == "create_policy"}
    assert sent == set(USER_NAMES)


async def test_a_side_that_builds_to_no_filter_is_held_back(
    source_server: FastMCP,
    target_server: FastMCP,
    target_state: StubState,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The zone-wide guard runs on the body that would be sent, not only on
    the backup's input: an address list the body builder turns into no items
    must not reach the console as a whole-zone match."""
    from mcp_unifi.clients import zone_policy

    monkeypatch.setattr(zone_policy, "address_items", lambda addresses: [])
    envelope = await _backup(source_server)
    spy = WriteSpy(target_state)

    dry = await _dry(target_server, envelope)
    blocked = {a["name"]: a["reason"] for a in _policy_actions(dry["would_apply"], "blocked")}
    # Every policy with an address side; the four Ecowitt ones share a name.
    assert set(blocked) == {
        ECOWITT,
        "Allow MGMT DNS",
        "Block Guest to Internal",
        "Allow Vpn to Internal",
        "Allow Dewfront web",
    }
    for reason in blocked.values():
        assert "matches every network in zone" in reason
    for action in _policy_actions(dry["would_apply"], "create"):
        for side in ("source", "destination"):
            assert action["payload"][side]["trafficFilter"]["type"] == "NETWORK"

    await _apply(target_server, envelope)
    sent = {args[0]["name"] for method, args in spy.calls if method == "create_policy"}
    assert sent == {"Allow TRUSTED to MGMT", "Block IoT to TRUSTED"}
