"""Tests for ``backup_config`` and ``restore_config`` (Phase 2, Part B).

Coverage:

* Round-trip on a clean state — backup, immediately restore, no actions.
* Round-trip with mutations — diff surfaces deletes/creates correctly.
* Envelope shape: schema, controller, ts, resource sub-keys, counts.
* Secret stripping on backup: passphrases sentineled, ``secrets_stripped`` set.
* Restore dry-run preview never mutates state.
* Schema mismatch returns a clear error envelope.
* Wrong controller name → warning, restore still proceeds.
* Stripped-secret restore force-disables WLANs and surfaces a warning.
* Partial failure rollback restores resource state.
* Hypothesis property test: random mutations between backup and restore must
  converge back to the snapshot.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from fastmcp import FastMCP
from hypothesis import HealthCheck, given
from hypothesis import settings as hyp_settings
from hypothesis import strategies as st

from mcp_unifi.clients.stubs import StubState
from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.config import Settings
from mcp_unifi.modules.network.backup import (
    BACKUP_SCHEMA,
    NOT_INCLUDED,
    REDACTED_PASSPHRASE,
)
from mcp_unifi.redaction import REDACTED_OUTPUT
from mcp_unifi.server import build_server
from tests.network.conftest import _call


async def _restore_applying(server, backup_json: str):
    """Run restore_config through the preview-then-confirm gate.

    restore_config used to apply on the first call. It now returns a preview
    envelope carrying a one-time token, matching the eleven delete_* tools, so
    tests that want the restore actually applied have to confirm it. Driving the
    real two-step flow here also means these tests exercise the gate rather than
    bypassing it.
    """
    preview = await _call(server, "restore_config", {"backup_json": backup_json})
    assert preview.get("preview") is True, f"expected a preview envelope, got {preview}"
    return await _call(server, "confirm_destructive_action", {"token": preview["token"]})


# ---------------------------------------------------------------------------
# Hypothesis profile — derandomized for CI reproducibility
# ---------------------------------------------------------------------------

hyp_settings.register_profile(
    "backup_restore_ci",
    deadline=None,
    derandomize=True,
    max_examples=30,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
hyp_settings.load_profile("backup_restore_ci")


# ---------------------------------------------------------------------------
# Snapshot helpers
# ---------------------------------------------------------------------------


def _resource_snapshot(state: StubState) -> dict[str, list[dict[str, Any]]]:
    """Deep copy every resource list ``backup_config`` cares about.

    Leases are taken through ``list_dhcp_leases`` (the ``use_fixedip``
    filter): clearing a reservation keeps the user record with the flag off,
    on real hardware and in the stub alike (issue #124, item 3), so the raw
    user list legitimately grows while the reservations are restored.
    """
    return {
        "networks": copy.deepcopy(state.networks),
        "wlans": copy.deepcopy(state.wlans),
        "firewall_rules": copy.deepcopy(state.firewall_rules),
        "port_profiles": copy.deepcopy(state.port_profiles),
        "dhcp_leases": copy.deepcopy(state.list_dhcp_leases()),
        "port_forwards": copy.deepcopy(state.port_forwards),
    }


def _normalized_view(state: StubState) -> dict[str, list[dict[str, Any]]]:
    """Resource view stripped of controller-assigned IDs for set-equality.

    Two snapshots may carry different ``_id`` strings after a delete/create
    cycle even though they are functionally identical. We compare on the
    operator-meaningful fields.
    """
    snap = _resource_snapshot(state)
    out: dict[str, list[dict[str, Any]]] = {}
    for rtype, items in snap.items():
        cleaned: list[dict[str, Any]] = []
        for item in items:
            without_id = {k: v for k, v in item.items() if k not in {"_id", "site_id"}}
            cleaned.append(without_id)
        out[rtype] = cleaned
    return out


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fresh_state() -> StubState:
    """Per-test stub state (Hypothesis runs many examples)."""
    return StubState()


@pytest.fixture
def fresh_server(stub_settings: Settings, fresh_state: StubState) -> FastMCP:
    return build_server(stub_settings, stub=fresh_state)


# ---------------------------------------------------------------------------
# Envelope shape & basic backup
# ---------------------------------------------------------------------------


async def test_backup_envelope_shape(stub_server: FastMCP) -> None:
    envelope = await _call(stub_server, "backup_config", {})
    assert envelope["schema"] == BACKUP_SCHEMA
    assert envelope["controller"] == "default"
    assert isinstance(envelope["ts"], str) and "T" in envelope["ts"]
    assert isinstance(envelope["secrets_stripped"], bool)

    resources = envelope["resources"]
    assert set(resources.keys()) == {
        "networks",
        "firewall_groups",
        "wlans",
        "firewall_rules",
        "port_profiles",
        "dhcp_leases",
        "port_forwards",
    }
    # Seed state always carries at least one of each. (DHCP leases seed has
    # one entry; port_forwards seed has one entry.)
    for rtype, items in resources.items():
        assert isinstance(items, list), f"{rtype} must be a list"
        assert len(items) >= 1, f"{rtype} unexpectedly empty in seed"


async def test_backup_strips_wlan_passphrases(stub_server: FastMCP) -> None:
    envelope = await _call(stub_server, "backup_config", {})
    assert envelope["secrets_stripped"] is True
    for wlan in envelope["resources"]["wlans"]:
        # The backup pass writes ``<redacted-on-backup>``; the response
        # serialiser rewrites it to ``[REDACTED]`` on the way out, so this
        # is what a caller sees and pastes back into ``restore_config``.
        assert wlan.get("x_passphrase") == REDACTED_OUTPUT


async def test_backup_drops_internal_ids(stub_server: FastMCP) -> None:
    """``_id`` is dropped from everything except networks and firewall groups.

    Those two retain ``_id`` so references to them (a WLAN's networkconf_id,
    a rule's firewall group ids) can be remapped at restore time. ``site_id``
    is dropped everywhere because it doesn't survive a cross-controller
    restore.
    """
    envelope = await _call(stub_server, "backup_config", {})
    for rtype, items in envelope["resources"].items():
        for item in items:
            assert "site_id" not in item, f"{rtype} record leaked site_id into backup"
            if rtype in ("networks", "firewall_groups"):
                # Referenced types intentionally keep _id for remapping.
                assert item.get("_id"), f"{rtype} record lost its _id"
                continue
            assert "_id" not in item, f"{rtype} record leaked _id into backup"


async def test_backup_unknown_controller_returns_error(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "backup_config", {"controller": "nope"})
    assert "error" in result
    assert "nope" in result["error"]


# ---------------------------------------------------------------------------
# Round-trip: clean state
# ---------------------------------------------------------------------------


async def test_round_trip_clean_state_is_noop(stub_server: FastMCP) -> None:
    """backup -> no mutations -> restore plan is empty in dry-run AND apply."""
    envelope = await _call(stub_server, "backup_config", {})
    backup_json = json.dumps(envelope)

    # Dry-run plan
    dry = await _call(stub_server, "restore_config", {"backup_json": backup_json, "dry_run": True})
    assert dry["dry_run"] is True
    create_actions = [a for a in dry["would_apply"] if a["action"] == "create"]
    delete_actions = [a for a in dry["would_apply"] if a["action"] == "delete"]
    assert create_actions == []
    assert delete_actions == []

    # Real apply also yields zero create/delete actions.
    real = await _restore_applying(stub_server, backup_json)
    assert "error" not in real
    creates = [a for a in real["applied"] if a.get("result") == "created"]
    deletes = [a for a in real["applied"] if a.get("result") == "deleted"]
    assert creates == []
    assert deletes == []


# ---------------------------------------------------------------------------
# Round-trip with mutations
# ---------------------------------------------------------------------------


async def test_round_trip_with_added_vlan_dry_run_flags_delete(
    fresh_state: StubState, fresh_server: FastMCP
) -> None:
    """backup -> add VLAN -> restore (dry-run) shows a delete in the plan."""
    envelope = await _call(fresh_server, "backup_config", {})
    backup_json = json.dumps(envelope)

    fresh_state.create_network(
        {
            "name": "Lab",
            "purpose": "corporate",
            "vlan_enabled": True,
            "vlan": 99,
            "ip_subnet": "10.99.0.0/24",
            "enabled": True,
        }
    )

    dry = await _call(fresh_server, "restore_config", {"backup_json": backup_json, "dry_run": True})
    deletes = [a for a in dry["would_apply"] if a["action"] == "delete" and a["type"] == "networks"]
    assert any(a["name"] == "Lab" for a in deletes), (
        f"expected delete of 'Lab' in plan, got {deletes}"
    )

    # State must NOT have changed during the dry-run.
    assert any(n["name"] == "Lab" for n in fresh_state.networks)


async def test_round_trip_with_added_vlan_real_apply_restores(
    fresh_state: StubState, fresh_server: FastMCP
) -> None:
    """backup -> add VLAN -> restore (real) deletes the extra."""
    envelope = await _call(fresh_server, "backup_config", {})
    backup_json = json.dumps(envelope)

    fresh_state.create_network(
        {
            "name": "Lab",
            "purpose": "corporate",
            "vlan_enabled": True,
            "vlan": 99,
            "ip_subnet": "10.99.0.0/24",
            "enabled": True,
        }
    )
    assert any(n["name"] == "Lab" for n in fresh_state.networks)

    result = await _restore_applying(fresh_server, backup_json)
    assert "error" not in result
    assert not any(n["name"] == "Lab" for n in fresh_state.networks)


async def test_round_trip_with_removed_vlan_real_apply_recreates(
    fresh_state: StubState, fresh_server: FastMCP
) -> None:
    """backup -> remove the seed network -> restore recreates it."""
    fresh_state.create_network(
        {
            "name": "Keep-Me",
            "purpose": "corporate",
            "vlan_enabled": True,
            "vlan": 77,
            "ip_subnet": "10.77.0.0/24",
            "enabled": True,
        }
    )
    envelope = await _call(fresh_server, "backup_config", {})
    backup_json = json.dumps(envelope)

    # Remove the network we just added.
    target_id = next(n["_id"] for n in fresh_state.networks if n["name"] == "Keep-Me")
    fresh_state.delete_network(target_id)
    assert not any(n["name"] == "Keep-Me" for n in fresh_state.networks)

    result = await _restore_applying(fresh_server, backup_json)
    assert "error" not in result
    assert any(n["name"] == "Keep-Me" for n in fresh_state.networks)


# ---------------------------------------------------------------------------
# Restore dry-run does not mutate state
# ---------------------------------------------------------------------------


async def test_dry_run_never_mutates(fresh_state: StubState, fresh_server: FastMCP) -> None:
    envelope = await _call(fresh_server, "backup_config", {})
    backup_json = json.dumps(envelope)

    fresh_state.create_network(
        {
            "name": "Drift",
            "purpose": "corporate",
            "vlan_enabled": True,
            "vlan": 33,
            "ip_subnet": "10.33.0.0/24",
            "enabled": True,
        }
    )

    snapshot = _resource_snapshot(fresh_state)
    result = await _call(
        fresh_server, "restore_config", {"backup_json": backup_json, "dry_run": True}
    )
    assert result["dry_run"] is True
    assert _resource_snapshot(fresh_state) == snapshot


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


async def test_schema_mismatch_returns_clean_error(
    fresh_state: StubState, fresh_server: FastMCP
) -> None:
    bad = {"schema": "2", "controller": "default", "resources": {}}
    snapshot = _resource_snapshot(fresh_state)
    result = await _call(fresh_server, "restore_config", {"backup_json": json.dumps(bad)})
    assert "error" in result
    assert "schema" in result["error"].lower()
    assert _resource_snapshot(fresh_state) == snapshot


async def test_malformed_json_returns_clean_error(
    fresh_state: StubState, fresh_server: FastMCP
) -> None:
    snapshot = _resource_snapshot(fresh_state)
    result = await _call(fresh_server, "restore_config", {"backup_json": "{not json"})
    assert "error" in result
    assert _resource_snapshot(fresh_state) == snapshot


async def test_missing_resources_object_returns_clean_error(
    fresh_state: StubState, fresh_server: FastMCP
) -> None:
    bad = {"schema": "1", "controller": "default"}
    result = await _call(fresh_server, "restore_config", {"backup_json": json.dumps(bad)})
    assert "error" in result
    assert "resources" in result["error"]


# ---------------------------------------------------------------------------
# Cross-controller warning
# ---------------------------------------------------------------------------


async def test_cross_controller_warning_proceeds(multi_site_server: FastMCP) -> None:
    """Backup from 'home' restored to 'office' surfaces a warning and proceeds."""
    envelope = await _call(multi_site_server, "backup_config", {"controller": "home"})
    backup_json = json.dumps(envelope)

    result = await _call(
        multi_site_server,
        "restore_config",
        {"backup_json": backup_json, "controller": "office", "dry_run": True},
    )
    assert any("home" in w and "office" in w for w in result["warnings"])
    assert result["dry_run"] is True


# ---------------------------------------------------------------------------
# WLAN -> network rebinding across recreate
# ---------------------------------------------------------------------------


async def test_wlan_rebinds_to_recreated_network(
    fresh_state: StubState, fresh_server: FastMCP
) -> None:
    """Delete a network *and* its WLAN, then restore.

    The restore must recreate the network with a fresh ``_id`` and rebind
    the recreated WLAN's ``networkconf_id`` to that fresh id (resolved via
    the network name). This is the load-bearing rebinding path.
    """
    # Add a named network and WLAN bound to it.
    new_net = fresh_state.create_network(
        {
            "name": "Rebound",
            "purpose": "corporate",
            "vlan_enabled": True,
            "vlan": 44,
            "ip_subnet": "10.44.0.0/24",
            "enabled": True,
        }
    )
    fresh_state.create_wlan(
        {
            "name": "Rebound-SSID",
            "enabled": True,
            "security": "wpapsk",
            "wpa_mode": "wpa2",
            "x_passphrase": "originalpass",
            "networkconf_id": new_net["_id"],
            "is_guest": False,
            "hide_ssid": False,
            "wlan_band": "both",
        }
    )

    envelope = await _call(fresh_server, "backup_config", {})
    backup_json = json.dumps(envelope)

    # Tear both down. Recreate would yield fresh ids; restore must rebind.
    fresh_state.delete_wlan(
        next(w["_id"] for w in fresh_state.wlans if w["name"] == "Rebound-SSID")
    )
    fresh_state.delete_network(new_net["_id"])

    result = await _restore_applying(fresh_server, backup_json)
    assert "error" not in result

    restored_net = next(n for n in fresh_state.networks if n["name"] == "Rebound")
    restored_wlan = next(w for w in fresh_state.wlans if w["name"] == "Rebound-SSID")
    # The restored WLAN's networkconf_id must equal the *new* network id.
    assert restored_wlan["networkconf_id"] == restored_net["_id"]


# ---------------------------------------------------------------------------
# Stripped-secrets warning + force-disable WLANs
# ---------------------------------------------------------------------------


async def test_stripped_secrets_force_disables_restored_wlans(
    fresh_state: StubState, fresh_server: FastMCP
) -> None:
    """A backup with secrets_stripped restores WLANs as enabled=False.

    We force-disable any WLAN the restore creates whose passphrase still
    equals the sentinel, so a known-string SSID is never broadcast.
    """
    # Snapshot first.
    envelope = await _call(fresh_server, "backup_config", {})
    assert envelope["secrets_stripped"] is True
    backup_json = json.dumps(envelope)

    # Delete the seed WLAN so restore has to recreate it.
    seed_wlan_id = fresh_state.wlans[0]["_id"]
    fresh_state.delete_wlan(seed_wlan_id)
    assert fresh_state.wlans == []

    result = await _restore_applying(fresh_server, backup_json)
    assert "error" not in result
    # The warning must name networks as well as WLANs. 0.20.0 extended the
    # force-disable to networks (a restored VPN comes back disabled because
    # its PSK is not in the envelope) while this text still spoke only of
    # WLAN passphrases, so an operator restoring a site-to-site tunnel was
    # told nothing about the thing that had actually just been turned off.
    warning = next(w for w in result["warnings"] if "disabled" in w.lower())
    assert "wlan" in warning.lower()
    assert "network" in warning.lower()
    assert "secret" in warning.lower()
    # The recreated WLAN must be disabled.
    assert len(fresh_state.wlans) == 1
    assert fresh_state.wlans[0]["enabled"] is False


# ---------------------------------------------------------------------------
# Partial failure rollback
# ---------------------------------------------------------------------------


async def test_partial_failure_rolls_back_creates(
    fresh_state: StubState, fresh_server: FastMCP
) -> None:
    """Inject a failure mid-plan; tracked creates must be undone."""
    envelope = await _call(fresh_server, "backup_config", {})
    backup_json = json.dumps(envelope)

    # Delete several seed records so restore plan has multiple creates.
    fresh_state.delete_wlan(fresh_state.wlans[0]["_id"])
    fresh_state.delete_firewall_rule(fresh_state.firewall_rules[0]["_id"])
    fresh_state.delete_dhcp_lease(fresh_state.dhcp_leases[0]["_id"])

    pre = _resource_snapshot(fresh_state)

    # Fail the firewall_rule create — the plan should already have created
    # the wlan and dhcp lease before that step (CREATE_ORDER is networks ->
    # port_profiles -> dhcp_leases -> wlans -> port_forwards -> firewall_rules).
    fresh_state.fail_next("create_firewall_rule", UniFiError("injected at create_firewall_rule"))

    result = await _restore_applying(fresh_server, backup_json)
    assert "error" in result
    assert "rolled_back" in result
    # Every successful create must have been deleted by the rollback.
    post = _resource_snapshot(fresh_state)
    # The snapshot must match pre on resource counts (rollback restored the
    # state we entered the call with).
    for rtype, items in pre.items():
        assert len(post[rtype]) == len(items), (
            f"{rtype}: pre had {len(items)}, post has {len(post[rtype])}; rollback incomplete"
        )


# ---------------------------------------------------------------------------
# Hypothesis property test
# ---------------------------------------------------------------------------

# Mutation operations the test will randomly apply between backup and restore.
# Each operation either adds an extra resource the backup doesn't know about
# (which restore should delete) or deletes a resource (which restore should
# recreate). The post-restore state must equal the pre-mutation state.
#
# The first version of this test could not fail on the paths that matter. Its
# only deletes hit records nothing points at, and it never deleted a network,
# so a recreated WLAN's network id was still live whether or not restore
# remapped it; and it popped ``enabled`` off every WLAN, so dropping the
# force-disable passed too. Reverting either, or skipping every network,
# port profile and lease create, left it green. It now seeds a network that a
# WLAN, a lease, a port profile and a rule point at (the rule through a
# firewall group as well), deletes those, compares references by the NAME of
# what they point at, and holds every recreated WLAN to ``enabled: False``.

_mutation_kinds = st.sampled_from(
    [
        "add_network",
        "add_firewall_rule",
        "add_port_forward",
        "add_dhcp_lease",
        "add_wlan",
        "add_port_profile",
        "delete_seed_wlan",
        "delete_seed_firewall_rule",
        "delete_seed_port_forward",
        "delete_bound_network",
        "delete_bound_group",
        "delete_bound_profile",
    ]
)

_vlan_ids = st.integers(min_value=2, max_value=4094)
_safe_names = st.text(
    alphabet=st.characters(min_codepoint=0x41, max_codepoint=0x7A, blacklist_categories=("Cs",)),
    min_size=2,
    max_size=10,
).filter(lambda s: s.strip() and "/" not in s and '"' not in s)

#: Every reference field the seeded records carry, and what each points at.
_REF_FIELDS: dict[str, str] = {
    "networkconf_id": "net",
    "network_id": "net",
    "native_networkconf_id": "net",
    "tagged_networkconf_ids": "net",
    "src_networkconf_id": "net",
    "dst_networkconf_id": "net",
    "src_firewallgroup_ids": "group",
    "dst_firewallgroup_ids": "group",
}


def _seed_bound(state: StubState) -> None:
    """Add a network and a group that other records point at by id."""
    net = state.create_network(
        {
            "name": "Bound",
            "purpose": "corporate",
            "vlan_enabled": True,
            "vlan": 60,
            "ip_subnet": "10.60.0.0/24",
            "enabled": True,
        }
    )
    group = state.create_firewall_group(
        {"name": "Bound-Hosts", "group_type": "address-group", "group_members": ["10.60.0.10"]}
    )
    default_id = state.networks[0]["_id"]
    state.create_wlan(
        {
            "name": "Bound-SSID",
            "enabled": True,
            "security": "wpapsk",
            "wpa_mode": "wpa2",
            "x_passphrase": "boundpassphrase",
            "networkconf_id": net["_id"],
        }
    )
    state.create_dhcp_lease(
        {
            "mac": "aa:bb:cc:60:00:01",
            "name": "Bound-Lease",
            "fixed_ip": "10.60.0.10",
            "network_id": net["_id"],
        }
    )
    state.create_port_profile(
        {
            "name": "Bound-Trunk",
            "forward": "customize",
            "native_networkconf_id": net["_id"],
            "tagged_networkconf_ids": [default_id, net["_id"]],
        }
    )
    state.create_firewall_rule(
        {
            "name": "Bound-Rule",
            "ruleset": "LAN_IN",
            "rule_index": 4000,
            "action": "drop",
            "src_networkconf_id": net["_id"],
            "dst_firewallgroup_ids": [group["_id"]],
        }
    )


def _points_at(record: dict[str, Any], kind: str, target_id: str) -> bool:
    for key, ref_kind in _REF_FIELDS.items():
        if ref_kind != kind:
            continue
        value = record.get(key)
        if value == target_id or (isinstance(value, list) and target_id in value):
            return True
    return False


def _delete_pointing_at(state: StubState, kind: str, target_id: str) -> None:
    """Delete every record that points at ``target_id`` (a real controller
    refuses to delete a network or group something still references)."""
    for wlan in [w for w in state.wlans if _points_at(w, kind, target_id)]:
        state.delete_wlan(wlan["_id"])
    for lease in [x for x in state.list_dhcp_leases() if _points_at(x, kind, target_id)]:
        state.delete_dhcp_lease(lease["_id"])
    for profile in [p for p in state.port_profiles if _points_at(p, kind, target_id)]:
        state.delete_port_profile(profile["_id"])
    for rule in [r for r in state.firewall_rules if _points_at(r, kind, target_id)]:
        state.delete_firewall_rule(rule["_id"])


def _apply_mutation(state: StubState, kind: str, name: str, vlan_id: int) -> None:
    """Apply a single mutation. Best-effort — unknown kinds are no-ops."""
    if kind == "add_network":
        state.create_network(
            {
                "name": f"Extra-{name}-{vlan_id}",
                "purpose": "corporate",
                "vlan_enabled": True,
                "vlan": vlan_id,
                "ip_subnet": f"10.{vlan_id % 256}.0.0/24",
                "enabled": True,
            }
        )
    elif kind == "add_firewall_rule":
        state.create_firewall_rule(
            {
                "name": f"Extra-FW-{name}",
                "ruleset": "LAN_IN",
                "rule_index": 5000 + vlan_id,
                "action": "drop",
                "enabled": True,
            }
        )
    elif kind == "add_port_forward":
        state.create_port_forward(
            {
                "name": f"Extra-PF-{name}",
                "fwd": "192.168.1.99",
                "fwd_port": str(8000 + (vlan_id % 1000)),
                "dst_port": str(8000 + (vlan_id % 1000)),
                "proto": "tcp",
                "src": "any",
                "enabled": True,
            }
        )
    elif kind == "add_dhcp_lease":
        mac = f"aa:bb:cc:99:{vlan_id // 256:02x}:{vlan_id % 256:02x}"
        if state.find_user_by_mac(mac) is not None:
            # The stub now refuses a duplicate MAC the way the controller
            # does (api.err.MacUsed); a generated collision is a no-op
            # mutation, not a failure of the property under test.
            return
        state.create_dhcp_lease(
            {
                "mac": mac,
                "name": f"Extra-Lease-{name}",
                "fixed_ip": f"192.168.1.{(vlan_id % 200) + 50}",
                "network_id": state.networks[0]["_id"],
            }
        )
    elif kind == "add_wlan":
        state.create_wlan(
            {
                "name": f"Extra-SSID-{name}",
                "enabled": True,
                "security": "wpapsk",
                "x_passphrase": "extrapassphrase",
                "networkconf_id": state.networks[0]["_id"],
            }
        )
    elif kind == "add_port_profile":
        state.create_port_profile(
            {"name": f"Extra-Profile-{name}", "native_networkconf_id": state.networks[0]["_id"]}
        )
    elif kind == "delete_seed_wlan" and state.wlans:
        state.delete_wlan(state.wlans[0]["_id"])
    elif kind == "delete_seed_firewall_rule" and state.firewall_rules:
        state.delete_firewall_rule(state.firewall_rules[0]["_id"])
    elif kind == "delete_seed_port_forward" and state.port_forwards:
        state.delete_port_forward(state.port_forwards[0]["_id"])
    elif kind == "delete_bound_network":
        net = next((n for n in state.networks if n.get("name") == "Bound"), None)
        if net is not None:
            _delete_pointing_at(state, "net", net["_id"])
            state.delete_network(net["_id"])
    elif kind == "delete_bound_group":
        group = next((g for g in state.firewall_groups if g.get("name") == "Bound-Hosts"), None)
        if group is not None:
            _delete_pointing_at(state, "group", group["_id"])
            state.delete_firewall_group(group["_id"])
    elif kind == "delete_bound_profile":
        profile = next((p for p in state.port_profiles if p.get("name") == "Bound-Trunk"), None)
        if profile is not None:
            state.delete_port_profile(profile["_id"])


def _referential_view(state: StubState) -> dict[str, list[str]]:
    """Every record, ids dropped, references replaced by the target's name.

    A network or group recreated by restore has a new ``_id``, so ids cannot
    be compared across the restore; what must hold is that each reference
    still points at the record of the same name. A reference to an id that
    no longer exists renders as ``<dangling ...>`` and cannot match. Records
    are compared as sorted JSON so a recreated record landing at the end of
    its list is not a difference.
    """
    names = {
        "net": {n["_id"]: n.get("name") for n in state.networks},
        "group": {g["_id"]: g.get("name") for g in state.firewall_groups},
    }

    def _name(kind: str, ref: Any) -> Any:
        if ref in ("", None):
            return ref
        target = names[kind].get(ref)
        return f"{kind}:{target}" if target is not None else f"<dangling {kind} {ref}>"

    snap = _resource_snapshot(state)
    snap["firewall_groups"] = copy.deepcopy(state.firewall_groups)
    out: dict[str, list[str]] = {}
    for rtype, items in snap.items():
        rendered: list[str] = []
        for item in items:
            rec = {k: v for k, v in item.items() if k not in {"_id", "site_id"}}
            for key, kind in _REF_FIELDS.items():
                if key in rec:
                    value = rec[key]
                    rec[key] = (
                        [_name(kind, v) for v in value]
                        if isinstance(value, list)
                        else _name(kind, value)
                    )
            # Restore cannot bring a secret back: the backup holds a sentinel.
            rec.pop("x_passphrase", None)
            rendered.append(json.dumps(rec, sort_keys=True))
        out[rtype] = sorted(rendered)
    return out


@given(
    mutations=st.lists(
        st.tuples(_mutation_kinds, _safe_names, _vlan_ids),
        min_size=0,
        max_size=4,
    ),
)
async def test_property_restore_converges_to_backup(
    stub_settings: Settings,
    mutations: list[tuple[str, str, int]],
) -> None:
    """Random mutations between backup and restore must converge.

    For every randomly-generated mutation sequence, the resource state
    AFTER ``restore_config`` must equal the state BEFORE the mutations,
    compared by :func:`_referential_view` (ids dropped, references followed
    to the name of their target). Every WLAN the restore recreated must come
    back disabled, since its passphrase is the backup sentinel. Hypothesis
    shrinks any counterexample to the smallest failing mutation list.
    """
    state = StubState()
    _seed_bound(state)
    server = build_server(stub_settings, stub=state)

    # Baseline: snapshot AND backup the seeded state.
    pre_view = _referential_view(state)
    envelope = await _call(server, "backup_config", {})
    backup_json = json.dumps(envelope)

    # Apply random mutations on top.
    for kind, name, vlan_id in mutations:
        _apply_mutation(state, kind, name, vlan_id)
    wlan_ids_before_restore = {w["_id"] for w in state.wlans}

    # Restore (real apply).
    result = await _restore_applying(server, backup_json)
    assert "error" not in result, f"restore failed: {result}"

    recreated = [w for w in state.wlans if w["_id"] not in wlan_ids_before_restore]
    for wlan in recreated:
        assert wlan["enabled"] is False, f"recreated WLAN {wlan['name']!r} came back enabled"
        # Normalise only the flag the restore was required to change.
        wlan["enabled"] = True

    post_view = _referential_view(state)
    assert post_view == pre_view, (
        f"restore did not converge.\nmutations: {mutations}\npre:  {pre_view}\npost: {post_view}"
    )


# ---------------------------------------------------------------------------
# Envelope secret handling
#
# The backup envelope is a tool response: it is returned to the caller in full
# and lands in the transcript. It carries network records, and the sentinel
# pass used to match the literal key ``x_passphrase`` — so every VPN pre-shared
# key on the controller went out in cleartext alongside the redacted WLANs.
# ---------------------------------------------------------------------------

NETWORK_SECRETS = {
    "x_ipsec_pre_shared_key": "ipsec-psk-do-not-leak",
    "x_preshared_key": "wireguard-psk-do-not-leak",
    "x_private_key": "wireguard-private-do-not-leak",
    "x_secret": "radius-secret-do-not-leak",
}


async def test_backup_strips_network_vpn_secrets(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    stub_state.create_network(
        {
            "name": "Site-to-Site",
            "purpose": "site-vpn",
            "vpn_type": "ipsec-vpn",
            "radiusprofile_id": "6501aaaabbbbccccdddd0001",
            **NETWORK_SECRETS,
        }
    )

    envelope = await _call(stub_server, "backup_config", {})

    vpn = next(n for n in envelope["resources"]["networks"] if n["name"] == "Site-to-Site")
    for key in NETWORK_SECRETS:
        assert vpn[key] == REDACTED_OUTPUT, f"{key} leaked into the backup envelope"
    assert "do-not-leak" not in json.dumps(envelope)
    assert envelope["secrets_stripped"] is True
    # The RADIUS profile reference is not a secret; restore needs it.
    assert vpn["radiusprofile_id"] == "6501aaaabbbbccccdddd0001"


async def test_restore_disables_networks_carrying_the_sentinel(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """A VPN network whose PSK is a published constant must not come up enabled."""
    envelope = {
        "schema": "1",
        "controller": "default",
        "ts": "2026-08-12T00:00:00+00:00",
        "secrets_stripped": True,
        "resources": {
            "networks": [
                {
                    "_id": "6501aaaabbbbccccdddd9999",
                    "name": "Restored-VPN",
                    "purpose": "site-vpn",
                    "vpn_type": "ipsec-vpn",
                    "x_ipsec_pre_shared_key": REDACTED_PASSPHRASE,
                    "enabled": True,
                }
            ],
            "wlans": [],
            "firewall_rules": [],
            "port_profiles": [],
            "dhcp_leases": [],
            "port_forwards": [],
        },
    }

    await _restore_applying(stub_server, json.dumps(envelope))

    restored = next(n for n in stub_state.list_networks() if n["name"] == "Restored-VPN")
    assert restored["enabled"] is False, (
        "restored a VPN network on a sentinel pre-shared key with the tunnel enabled"
    )


def _vpn_envelope(secret_value: object) -> dict[str, Any]:
    return {
        "schema": "1",
        "controller": "default",
        "ts": "2026-08-12T00:00:00+00:00",
        "secrets_stripped": True,
        "resources": {
            "networks": [
                {
                    "_id": "6501aaaabbbbccccdddd9999",
                    "name": "Restored-VPN",
                    "purpose": "site-vpn",
                    "vpn_type": "ipsec-vpn",
                    "x_ipsec_pre_shared_key": secret_value,
                    "enabled": True,
                }
            ],
            "wlans": [],
            "firewall_rules": [],
            "port_profiles": [],
            "dhcp_leases": [],
            "port_forwards": [],
        },
    }


async def test_restore_disables_networks_carrying_the_output_sentinel(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """``[REDACTED]`` is the spelling a caller actually sees in a
    ``backup_config`` result, now that the response serialiser redacts every
    tool response. Restore must treat it exactly like the backup sentinel, or
    a VPN tunnel would come up with the literal string as its key.
    """
    await _restore_applying(stub_server, json.dumps(_vpn_envelope(REDACTED_OUTPUT)))

    restored = next(n for n in stub_state.list_networks() if n["name"] == "Restored-VPN")
    assert restored["enabled"] is False


async def test_restore_disables_networks_with_a_nested_sentinel(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """The serialiser redacts at every depth while the backup pass is
    top-level only, so a sentinel can sit inside a nested structure."""
    envelope = _vpn_envelope("not-a-sentinel")
    envelope["resources"]["networks"][0]["wireguard_peers"] = [
        {"public_key": "pub", "x_preshared_key": REDACTED_OUTPUT}
    ]

    await _restore_applying(stub_server, json.dumps(envelope))

    restored = next(n for n in stub_state.list_networks() if n["name"] == "Restored-VPN")
    assert restored["enabled"] is False


async def test_backup_output_restores_with_secret_bearing_wlans_disabled(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """End to end through the real tool output: take a backup, lose a WLAN,
    paste the backup back. The recreated WLAN carries a redacted passphrase
    and must come back disabled rather than broadcasting ``[REDACTED]``."""
    envelope = await _call(stub_server, "backup_config", {})
    victim = stub_state.list_wlans()[0]
    stub_state.delete_wlan(victim["_id"])
    assert all(w["name"] != victim["name"] for w in stub_state.list_wlans())

    await _restore_applying(stub_server, json.dumps(envelope))

    recreated = next(w for w in stub_state.list_wlans() if w["name"] == victim["name"])
    assert recreated["enabled"] is False


@pytest.mark.asyncio
async def test_restore_config_requires_confirmation(
    fresh_state: StubState, fresh_server: FastMCP
) -> None:
    """restore_config must not mutate on the first call.

    It is the most destructive tool in this server: it deletes across
    firewall_rules, port_forwards, wlans, dhcp_leases, port_profiles and networks
    before creating anything, and its own docstring says deletes already run are
    NOT undone on rollback. It was nonetheless outside the preview-then-confirm
    registry that guards the eleven delete_* tools.
    """
    envelope = await _call(fresh_server, "backup_config", {})
    backup_json = json.dumps(envelope)

    fresh_state.create_network(
        {"name": "ShouldSurvivePreview", "purpose": "corporate", "enabled": True}
    )
    before = {n["name"] for n in fresh_state.list_networks()}

    preview = await _call(fresh_server, "restore_config", {"backup_json": backup_json})
    assert preview["preview"] is True
    assert preview["confirm_with"] == "confirm_destructive_action"
    assert len(preview["token"]) == 36

    after_preview = {n["name"] for n in fresh_state.list_networks()}
    assert after_preview == before, "preview must not mutate controller state"

    await _call(fresh_server, "confirm_destructive_action", {"token": preview["token"]})
    after_confirm = {n["name"] for n in fresh_state.list_networks()}
    assert "ShouldSurvivePreview" not in after_confirm, "confirm should apply the plan"


@pytest.mark.asyncio
async def test_restore_config_token_is_single_use(
    fresh_state: StubState, fresh_server: FastMCP
) -> None:
    envelope = await _call(fresh_server, "backup_config", {})
    preview = await _call(fresh_server, "restore_config", {"backup_json": json.dumps(envelope)})
    await _call(fresh_server, "confirm_destructive_action", {"token": preview["token"]})
    second = await _call(fresh_server, "confirm_destructive_action", {"token": preview["token"]})
    assert "error" in second


async def test_restore_recreates_a_lease_whose_user_record_survived(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """Clearing a reservation keeps the user record with the flag off, and a
    plain create for that MAC would answer ``api.err.MacUsed`` on a real
    controller. Restore upserts, so the reservation comes back on the same
    record and the user list does not grow (issue #124, items 3 and 7)."""
    envelope = await _call(stub_server, "backup_config", {})
    victim = stub_state.list_dhcp_leases()[0]
    stub_state.delete_dhcp_lease(victim["_id"])
    assert all(lease["_id"] != victim["_id"] for lease in stub_state.list_dhcp_leases())
    raw_before = len(stub_state.dhcp_leases)

    await _restore_applying(stub_server, json.dumps(envelope))

    restored = next(u for u in stub_state.dhcp_leases if u["mac"] == victim["mac"])
    assert restored["use_fixedip"] is True
    assert restored["_id"] == victim["_id"], "restore must reuse the surviving record"
    assert len(stub_state.dhcp_leases) == raw_before


# ---------------------------------------------------------------------------
# References to recreated networks and groups (C3)
#
# Restore recreates a lost network with a new id. It used to remap only a
# WLAN's networkconf_id and a lease's network_id, so a restored firewall rule
# or port profile kept the source network's id: a rule matching nothing and a
# profile pointing at no VLAN, both reported as restored.
# ---------------------------------------------------------------------------


def _empty_resources() -> dict[str, list[dict[str, Any]]]:
    return {
        "networks": [],
        "firewall_groups": [],
        "wlans": [],
        "firewall_rules": [],
        "port_profiles": [],
        "dhcp_leases": [],
        "port_forwards": [],
    }


def _envelope(resources: dict[str, list[dict[str, Any]]], **extra: Any) -> str:
    return json.dumps(
        {
            "schema": "1",
            "controller": "default",
            "ts": "2026-11-10T00:00:00+00:00",
            "secrets_stripped": False,
            "resources": resources,
            **extra,
        }
    )


async def test_restore_remaps_rule_and_profile_refs_to_recreated_network(
    fresh_state: StubState, fresh_server: FastMCP
) -> None:
    iot = fresh_state.create_network(
        {"name": "IoT", "purpose": "corporate", "vlan_enabled": True, "vlan": 50}
    )
    default_id = fresh_state.networks[0]["_id"]
    fresh_state.create_firewall_rule(
        {
            "name": "Block IoT to LAN",
            "ruleset": "LAN_IN",
            "action": "drop",
            "src_networkconf_id": iot["_id"],
            "dst_networkconf_id": default_id,
        }
    )
    fresh_state.create_port_profile(
        {
            "name": "IoT-Trunk",
            "native_networkconf_id": iot["_id"],
            "tagged_networkconf_ids": [default_id, iot["_id"]],
        }
    )
    backup_json = json.dumps(await _call(fresh_server, "backup_config", {}))

    # The operator loses the network; on a real controller the rule and the
    # profile have to go first.
    fresh_state.firewall_rules = [
        r for r in fresh_state.firewall_rules if r["name"] != "Block IoT to LAN"
    ]
    fresh_state.port_profiles = [p for p in fresh_state.port_profiles if p["name"] != "IoT-Trunk"]
    fresh_state.delete_network(iot["_id"])

    result = await _restore_applying(fresh_server, backup_json)
    assert "error" not in result, result

    new_iot = next(n for n in fresh_state.networks if n["name"] == "IoT")
    assert new_iot["_id"] != iot["_id"]
    rule = next(r for r in fresh_state.firewall_rules if r["name"] == "Block IoT to LAN")
    assert rule["src_networkconf_id"] == new_iot["_id"]
    assert rule["dst_networkconf_id"] == default_id
    profile = next(p for p in fresh_state.port_profiles if p["name"] == "IoT-Trunk")
    assert profile["native_networkconf_id"] == new_iot["_id"]
    assert profile["tagged_networkconf_ids"] == [default_id, new_iot["_id"]]


async def test_restore_remaps_rule_group_refs_to_recreated_group(
    fresh_state: StubState, fresh_server: FastMCP
) -> None:
    group = fresh_state.create_firewall_group(
        {"name": "Cameras", "group_type": "address-group", "group_members": ["10.0.50.10"]}
    )
    fresh_state.create_firewall_rule(
        {
            "name": "Block Cameras Out",
            "ruleset": "LAN_IN",
            "action": "drop",
            "src_firewallgroup_ids": [group["_id"]],
        }
    )
    envelope = await _call(fresh_server, "backup_config", {})
    assert any(g["name"] == "Cameras" for g in envelope["resources"]["firewall_groups"])

    fresh_state.firewall_rules = [
        r for r in fresh_state.firewall_rules if r["name"] != "Block Cameras Out"
    ]
    fresh_state.delete_firewall_group(group["_id"])

    result = await _restore_applying(fresh_server, json.dumps(envelope))
    assert "error" not in result, result

    new_group = next(g for g in fresh_state.firewall_groups if g["name"] == "Cameras")
    assert new_group["_id"] != group["_id"]
    assert new_group["group_members"] == ["10.0.50.10"]
    rule = next(r for r in fresh_state.firewall_rules if r["name"] == "Block Cameras Out")
    assert rule["src_firewallgroup_ids"] == [new_group["_id"]]


async def test_restore_blocks_a_rule_whose_network_ref_cannot_resolve(
    fresh_state: StubState, fresh_server: FastMCP
) -> None:
    """A reference to a network the backup does not hold is refused in the plan."""
    resources = _empty_resources()
    resources["networks"] = [
        {"_id": n["_id"], **{k: v for k, v in n.items() if k not in ("_id", "site_id")}}
        for n in fresh_state.networks
    ]
    resources["firewall_rules"] = [
        {
            "name": "Dangling",
            "ruleset": "LAN_IN",
            "action": "drop",
            "src_networkconf_id": "6501aaaabbbbccccdddd0042",
        }
    ]
    backup_json = _envelope(resources)

    dry = await _call(fresh_server, "restore_config", {"backup_json": backup_json, "dry_run": True})
    blocked = [a for a in dry["would_apply"] if a["action"] == "blocked"]
    assert len(blocked) == 1
    assert blocked[0]["type"] == "firewall_rules"
    assert blocked[0]["name"] == "Dangling"
    assert blocked[0]["unresolved"] == [
        {
            "field": "src_networkconf_id",
            "id": "6501aaaabbbbccccdddd0042",
            "reason": "no record in the backup's networks carries this _id",
        }
    ]
    assert not [a for a in dry["would_apply"] if a["action"] == "create"]
    assert dry["summary"].endswith("1 blocked")
    assert any("blocked" in w and "Dangling" in w for w in dry["warnings"])

    # Confirming the rest of the plan never writes the blocked rule.
    result = await _restore_applying(fresh_server, backup_json)
    assert "error" not in result, result
    assert not any(r.get("name") == "Dangling" for r in fresh_state.firewall_rules)


async def test_restore_blocks_a_wlan_bound_to_a_network_the_backup_lacks(
    fresh_state: StubState, fresh_server: FastMCP
) -> None:
    """The WLAN path used to pass an unresolvable networkconf_id through as is."""
    resources = _empty_resources()
    resources["networks"] = [
        {"_id": n["_id"], **{k: v for k, v in n.items() if k not in ("_id", "site_id")}}
        for n in fresh_state.networks
    ]
    resources["wlans"] = [
        dict(fresh_state.wlans[0], name="Orphan-SSID", networkconf_id="6501aaaabbbbccccdddd0043")
    ]
    resources["wlans"][0].pop("_id")
    dry = await _call(
        fresh_server, "restore_config", {"backup_json": _envelope(resources), "dry_run": True}
    )
    blocked = [a for a in dry["would_apply"] if a["action"] == "blocked"]
    assert [(a["type"], a["name"]) for a in blocked] == [("wlans", "Orphan-SSID")]


async def test_restore_refuses_when_a_matched_network_is_gone_at_confirm(
    fresh_state: StubState, fresh_server: FastMCP
) -> None:
    """References are resolved at preview; a network replaced before confirm
    would leave them dangling, so the confirm applies nothing."""
    iot = fresh_state.create_network({"name": "IoT", "purpose": "corporate", "vlan": 50})
    fresh_state.create_port_profile({"name": "IoT-Access", "native_networkconf_id": iot["_id"]})
    backup_json = json.dumps(await _call(fresh_server, "backup_config", {}))
    fresh_state.port_profiles = [p for p in fresh_state.port_profiles if p["name"] != "IoT-Access"]

    preview = await _call(fresh_server, "restore_config", {"backup_json": backup_json})
    assert preview["preview"] is True

    # Someone deletes and recreates IoT between the preview and the confirm.
    fresh_state.delete_network(iot["_id"])
    fresh_state.create_network({"name": "IoT", "purpose": "corporate", "vlan": 50})
    before = _resource_snapshot(fresh_state)

    result = await _call(fresh_server, "confirm_destructive_action", {"token": preview["token"]})
    assert "error" in result
    assert "changed since the preview" in result["error"]
    assert _resource_snapshot(fresh_state) == before


async def test_restore_never_deletes_an_extra_firewall_group(
    fresh_state: StubState, fresh_server: FastMCP
) -> None:
    backup_json = json.dumps(await _call(fresh_server, "backup_config", {}))
    fresh_state.create_firewall_group(
        {"name": "Used-By-A-Zone-Policy", "group_type": "port-group", "group_members": ["22"]}
    )

    dry = await _call(fresh_server, "restore_config", {"backup_json": backup_json, "dry_run": True})
    group_actions = [a for a in dry["would_apply"] if a["type"] == "firewall_groups"]
    assert [a["action"] for a in group_actions] == ["skip"]
    assert "never deleted" in group_actions[0]["reason"]

    await _restore_applying(fresh_server, backup_json)
    assert any(g["name"] == "Used-By-A-Zone-Policy" for g in fresh_state.firewall_groups)


# ---------------------------------------------------------------------------
# Duplicate identities (C6)
# ---------------------------------------------------------------------------


async def test_restore_reports_duplicate_names_and_picks_none(
    fresh_state: StubState, fresh_server: FastMCP
) -> None:
    """Two rules share a name; one is lost. Restore used to see the name on the
    site, restore nothing, and say nothing."""
    for idx, dst in ((20001, "10.0.0.0/8"), (20002, "172.16.0.0/12")):
        fresh_state.create_firewall_rule(
            {
                "name": "Block RFC1918",
                "ruleset": "LAN_IN",
                "action": "drop",
                "rule_index": idx,
                "dst_address": dst,
            }
        )
    backup_json = json.dumps(await _call(fresh_server, "backup_config", {}))
    fresh_state.firewall_rules = [
        r for r in fresh_state.firewall_rules if r.get("dst_address") != "172.16.0.0/12"
    ]

    dry = await _call(fresh_server, "restore_config", {"backup_json": backup_json, "dry_run": True})
    blocked = [a for a in dry["would_apply"] if a["action"] == "blocked"]
    assert len(blocked) == 1
    assert blocked[0]["type"] == "firewall_rules"
    assert blocked[0]["name"] == "Block RFC1918"
    assert "2 in the backup, 1 on the site" in blocked[0]["reason"]
    assert any("Block RFC1918" in w for w in dry["warnings"])

    before = copy.deepcopy(fresh_state.firewall_rules)
    await _restore_applying(fresh_server, backup_json)
    assert fresh_state.firewall_rules == before


async def test_restore_reports_a_duplicate_that_appeared_on_the_site(
    fresh_state: StubState, fresh_server: FastMCP
) -> None:
    backup_json = json.dumps(await _call(fresh_server, "backup_config", {}))
    seed_rule = fresh_state.firewall_rules[0]
    fresh_state.create_firewall_rule({**seed_rule, "_id": "dup-rule", "action": "accept"})

    dry = await _call(fresh_server, "restore_config", {"backup_json": backup_json, "dry_run": True})
    blocked = [a for a in dry["would_apply"] if a["action"] == "blocked"]
    assert [a["name"] for a in blocked] == [seed_rule["name"]]
    assert "1 in the backup, 2 on the site" in blocked[0]["reason"]
    assert not [a for a in dry["would_apply"] if a["action"] == "delete"]


async def test_restore_deletes_every_extra_sharing_a_name_the_backup_lacks(
    fresh_state: StubState, fresh_server: FastMCP
) -> None:
    """No ambiguity when the backup holds none: all of them are extras."""
    backup_json = json.dumps(await _call(fresh_server, "backup_config", {}))
    for idx in (1, 2):
        fresh_state.create_firewall_rule(
            {"name": "Extra", "ruleset": "LAN_IN", "action": "drop", "rule_index": 6000 + idx}
        )
    dry = await _call(fresh_server, "restore_config", {"backup_json": backup_json, "dry_run": True})
    deletes = [a for a in dry["would_apply"] if a["action"] == "delete"]
    assert [a["name"] for a in deletes] == ["Extra", "Extra"]
    assert not [a for a in dry["would_apply"] if a["action"] == "blocked"]


# ---------------------------------------------------------------------------
# What a backup does not contain (C8)
# ---------------------------------------------------------------------------


async def test_backup_states_what_it_does_not_contain(stub_server: FastMCP) -> None:
    envelope = await _call(stub_server, "backup_config", {})
    assert envelope["not_included"] == NOT_INCLUDED
    assert "firewall_policies" in envelope["not_included"]
    assert "firewall_zones" in envelope["not_included"]


async def test_restore_plan_repeats_what_it_does_not_restore(
    fresh_state: StubState, fresh_server: FastMCP
) -> None:
    backup_json = json.dumps(await _call(fresh_server, "backup_config", {}))
    dry = await _call(fresh_server, "restore_config", {"backup_json": backup_json, "dry_run": True})
    assert dry["not_restored"] == NOT_INCLUDED
    assert any("Zone-Based Firewall policies" in w for w in dry["warnings"])

    preview = await _call(fresh_server, "restore_config", {"backup_json": backup_json})
    assert preview["resource"]["not_restored"] == NOT_INCLUDED
    assert preview["resource"]["blocked"] == 0


async def test_restore_of_a_backup_without_groups_leaves_groups_and_blocks_their_rules(
    fresh_state: StubState, fresh_server: FastMCP
) -> None:
    """A backup taken before groups were included has no firewall_groups key."""
    group_id = fresh_state.firewall_groups[0]["_id"]
    envelope = await _call(fresh_server, "backup_config", {})
    del envelope["resources"]["firewall_groups"]
    envelope["resources"]["firewall_rules"].append(
        {
            "name": "Uses-Group",
            "ruleset": "LAN_IN",
            "action": "drop",
            "dst_firewallgroup_ids": [group_id],
        }
    )
    groups_before = copy.deepcopy(fresh_state.firewall_groups)

    dry = await _call(
        fresh_server, "restore_config", {"backup_json": json.dumps(envelope), "dry_run": True}
    )
    assert any("no firewall_groups section" in w for w in dry["warnings"])
    assert [a["name"] for a in dry["would_apply"] if a["action"] == "blocked"] == ["Uses-Group"]
    assert not [a for a in dry["would_apply"] if a["type"] == "firewall_groups"]

    await _restore_applying(fresh_server, json.dumps(envelope))
    assert fresh_state.firewall_groups == groups_before


# ---------------------------------------------------------------------------
# Sentinel check does not trust the flag (C9)
# ---------------------------------------------------------------------------


async def test_restore_disables_a_sentinel_wlan_when_the_flag_says_false(
    fresh_state: StubState, fresh_server: FastMCP
) -> None:
    """A hand-trimmed or rebuilt envelope can say secrets_stripped: false while
    still carrying the placeholder. The flag used to gate the check, so the
    WLAN went to the controller enabled with ``[REDACTED]`` as its passphrase."""
    sent: list[dict[str, Any]] = []
    original = fresh_state.create_wlan

    def _spy(payload: dict[str, Any]) -> dict[str, Any]:
        sent.append(dict(payload))
        return original(payload)

    fresh_state.create_wlan = _spy  # type: ignore[method-assign]
    envelope = await _call(fresh_server, "backup_config", {})
    envelope["secrets_stripped"] = False
    victim = fresh_state.wlans[0]
    fresh_state.delete_wlan(victim["_id"])

    dry = await _call(
        fresh_server, "restore_config", {"backup_json": json.dumps(envelope), "dry_run": True}
    )
    assert any("secrets_stripped is false" in w for w in dry["warnings"])
    assert any("force-disabled" in w for w in dry["warnings"])

    await _restore_applying(fresh_server, json.dumps(envelope))
    assert len(sent) == 1
    assert sent[0]["x_passphrase"] == REDACTED_OUTPUT
    assert sent[0]["enabled"] is False
