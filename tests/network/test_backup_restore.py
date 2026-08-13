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
    REDACTED_PASSPHRASE,
)
from mcp_unifi.server import build_server
from tests.network.conftest import _call

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
    """Deep copy every resource list ``backup_config`` cares about."""
    return {
        "networks": copy.deepcopy(state.networks),
        "wlans": copy.deepcopy(state.wlans),
        "firewall_rules": copy.deepcopy(state.firewall_rules),
        "port_profiles": copy.deepcopy(state.port_profiles),
        "dhcp_leases": copy.deepcopy(state.dhcp_leases),
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
        assert wlan.get("x_passphrase") == REDACTED_PASSPHRASE


async def test_backup_drops_internal_ids(stub_server: FastMCP) -> None:
    """``_id`` is dropped from everything except networks.

    Networks retain ``_id`` so wlan/lease references can be resolved back to
    a network name (and then a live id) at restore time. ``site_id`` is
    dropped everywhere because it doesn't survive a cross-controller restore.
    """
    envelope = await _call(stub_server, "backup_config", {})
    for rtype, items in envelope["resources"].items():
        for item in items:
            assert "site_id" not in item, f"{rtype} record leaked site_id into backup"
            if rtype == "networks":
                # Networks intentionally keep _id for restore-time rebinding.
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
    real = await _call(stub_server, "restore_config", {"backup_json": backup_json})
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

    result = await _call(fresh_server, "restore_config", {"backup_json": backup_json})
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

    result = await _call(fresh_server, "restore_config", {"backup_json": backup_json})
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

    result = await _call(fresh_server, "restore_config", {"backup_json": backup_json})
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

    result = await _call(fresh_server, "restore_config", {"backup_json": backup_json})
    assert "error" not in result
    assert any("passphrase" in w.lower() and "disabled" in w.lower() for w in result["warnings"])
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

    result = await _call(fresh_server, "restore_config", {"backup_json": backup_json})
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
# (which restore should delete) or deletes a seed resource (which restore
# should recreate). The post-restore state must equal the pre-mutation state.

_mutation_kinds = st.sampled_from(
    [
        "add_network",
        "add_firewall_rule",
        "add_port_forward",
        "add_dhcp_lease",
        "delete_seed_wlan",
        "delete_seed_firewall_rule",
        "delete_seed_port_forward",
    ]
)

_vlan_ids = st.integers(min_value=2, max_value=4094)
_safe_names = st.text(
    alphabet=st.characters(min_codepoint=0x41, max_codepoint=0x7A, blacklist_categories=("Cs",)),
    min_size=2,
    max_size=10,
).filter(lambda s: s.strip() and "/" not in s and '"' not in s)


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
        state.create_dhcp_lease(
            {
                "mac": f"aa:bb:cc:99:{vlan_id // 256:02x}:{vlan_id % 256:02x}",
                "name": f"Extra-Lease-{name}",
                "fixed_ip": f"192.168.1.{(vlan_id % 200) + 50}",
                "network_id": state.networks[0]["_id"],
            }
        )
    elif kind == "delete_seed_wlan" and state.wlans:
        state.delete_wlan(state.wlans[0]["_id"])
    elif kind == "delete_seed_firewall_rule" and state.firewall_rules:
        state.delete_firewall_rule(state.firewall_rules[0]["_id"])
    elif kind == "delete_seed_port_forward" and state.port_forwards:
        state.delete_port_forward(state.port_forwards[0]["_id"])


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
    AFTER ``restore_config`` must equal the state BEFORE the mutations
    (modulo controller-assigned ``_id`` strings, which we strip for
    comparison). Hypothesis shrinks any counterexample to the smallest
    failing mutation list.
    """
    state = StubState()
    server = build_server(stub_settings, stub=state)

    # Baseline: snapshot AND backup the freshly-seeded state.
    pre_view = _normalized_view(state)
    envelope = await _call(server, "backup_config", {})
    backup_json = json.dumps(envelope)

    # Apply random mutations on top.
    for kind, name, vlan_id in mutations:
        _apply_mutation(state, kind, name, vlan_id)

    # Restore (real apply).
    result = await _call(server, "restore_config", {"backup_json": backup_json})
    assert "error" not in result, f"restore failed: {result}"

    # Verify convergence.
    post_view = _normalized_view(state)

    # The seed WLAN's x_passphrase came back as the sentinel (because the
    # backup stripped it). Strip both sides for comparison so that secret
    # difference doesn't drown out genuine drift.
    def _strip_wlan_passphrases(
        view: dict[str, list[dict[str, Any]]],
    ) -> dict[str, list[dict[str, Any]]]:
        out = copy.deepcopy(view)
        for wlan in out["wlans"]:
            wlan.pop("x_passphrase", None)
            # Force-disabled flag also differs between the seed (enabled)
            # and a sentinel-restored WLAN; normalise it out of the
            # comparison because we already cover the disable-on-restore
            # path explicitly above.
            wlan.pop("enabled", None)
        return out

    assert _strip_wlan_passphrases(post_view) == _strip_wlan_passphrases(pre_view), (
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
        assert vpn[key] == REDACTED_PASSPHRASE, f"{key} leaked into the backup envelope"
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

    await _call(
        stub_server,
        "restore_config",
        {"backup_json": json.dumps(envelope)},
    )

    restored = next(n for n in stub_state.list_networks() if n["name"] == "Restored-VPN")
    assert restored["enabled"] is False, (
        "restored a VPN network on a sentinel pre-shared key with the tunnel enabled"
    )
