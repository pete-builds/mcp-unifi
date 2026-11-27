"""Network references in either form: ``_id`` or ``legacy_id`` (issue #219).

On UniFi Network 11 a network's ``_id`` is a UUID and its old 24-hex
ObjectId is kept as ``legacy_id``. Reservations made before the migration
still store that legacy id as their ``network_id``: 5 of 6 on the
maintainer's gateway (Network 11.0.99, probed 2026-11-27), and the issue
#219 reporter saw the same on a UDM-SE (Network 11.1.47). Everything that
resolves a lease's, client's or honeypot's network must accept either form,
and a write must never rewrite a binding that already names the right
network.

The same issue reported that ``update_static_dhcp_lease``'s real call
answered ``{}`` while its dry run answered a summary, so a caller could not
tell whether a write was sent. The real call now answers the dry run's shape
plus what was applied.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import FastMCP

from mcp_unifi.clients.stubs import StubState
from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.config import Settings
from mcp_unifi.modules.network import _common, composites
from mcp_unifi.server import build_server
from tests.network.conftest import BASE, _call

# ---------------------------------------------------------------------------
# The resolver
# ---------------------------------------------------------------------------

NETS: list[dict[str, Any]] = [
    {
        "_id": "88a83e2a-5611-4d56-9a4e-4dc5d6cd2f43",
        "legacy_id": "6a0525dd18ec98252c8a08cc",
        "name": "Default",
    },
    {
        "_id": "7f574364-e98f-49de-8a6e-e89bde2e2bdf",
        "legacy_id": "6a124ca05d0b83f118f71276",
        "name": "TRUSTED",
    },
    {"_id": "net-without-legacy", "name": "Old"},
]


def test_find_network_by_id() -> None:
    assert _common.find_network(NETS, NETS[1]["_id"]) is NETS[1]


def test_find_network_by_legacy_id() -> None:
    assert _common.find_network(NETS, "6a124ca05d0b83f118f71276") is NETS[1]


def test_find_network_unknown_or_empty_is_none() -> None:
    assert _common.find_network(NETS, "6a124ca05d0b83f118f7127") is None  # a prefix
    assert _common.find_network(NETS, "") is None
    assert _common.find_network(NETS, None) is None


def test_find_network_refuses_a_reference_naming_two_networks() -> None:
    clash = [*NETS, {"_id": "other", "legacy_id": NETS[0]["_id"], "name": "Clash"}]
    with pytest.raises(_common.NetworkRefError, match="more than one network"):
        _common.find_network(clash, NETS[0]["_id"])


def test_find_network_same_record_listed_twice_is_not_ambiguous() -> None:
    assert _common.find_network([NETS[0], dict(NETS[0])], NETS[0]["legacy_id"]) == NETS[0]


def test_same_network_across_forms() -> None:
    assert _common.same_network(NETS, NETS[1]["legacy_id"], NETS[1]["_id"])
    assert _common.same_network(NETS, NETS[1]["_id"], NETS[1]["legacy_id"])
    assert not _common.same_network(NETS, NETS[0]["legacy_id"], NETS[1]["_id"])
    assert not _common.same_network(NETS, None, NETS[1]["_id"])
    assert not _common.same_network(NETS, "ghost", NETS[1]["_id"])
    # An unknown reference is still the same as itself.
    assert _common.same_network(NETS, "ghost", "ghost")


# ---------------------------------------------------------------------------
# Writes: create / update / provision
# ---------------------------------------------------------------------------


def _nas(state: StubState) -> dict[str, Any]:
    """The seeded NAS reservation, which stores Default's legacy_id."""
    return next(u for u in state.dhcp_leases if u["mac"] == "aa:bb:cc:00:00:03")


def _spy_updates(state: StubState) -> list[dict[str, Any]]:
    sent: list[dict[str, Any]] = []
    original = state.update_dhcp_lease

    def _spy(user_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        sent.append(dict(payload))
        return original(user_id, payload)

    state.update_dhcp_lease = _spy  # type: ignore[method-assign]
    return sent


@pytest.mark.parametrize("ref_key", ["_id", "legacy_id"])
async def test_update_with_an_unchanged_binding_sends_no_network_id(
    stub_server: FastMCP, stub_state: StubState, ref_key: str
) -> None:
    """The NAS points at Default by legacy id. Naming Default in either form
    is no change, so network_id is not sent and the stored form survives."""
    nas = _nas(stub_state)
    default = stub_state.networks[0]
    assert nas["network_id"] == default["legacy_id"]
    sent = _spy_updates(stub_state)

    result = await _call(
        stub_server,
        "update_static_dhcp_lease",
        {"mac": nas["mac"], "fixed_ip": "192.168.1.11", "network_id": default[ref_key]},
    )

    assert "error" not in result, result
    assert sent == [{"use_fixedip": True, "fixed_ip": "192.168.1.11"}]
    assert nas["network_id"] == default["legacy_id"]
    assert result["network_binding"]["network_id_sent"] is False

    dry = await _call(
        stub_server,
        "update_static_dhcp_lease",
        {
            "mac": nas["mac"],
            "fixed_ip": "192.168.1.12",
            "network_id": default[ref_key],
            "dry_run": True,
        },
    )
    assert "network_id" not in dry["would_update"]["patch"]


async def test_update_to_a_different_network_sends_its_id(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """Moving the NAS to another network, named by that network's legacy id,
    sends the network's _id."""
    lab = stub_state.create_network({"name": "Lab", "ip_subnet": "10.70.0.1/24"})
    sent = _spy_updates(stub_state)

    await _call(
        stub_server,
        "update_static_dhcp_lease",
        {"mac": "aa:bb:cc:00:00:03", "fixed_ip": "10.70.0.5", "network_id": lab["legacy_id"]},
    )

    assert sent[0]["network_id"] == lab["_id"]


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("create_static_dhcp_lease", {"mac": "11:22:33:44:55:77", "ip": "192.168.1.60"}),
        ("update_static_dhcp_lease", {"mac": "aa:bb:cc:00:00:03", "fixed_ip": "192.168.1.61"}),
        (
            "provision_homelab_service",
            {"name": "svc", "mac": "11:22:33:44:55:78", "ip": "192.168.1.62", "ports": [80]},
        ),
    ],
)
@pytest.mark.parametrize("dry_run", [False, True])
async def test_a_write_naming_an_unknown_network_is_refused(
    stub_server: FastMCP, stub_state: StubState, tool: str, args: dict[str, Any], dry_run: bool
) -> None:
    leases_before = json.dumps(stub_state.dhcp_leases, sort_keys=True, default=str)
    rules_before = len(stub_state.firewall_rules)

    result = await _call(
        stub_server, tool, {**args, "network_id": "6a0525dd18ec98252c8affff", "dry_run": dry_run}
    )

    assert "not found" in result["error"], result
    assert "nothing was" in result["error"]
    assert json.dumps(stub_state.dhcp_leases, sort_keys=True, default=str) == leases_before
    assert len(stub_state.firewall_rules) == rules_before


async def test_a_write_naming_two_networks_is_refused(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    clash = stub_state.create_network({"name": "Clash"})
    clash["legacy_id"] = stub_state.networks[0]["_id"]

    result = await _call(
        stub_server,
        "create_static_dhcp_lease",
        {"mac": "11:22:33:44:55:79", "ip": "192.168.1.63", "network_id": clash["legacy_id"]},
    )

    assert "more than one network" in result["error"]
    assert not any(u["mac"] == "11:22:33:44:55:79" for u in stub_state.dhcp_leases)


async def test_create_sends_the_network_id_for_a_legacy_reference(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    default = stub_state.networks[0]
    result = await _call(
        stub_server,
        "create_static_dhcp_lease",
        {"mac": "11:22:33:44:55:80", "ip": "192.168.1.64", "network_id": default["legacy_id"]},
    )
    assert result["network_id"] == default["_id"]


@pytest.mark.parametrize("ref_key", ["_id", "legacy_id"])
async def test_provision_rollback_on_a_legacy_bound_lease_leaves_network_id_alone(
    stub_server: FastMCP, stub_state: StubState, ref_key: str
) -> None:
    """The NAS stores Default's legacy id. Provisioning it on Default (named
    either way) must not send network_id, and the rollback must not count it
    as a field to put back."""
    nas = _nas(stub_state)
    before = dict(nas)
    sent = _spy_updates(stub_state)
    stub_state.fail_next("create_firewall_rule", UniFiError("injected"))

    result = await _call(
        stub_server,
        "provision_homelab_service",
        {
            "name": "plex",
            "mac": nas["mac"],
            "ip": "192.168.1.50",
            "network_id": stub_state.networks[0][ref_key],
            "ports": [32400],
        },
    )

    assert "firewall_rule" in result["error"]
    assert all("network_id" not in payload for payload in sent), sent
    lease_action = next(a for a in result["rolled_back"] if "dhcp_lease" in a)
    assert lease_action["restored_fields"] == ["fixed_ip", "name"]
    assert nas == before


async def test_provision_dry_run_omits_an_unchanged_binding(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    dry = await _call(
        stub_server,
        "provision_homelab_service",
        {
            "name": "plex",
            "mac": "aa:bb:cc:00:00:03",
            "ip": "192.168.1.50",
            "network_id": stub_state.networks[0]["_id"],
            "dry_run": True,
        },
    )
    assert "network_id" not in dry["would_create"]["lease"]


@pytest.mark.parametrize("ref_key", ["_id", "legacy_id"])
async def test_provision_of_a_new_mac_sends_the_network_id(
    stub_server: FastMCP, stub_state: StubState, ref_key: str
) -> None:
    """A MAC the controller has never seen has no binding to keep, so the
    lease is written, and it carries the network's ``_id`` whichever form the
    caller named the network by."""
    default = stub_state.networks[0]
    sent: list[dict[str, Any]] = []
    original = stub_state.create_dhcp_lease

    def _spy(payload: dict[str, Any]) -> dict[str, Any]:
        sent.append(dict(payload))
        return original(payload)

    stub_state.create_dhcp_lease = _spy  # type: ignore[method-assign]

    result = await _call(
        stub_server,
        "provision_homelab_service",
        {
            "name": "newbox",
            "mac": "11:22:33:44:55:90",
            "ip": "192.168.1.70",
            "network_id": default[ref_key],
        },
    )

    assert "error" not in result, result
    assert [p["network_id"] for p in sent] == [default["_id"]]
    assert result["lease"]["network_id"] == default["_id"]


async def test_provision_by_legacy_id_puts_the_policy_in_the_networks_zone(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """On a zone-based site the ALLOW policy's destination zone comes from
    the service's network. Named by its legacy id, the network must still be
    found, or the policy silently lands in the fallback Internal zone."""
    guest = stub_state.create_network(
        {"name": "Guests", "purpose": "guest", "vlan": 60, "ip_subnet": "10.60.0.1/24"}
    )
    stub_state.zone_firewall.migrate()
    zones = dict(stub_state.zone_firewall.zone_ids)

    result = await _call(
        stub_server,
        "provision_homelab_service",
        {
            "name": "kiosk",
            "mac": "11:22:33:44:55:91",
            "ip": "10.60.0.20",
            "network_id": guest["legacy_id"],
            "ports": [8080],
        },
    )

    assert "error" not in result, result
    policy = result["firewall_policy"]
    assert policy["destination"]["zoneId"] == zones["Hotspot"]
    assert policy["destination"]["zoneId"] != zones["Internal"]
    assert "not found" not in policy["description"]


class _RecordingBackend:
    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    async def update_dhcp_lease(self, user_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        self.sent.append(payload)
        return {"_id": user_id, **payload}


async def test_restore_lease_treats_legacy_and_uuid_of_one_network_as_equal() -> None:
    """Defense in depth: even if a payload carries the UUID for a record that
    stores the legacy id of the same network, rollback does not 'restore' it."""
    backend = _RecordingBackend()
    prior = {"_id": "u1", "fixed_ip": "10.0.0.1", "network_id": NETS[1]["legacy_id"]}
    payload = {"fixed_ip": "10.0.0.2", "network_id": NETS[1]["_id"]}

    action = await composites._restore_lease(backend, "u1", prior, payload, NETS)  # type: ignore[arg-type]

    assert action["restored_fields"] == ["fixed_ip"]
    assert backend.sent == [{"fixed_ip": "10.0.0.1"}]

    moved = {"fixed_ip": "10.0.0.2", "network_id": NETS[0]["_id"]}
    action = await composites._restore_lease(backend, "u1", prior, moved, NETS)  # type: ignore[arg-type]
    assert action["restored_fields"] == ["fixed_ip", "network_id"]


# ---------------------------------------------------------------------------
# Backup and restore
# ---------------------------------------------------------------------------


def _with_lab_and_legacy_lease() -> StubState:
    state = StubState()
    lab = state.create_network(
        {
            "name": "Lab",
            "purpose": "corporate",
            "vlan_enabled": True,
            "vlan": 70,
            "ip_subnet": "10.70.0.1/24",
            "external_id": "b35d590a-ce10-4ead-9b49-7493c76580cb",
        }
    )
    state.create_dhcp_lease(
        {
            "mac": "aa:bb:cc:70:00:01",
            "name": "Lab-Pi",
            "fixed_ip": "10.70.0.10",
            "network_id": lab["legacy_id"],
        }
    )
    return state


@pytest.mark.parametrize("lab_on_target", [False, True])
async def test_restore_remaps_a_legacy_bound_lease_onto_a_target_with_other_ids(
    stub_settings: Settings, lab_on_target: bool
) -> None:
    """Back up a site whose lease points at Lab by legacy id, restore it onto
    a site where Lab is missing (restore creates it) or exists with ids of
    its own. The lease must land pointing at the target's Lab ``_id``."""
    source = _with_lab_and_legacy_lease()
    source_lab = next(n for n in source.networks if n["name"] == "Lab")
    envelope = await _call(build_server(stub_settings, stub=source), "backup_config", {})

    target = StubState()
    if lab_on_target:
        target.create_network({"name": "Lab", "purpose": "corporate", "vlan": 70})
    server = build_server(stub_settings, stub=target)

    dry = await _call(
        server, "restore_config", {"backup_json": json.dumps(envelope), "dry_run": True}
    )
    assert not [a for a in dry["would_apply"] if a["action"] == "blocked"], dry["would_apply"]

    preview = await _call(server, "restore_config", {"backup_json": json.dumps(envelope)})
    result = await _call(server, "confirm_destructive_action", {"token": preview["token"]})
    assert "error" not in result, result

    target_lab = next(n for n in target.networks if n["name"] == "Lab")
    assert target_lab["_id"] != source_lab["_id"]
    lease = next(u for u in target.list_dhcp_leases() if u["mac"] == "aa:bb:cc:70:00:01")
    assert lease["network_id"] == target_lab["_id"]


async def test_restore_never_sends_legacy_or_external_id_in_a_create(
    stub_settings: Settings,
) -> None:
    """Both are controller-assigned. A create carrying the source's values
    would ask the controller to reuse another record's ids."""
    state = _with_lab_and_legacy_lease()
    server = build_server(stub_settings, stub=state)
    envelope = await _call(server, "backup_config", {})
    lab = next(n for n in state.networks if n["name"] == "Lab")
    lease = next(u for u in state.dhcp_leases if u["mac"] == "aa:bb:cc:70:00:01")
    state.dhcp_leases.remove(lease)
    state.delete_network(lab["_id"])

    sent: list[dict[str, Any]] = []
    original = state.create_network

    def _spy(payload: dict[str, Any]) -> dict[str, Any]:
        sent.append(dict(payload))
        return original(payload)

    state.create_network = _spy  # type: ignore[method-assign]
    preview = await _call(server, "restore_config", {"backup_json": json.dumps(envelope)})
    result = await _call(server, "confirm_destructive_action", {"token": preview["token"]})
    assert "error" not in result, result

    assert [p["name"] for p in sent] == ["Lab"]
    assert "legacy_id" not in sent[0]
    assert "external_id" not in sent[0]
    assert "_id" not in sent[0]
    new_lab = next(n for n in state.networks if n["name"] == "Lab")
    assert new_lab["legacy_id"] != lab["legacy_id"]
    restored = next(u for u in state.list_dhcp_leases() if u["mac"] == "aa:bb:cc:70:00:01")
    assert restored["network_id"] == new_lab["_id"]


# ---------------------------------------------------------------------------
# Honeypots
# ---------------------------------------------------------------------------


async def test_list_honeypots_names_a_network_stored_by_legacy_id(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    default = stub_state.networks[0]
    stub_state.settings["ips"]["honeypot"] = [
        {"network_id": default["legacy_id"], "ip_address": "192.168.1.50", "version": "v4"}
    ]
    result = await _call(stub_server, "list_honeypots")
    assert result["honeypots"][0]["network_name"] == default["name"]


async def test_create_honeypot_by_legacy_id_and_duplicates_across_forms(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    default = stub_state.networks[0]
    created = await _call(
        stub_server,
        "create_honeypot",
        {"network_id": default["legacy_id"], "ip": "192.168.1.50"},
    )
    assert "error" not in created, created
    assert created["network_name"] == default["name"]

    # The same network named by its _id is the same honeypot.
    dup = await _call(
        stub_server, "create_honeypot", {"network_id": default["_id"], "ip": "192.168.1.50"}
    )
    assert "already exists" in dup["error"]

    # The resolved network's subnet is what the address is checked against.
    outside = await _call(
        stub_server, "create_honeypot", {"network_id": default["legacy_id"], "ip": "10.9.9.9"}
    )
    assert "outside network" in outside["error"]


# ---------------------------------------------------------------------------
# What the real call returns (issue #219)
# ---------------------------------------------------------------------------


def _mock_networks() -> None:
    respx.get(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {"_id": "uuid-lan", "legacy_id": "6a0525dd18ec98252c8a0000", "name": "LAN"},
                ]
            },
        )
    )


@respx.mock
async def test_real_update_answers_what_was_sent_and_the_record_read_back(
    real_server: FastMCP,
) -> None:
    """The controller answers the PUT with an empty list, which the tool used
    to return as ``{}``. It now answers the dry run's shape plus the applied
    result: the fields sent and the record as read back after the write."""
    _mock_networks()
    before = {
        "_id": "u42",
        "mac": "d0:11:e5:03:f6:3a",
        "use_fixedip": True,
        "fixed_ip": "192.168.1.40",
        "network_id": "6a0525dd18ec98252c8a0000",
    }
    after = {**before, "fixed_ip": "192.168.1.50", "name": "cypher"}
    respx.get(f"{BASE}/list/user").mock(
        side_effect=[
            httpx.Response(200, json={"data": [before]}),
            httpx.Response(200, json={"data": [after]}),
        ]
    )
    put_route = respx.put(f"{BASE}/rest/user/u42").mock(
        return_value=httpx.Response(200, json={"data": []})
    )

    result = await _call(
        real_server,
        "update_static_dhcp_lease",
        {
            "mac": "d0:11:e5:03:f6:3a",
            "fixed_ip": "192.168.1.50",
            "network_id": "uuid-lan",
            "name": "cypher",
        },
    )

    sent = json.loads(put_route.calls.last.request.content)
    assert sent == {"use_fixedip": True, "fixed_ip": "192.168.1.50", "name": "cypher"}
    assert result["dry_run"] is False
    assert result["controller"] == "default"
    assert result["updated"] == {"mac": "d0:11:e5:03:f6:3a", "user_id": "u42", "patch": sent}
    assert result["sent_fields"] == ["fixed_ip", "name", "use_fixedip"]
    assert result["record"] == after
    assert result["summary"] == "Pinned 192.168.1.50 on d0:11:e5:03:f6:3a"
    assert result["network_binding"]["network_id_sent"] is False
    # Kept for callers that read the record's fields at the top level.
    assert result["_id"] == "u42"
    assert result["fixed_ip"] == "192.168.1.50"
    assert "read_back_error" not in result


@respx.mock
async def test_real_update_reports_a_failed_read_back_without_failing(
    real_server: FastMCP,
) -> None:
    respx.get(f"{BASE}/list/user").mock(
        side_effect=[
            httpx.Response(200, json={"data": [{"_id": "u42", "mac": "d0:11:e5:03:f6:3a"}]}),
            httpx.Response(400, json={"meta": {"rc": "error", "msg": "api.err.Invalid"}}),
        ]
    )
    respx.put(f"{BASE}/rest/user/u42").mock(return_value=httpx.Response(200, json={"data": []}))

    result = await _call(
        real_server,
        "update_static_dhcp_lease",
        {"mac": "d0:11:e5:03:f6:3a", "fixed_ip": "192.168.1.50"},
    )

    assert "error" not in result
    assert result["sent_fields"] == ["fixed_ip", "use_fixedip"]
    assert result["record"] is None
    assert "the write was sent" in result["read_back_error"]


@respx.mock
async def test_real_create_answers_what_was_sent_and_the_record_read_back(
    real_server: FastMCP,
) -> None:
    _mock_networks()
    created = {"_id": "u9", "mac": "aa:bb:cc:dd:ee:ff", "use_fixedip": True}
    stored = {**created, "fixed_ip": "192.168.1.42", "network_id": "uuid-lan"}
    respx.get(f"{BASE}/list/user").mock(return_value=httpx.Response(200, json={"data": [stored]}))
    respx.post(f"{BASE}/rest/user").mock(return_value=httpx.Response(200, json={"data": [created]}))

    result = await _call(
        real_server,
        "create_static_dhcp_lease",
        {
            "mac": "aa:bb:cc:dd:ee:ff",
            "ip": "192.168.1.42",
            "network_id": "6a0525dd18ec98252c8a0000",
        },
    )

    payload = {
        "mac": "aa:bb:cc:dd:ee:ff",
        "use_fixedip": True,
        "fixed_ip": "192.168.1.42",
        "network_id": "uuid-lan",
    }
    assert result["dry_run"] is False
    assert result["created"] == {"dhcp_lease": payload}
    assert result["sent_fields"] == sorted(payload)
    assert result["record"] == stored
    assert result["_id"] == "u9"
    assert result["summary"] == "Reserved 192.168.1.42 for aa:bb:cc:dd:ee:ff"


async def test_restore_description_says_the_uuid_lease_write_is_unverified(
    stub_server: FastMCP,
) -> None:
    listed = next(t for t in await stub_server.list_tools() if t.name == "restore_config")
    description = listed.description or ""
    assert "Args:" not in description
    assert "legacy_id" in description
    assert "has not been verified live" in description
    assert "same controller" in description


@pytest.mark.parametrize(
    ("tool", "change_key"),
    [("update_static_dhcp_lease", "updated"), ("create_static_dhcp_lease", "created")],
)
async def test_the_return_shape_is_in_the_tool_description(
    stub_server: FastMCP, tool: str, change_key: str
) -> None:
    """FastMCP sends only the prose above ``Args:`` as the description, so the
    return shape and the network-reference rules must be up there."""
    listed = next(t for t in await stub_server.list_tools() if t.name == tool)
    description = listed.description or ""
    assert "Args:" not in description
    for needle in (
        f'"{change_key}"',
        '"sent_fields"',
        '"record"',
        "re-read after the write",
        "read_back_error",
        "legacy_id",
        "not been verified live",
    ):
        assert needle in description, needle
