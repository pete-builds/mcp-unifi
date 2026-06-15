"""Tests for the IPv6 tools: get_wan_ipv6, set_wan_ipv6, set_lan_ipv6.

Shape, dry-run before/after, validation, and the WAN/LAN guard rails, plus a
real-mode test proving the read-modify-write PUT carries only the IPv6 keys.

The split-module fixtures (``stub_server``, ``real_server``) and helpers
(``BASE``, ``_call``) come from ``tests/network/conftest.py``.
"""

from __future__ import annotations

import httpx
import respx
from fastmcp import FastMCP

from mcp_unifi.clients.stubs import StubState
from tests.network.conftest import BASE, _call


def _lan_id(state: StubState) -> str:
    lan = next(n for n in state.networks if n.get("purpose") == "corporate")
    return str(lan["_id"])


def _wan_id(state: StubState) -> str:
    wan = next(n for n in state.networks if n.get("purpose") == "wan")
    return str(wan["_id"])


# ---------------------------------------------------------------------------
# get_wan_ipv6 (read-only)
# ---------------------------------------------------------------------------


async def test_get_wan_ipv6_returns_keys(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_wan_ipv6")
    assert result["controller"] == "default"
    wans = result["wan_ipv6"]
    assert len(wans) == 1
    wan = wans[0]
    assert wan["name"] == "Internet 1"
    # The stub WAN mirrors the live UCG-Fiber: DHCPv6 with prefix delegation on.
    assert wan["wan_type_v6"] == "dhcpv6"
    assert wan["ipv6_wan_delegation_type"] == "pd"
    assert "_id" in wan


async def test_get_wan_ipv6_filter_by_name(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_wan_ipv6", {"wan_name": "Internet 1"})
    assert len(result["wan_ipv6"]) == 1


async def test_get_wan_ipv6_unknown_name_errors(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_wan_ipv6", {"wan_name": "Nope"})
    assert "error" in result


# ---------------------------------------------------------------------------
# set_wan_ipv6 (mutating)
# ---------------------------------------------------------------------------


async def test_set_wan_ipv6_dry_run_diff(stub_server: FastMCP, stub_state: StubState) -> None:
    before = [dict(n) for n in stub_state.networks]
    result = await _call(
        stub_server,
        "set_wan_ipv6",
        {
            "connection_type": "dhcpv6",
            "prefix_delegation": "prefix-delegation",
            "pd_size": 56,
            "dry_run": True,
        },
    )
    assert result["dry_run"] is True
    upd = result["would_update"]
    assert upd["action"] == "set_wan_ipv6"
    # Stub WAN starts DHCPv6+PD (mirrors the live gateway); the dry-run shows the
    # would-be after-state with a consistent PD-size pair.
    assert upd["before"]["wan_type_v6"] == "dhcpv6"
    assert upd["after"]["wan_type_v6"] == "dhcpv6"
    # The "prefix-delegation" alias normalises to the controller's wire value "pd".
    assert upd["after"]["ipv6_wan_delegation_type"] == "pd"
    assert upd["after"]["wan_dhcpv6_pd_size"] == 56
    assert upd["after"]["wan_dhcpv6_pd_size_auto"] is False
    assert "blast_radius" in result
    # Nothing mutated.
    assert [dict(n) for n in stub_state.networks] == before


async def test_set_wan_ipv6_applies(stub_server: FastMCP, stub_state: StubState) -> None:
    result = await _call(
        stub_server,
        "set_wan_ipv6",
        {"connection_type": "dhcpv6"},
    )
    assert result["updated"] is True
    assert result["after"]["wan_type_v6"] == "dhcpv6"
    # State actually changed.
    wan = next(n for n in stub_state.networks if n.get("purpose") == "wan")
    assert wan["wan_type_v6"] == "dhcpv6"


async def test_set_wan_ipv6_requires_a_field(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "set_wan_ipv6", {})
    assert "error" in result
    assert "at least one" in result["error"]


async def test_set_wan_ipv6_rejects_bad_type(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "set_wan_ipv6", {"connection_type": "ipv6plus"})
    assert "error" in result


async def test_set_wan_ipv6_rejects_bad_pd_size(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "set_wan_ipv6", {"pd_size": 32})
    assert "error" in result


async def test_set_wan_ipv6_alias_normalises_to_pd(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """The friendly ``"prefix-delegation"`` alias must hit the wire value ``"pd"``.

    Regression: UniFi Network 10.4.57 rejects ``ipv6_wan_delegation_type:
    "prefix-delegation"`` with ``api.err.InvalidValue``; the only accepted value
    is ``"pd"``.
    """
    result = await _call(
        stub_server,
        "set_wan_ipv6",
        {"connection_type": "dhcpv6", "prefix_delegation": "prefix-delegation"},
    )
    assert result["updated"] is True
    wan = next(n for n in stub_state.networks if n.get("purpose") == "wan")
    assert wan["ipv6_wan_delegation_type"] == "pd"


async def test_set_wan_ipv6_accepts_pd_wire_value(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """Passing the raw wire value ``"pd"`` works too."""
    result = await _call(
        stub_server,
        "set_wan_ipv6",
        {"connection_type": "dhcpv6", "prefix_delegation": "pd"},
    )
    assert result["updated"] is True
    wan = next(n for n in stub_state.networks if n.get("purpose") == "wan")
    assert wan["ipv6_wan_delegation_type"] == "pd"


async def test_set_wan_ipv6_enable_pd_without_size_pins_auto_true(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """Enabling delegation with no explicit ``pd_size`` must emit a consistent
    auto/size pair: ``wan_dhcpv6_pd_size_auto=True`` (controller auto-sizes).

    Regression for the ``api.err.InvalidValue`` 400: the live WAN record carries
    ``wan_dhcpv6_pd_size_auto: false`` with NO ``wan_dhcpv6_pd_size`` key. Turning
    delegation on without normalising that pair produces an internally
    inconsistent record the controller rejects.
    """
    result = await _call(
        stub_server,
        "set_wan_ipv6",
        {"connection_type": "dhcpv6", "prefix_delegation": "prefix-delegation"},
    )
    assert result["updated"] is True
    wan = next(n for n in stub_state.networks if n.get("purpose") == "wan")
    assert wan["wan_dhcpv6_pd_size_auto"] is True
    # No explicit size is sent when auto-sizing.
    assert "wan_dhcpv6_pd_size" not in wan


async def test_set_wan_ipv6_enable_pd_with_size_pins_auto_false(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """An explicit ``pd_size`` pins ``wan_dhcpv6_pd_size_auto=False`` + that size,
    a self-consistent pair the controller accepts."""
    result = await _call(
        stub_server,
        "set_wan_ipv6",
        {"connection_type": "dhcpv6", "prefix_delegation": "prefix-delegation", "pd_size": 56},
    )
    assert result["updated"] is True
    wan = next(n for n in stub_state.networks if n.get("purpose") == "wan")
    assert wan["wan_dhcpv6_pd_size_auto"] is False
    assert wan["wan_dhcpv6_pd_size"] == 56


@respx.mock
async def test_real_set_wan_ipv6_enable_pd_puts_consistent_payload(
    real_server: FastMCP,
) -> None:
    """The live PUT body the controller accepts: delegation wire value ``"pd"``
    plus a consistent ``wan_dhcpv6_pd_size_auto``/``wan_dhcpv6_pd_size`` pair.

    This pins the exact payload shape that fixed the ``api.err.InvalidValue``
    400. The starting record reproduces the live inconsistency
    (``wan_dhcpv6_pd_size_auto: False`` with no size key).
    """
    import json as _json

    respx.get(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "_id": "wan1",
                        "name": "Internet 1",
                        "purpose": "wan",
                        "wan_type_v6": "disabled",
                        "ipv6_wan_delegation_type": "none",
                        "wan_dhcpv6_pd_size_auto": False,
                    }
                ]
            },
        )
    )
    put_route = respx.put(f"{BASE}/rest/networkconf/wan1").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "_id": "wan1",
                        "wan_type_v6": "dhcpv6",
                        "ipv6_wan_delegation_type": "pd",
                        "wan_dhcpv6_pd_size_auto": False,
                        "wan_dhcpv6_pd_size": 56,
                    }
                ]
            },
        )
    )
    result = await _call(
        real_server,
        "set_wan_ipv6",
        {"connection_type": "dhcpv6", "prefix_delegation": "prefix-delegation", "pd_size": 56},
    )
    assert result["updated"] is True
    assert put_route.called
    body = _json.loads(put_route.calls[0].request.content)
    # Exact payload the live controller accepts (probed 2026-06-14):
    assert body == {
        "wan_type_v6": "dhcpv6",
        "ipv6_wan_delegation_type": "pd",
        "wan_dhcpv6_pd_size": 56,
        "wan_dhcpv6_pd_size_auto": False,
    }


# ---------------------------------------------------------------------------
# set_lan_ipv6 (mutating)
# ---------------------------------------------------------------------------


async def test_set_lan_ipv6_dry_run_diff(stub_server: FastMCP, stub_state: StubState) -> None:
    lan_id = _lan_id(stub_state)
    before = [dict(n) for n in stub_state.networks]
    result = await _call(
        stub_server,
        "set_lan_ipv6",
        {"network_id": lan_id, "interface_type": "pd", "ra_enabled": True, "dry_run": True},
    )
    assert result["dry_run"] is True
    upd = result["would_update"]
    assert upd["action"] == "set_lan_ipv6"
    assert upd["before"]["ipv6_interface_type"] == "none"
    assert upd["after"]["ipv6_interface_type"] == "pd"
    assert upd["after"]["ipv6_ra_enabled"] is True
    assert [dict(n) for n in stub_state.networks] == before


async def test_set_lan_ipv6_applies(stub_server: FastMCP, stub_state: StubState) -> None:
    lan_id = _lan_id(stub_state)
    result = await _call(
        stub_server,
        "set_lan_ipv6",
        {"network_id": lan_id, "interface_type": "pd", "address_assignment": "dhcpv6"},
    )
    assert result["updated"] is True
    assert result["after"]["ipv6_interface_type"] == "pd"
    # PD enable auto-binds to the DHCPv6-PD WAN (mandatory or the controller 400s).
    assert result["after"]["ipv6_pd_interface"] == "wan"
    lan = next(n for n in stub_state.networks if n.get("_id") == lan_id)
    assert lan["ipv6_pd_interface"] == "wan"


async def test_set_lan_ipv6_pd_fresh_lan_fills_complete_scaffold(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """Enabling PD on a fresh LAN (no pre-existing ipv6 PD fields) must emit a
    COMPLETE, non-null PD payload, not just ``ipv6_interface_type=pd``.

    Regression for HTTP 400 ``api.err.InvalidIpv6Addr`` / ``ipv6_pd_start: null``
    (probed live 2026-06-14): the stub LAN mirrors a fresh blank LAN — it has
    ``ipv6_interface_type=none`` and NO ``ipv6_pd_start``/``ipv6_pd_stop``,
    DHCPv6 lease window, or RA lifetimes. The fix fills the full scaffold from
    Default's working values so the controller accepts the record.
    """
    lan_id = _lan_id(stub_state)
    # Precondition: the stub LAN genuinely lacks the PD scaffold (a fresh LAN).
    lan_before = next(n for n in stub_state.networks if n.get("_id") == lan_id)
    assert "ipv6_pd_start" not in lan_before
    assert "ipv6_pd_stop" not in lan_before

    result = await _call(
        stub_server,
        "set_lan_ipv6",
        {"network_id": lan_id, "interface_type": "pd", "ra_enabled": True},
    )
    assert result["updated"] is True
    lan = next(n for n in stub_state.networks if n.get("_id") == lan_id)
    # The mandatory PD bits.
    assert lan["ipv6_interface_type"] == "pd"
    assert lan["ipv6_pd_interface"] == "wan"
    # The PD window the controller demanded — populated, non-null.
    assert lan["ipv6_pd_start"] == "::2"
    assert lan["ipv6_pd_stop"] == "::7d1"
    assert lan["ipv6_pd_start"] is not None
    # The complete supporting scaffold (DHCPv6 lease window + RA lifetimes).
    assert lan["dhcpdv6_start"] == "::2"
    assert lan["dhcpdv6_stop"] == "::7d1"
    assert lan["dhcpdv6_leasetime"] == 86400
    assert lan["ipv6_ra_priority"] == "high"
    assert lan["ipv6_ra_preferred_lifetime"] == 14400
    assert lan["ipv6_aliases"] == []


async def test_set_lan_ipv6_pd_flips_manual_preference_to_auto(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """A fresh LAN sits at ``ipv6_setting_preference=manual``; in that mode the
    controller will not auto-carve a sub-prefix, so the LAN never gets a global
    /64. Enabling PD must flip manual → auto (matching the working Default LAN).

    Verified live 2026-06-14: TRUSTED stayed at manual after the first apply and
    its ``ipv6_subnets`` stayed empty; Default runs ``auto`` and carries a /64.
    """
    lan_id = _lan_id(stub_state)
    lan = next(n for n in stub_state.networks if n.get("_id") == lan_id)
    lan["ipv6_setting_preference"] = "manual"

    result = await _call(
        stub_server,
        "set_lan_ipv6",
        {"network_id": lan_id, "interface_type": "pd"},
    )
    assert result["updated"] is True
    lan = next(n for n in stub_state.networks if n.get("_id") == lan_id)
    assert lan["ipv6_setting_preference"] == "auto"


async def test_set_lan_ipv6_pd_leaves_auto_preference_untouched(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """An already-``auto`` LAN keeps ``auto``; the flip only fires for manual."""
    lan_id = _lan_id(stub_state)
    lan = next(n for n in stub_state.networks if n.get("_id") == lan_id)
    lan["ipv6_setting_preference"] = "auto"
    result = await _call(
        stub_server,
        "set_lan_ipv6",
        {"network_id": lan_id, "interface_type": "pd"},
    )
    assert result["updated"] is True
    lan = next(n for n in stub_state.networks if n.get("_id") == lan_id)
    assert lan["ipv6_setting_preference"] == "auto"


async def test_set_lan_ipv6_pd_preserves_existing_pd_window(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """An already-configured PD LAN keeps its OWN window — the scaffold defaults
    only fill MISSING keys, never clobber a live value (strict read-modify-write).
    """
    lan_id = _lan_id(stub_state)
    lan = next(n for n in stub_state.networks if n.get("_id") == lan_id)
    # Simulate a LAN that already carries a custom PD window.
    lan["ipv6_pd_start"] = "::a"
    lan["ipv6_pd_stop"] = "::ff"
    lan["ipv6_ra_priority"] = "medium"

    result = await _call(
        stub_server,
        "set_lan_ipv6",
        {"network_id": lan_id, "interface_type": "pd"},
    )
    assert result["updated"] is True
    lan = next(n for n in stub_state.networks if n.get("_id") == lan_id)
    # Existing values preserved, not overwritten by the scaffold defaults.
    assert lan["ipv6_pd_start"] == "::a"
    assert lan["ipv6_pd_stop"] == "::ff"
    assert lan["ipv6_ra_priority"] == "medium"
    # Still-missing scaffold keys get filled.
    assert lan["dhcpdv6_start"] == "::2"


async def test_set_lan_ipv6_pd_dry_run_shows_binding(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """Dry-run of a PD enable must surface the WAN binding in the after-state."""
    lan_id = _lan_id(stub_state)
    result = await _call(
        stub_server,
        "set_lan_ipv6",
        {"network_id": lan_id, "interface_type": "pd", "prefix_id": 0, "dry_run": True},
    )
    upd = result["would_update"]
    assert upd["after"]["ipv6_interface_type"] == "pd"
    assert upd["after"]["ipv6_pd_interface"] == "wan"
    assert upd["after"]["ipv6_pd_prefixid"] == 0
    # Pinning a prefix_id pins manual mode (so the controller honours the id).
    assert upd["after"]["ipv6_setting_preference"] == "manual"


async def test_set_lan_ipv6_prefix_id_requires_pd(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """``prefix_id`` is only meaningful when enabling PD; reject it otherwise."""
    lan_id = _lan_id(stub_state)
    result = await _call(
        stub_server,
        "set_lan_ipv6",
        {"network_id": lan_id, "ra_enabled": True, "prefix_id": 1},
    )
    assert "error" in result
    assert "prefix_id" in result["error"]


async def test_set_lan_ipv6_prefix_id_writes_prefixid_and_manual(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """Supplying ``prefix_id`` on a PD enable must write ``ipv6_pd_prefixid``
    AND pin ``ipv6_setting_preference=manual``, and both must round-trip on a
    re-read of the networkconf.

    Regression for the live-firmware bug (probed 2026-06-14, fixed v0.15.4): a
    second PD LAN in ``auto`` mode never carves its own /64 because the
    controller only hands the primary slice (id 0) to one LAN. Pinning a
    distinct sub-prefix id only takes effect in manual mode, so the tool must
    set both fields together — and the strict read-modify-write / scaffold-fill
    must not strip either.
    """
    lan_id = _lan_id(stub_state)
    # Start the LAN in auto PD mode (as TRUSTED was live before the fix).
    lan = next(n for n in stub_state.networks if n.get("_id") == lan_id)
    lan["ipv6_setting_preference"] = "auto"

    result = await _call(
        stub_server,
        "set_lan_ipv6",
        {
            "network_id": lan_id,
            "interface_type": "pd",
            "ra_enabled": True,
            "address_assignment": "slaac",
            "prefix_id": 1,
        },
    )
    assert result["updated"] is True
    # The applied after-view exposes both fields.
    assert result["after"]["ipv6_pd_prefixid"] == 1
    assert result["after"]["ipv6_setting_preference"] == "manual"

    # Round-trip: a fresh read of the persisted record carries both fields.
    lan = next(n for n in stub_state.networks if n.get("_id") == lan_id)
    assert lan["ipv6_pd_prefixid"] == 1
    assert lan["ipv6_setting_preference"] == "manual"
    assert lan["ipv6_interface_type"] == "pd"
    assert lan["ipv6_pd_interface"] == "wan"


async def test_set_lan_ipv6_prefix_id_zero_is_distinct_from_unset(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """``prefix_id=0`` is a real, distinct sub-prefix id (NOT the unset
    sentinel ``-1``): it must write ``ipv6_pd_prefixid=0`` and pin manual mode,
    not fall through to the legacy auto path."""
    lan_id = _lan_id(stub_state)
    result = await _call(
        stub_server,
        "set_lan_ipv6",
        {"network_id": lan_id, "interface_type": "pd", "prefix_id": 0},
    )
    assert result["updated"] is True
    lan = next(n for n in stub_state.networks if n.get("_id") == lan_id)
    assert lan["ipv6_pd_prefixid"] == 0
    assert lan["ipv6_setting_preference"] == "manual"


async def test_set_lan_ipv6_no_prefix_id_keeps_auto_carve(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """Omitting ``prefix_id`` (default sentinel) leaves the legacy auto behaviour
    intact: no ``ipv6_pd_prefixid`` is written and a manual/blank LAN flips to
    ``auto`` (back-compat for the primary MGMT/Default LAN)."""
    lan_id = _lan_id(stub_state)
    lan = next(n for n in stub_state.networks if n.get("_id") == lan_id)
    lan["ipv6_setting_preference"] = "manual"

    result = await _call(
        stub_server,
        "set_lan_ipv6",
        {"network_id": lan_id, "interface_type": "pd"},
    )
    assert result["updated"] is True
    lan = next(n for n in stub_state.networks if n.get("_id") == lan_id)
    assert "ipv6_pd_prefixid" not in lan
    assert lan["ipv6_setting_preference"] == "auto"


async def test_set_lan_ipv6_explicit_dns(stub_server: FastMCP, stub_state: StubState) -> None:
    lan_id = _lan_id(stub_state)
    result = await _call(
        stub_server,
        "set_lan_ipv6",
        {"network_id": lan_id, "dns_auto": False, "dns_servers": ["2606:4700:4700::1111"]},
    )
    assert result["updated"] is True
    lan = next(n for n in stub_state.networks if n.get("_id") == lan_id)
    assert lan["dhcpdv6_dns_auto"] is False
    assert lan["dhcpdv6_dns_1"] == "2606:4700:4700::1111"
    # Unused slots blanked so a shorter list clears stale servers.
    assert lan["dhcpdv6_dns_2"] == ""


async def test_set_lan_ipv6_rejects_wan_target(stub_server: FastMCP, stub_state: StubState) -> None:
    wan_id = _wan_id(stub_state)
    result = await _call(
        stub_server, "set_lan_ipv6", {"network_id": wan_id, "interface_type": "pd"}
    )
    assert "error" in result
    assert "set_wan_ipv6" in result["error"]


async def test_set_lan_ipv6_unknown_network(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server, "set_lan_ipv6", {"network_id": "nope", "interface_type": "pd"}
    )
    assert "error" in result
    assert "not found" in result["error"]


async def test_set_lan_ipv6_requires_a_field(stub_server: FastMCP, stub_state: StubState) -> None:
    lan_id = _lan_id(stub_state)
    result = await _call(stub_server, "set_lan_ipv6", {"network_id": lan_id})
    assert "error" in result
    assert "at least one" in result["error"]


async def test_set_lan_ipv6_rejects_bad_interface_type(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    lan_id = _lan_id(stub_state)
    result = await _call(
        stub_server, "set_lan_ipv6", {"network_id": lan_id, "interface_type": "magic"}
    )
    assert "error" in result


# ---------------------------------------------------------------------------
# Real-mode: prove read-modify-write PUTs only the IPv6 keys
# ---------------------------------------------------------------------------


@respx.mock
async def test_real_set_lan_ipv6_pd_puts_wan_binding(real_server: FastMCP) -> None:
    """Enabling PD on a LAN must emit the ``ipv6_pd_interface`` WAN binding.

    Regression for ``api.err.PdRequiresAssignedDhcpv6Wan`` (probed live
    2026-06-14): ``ipv6_interface_type=pd`` alone is rejected; the controller
    requires the LAN to reference the DHCPv6-PD WAN via ``ipv6_pd_interface``
    (the WAN's networkgroup, lowercased — ``"wan"``). The tool auto-resolves it
    from the PD-enabled WAN.
    """
    respx.get(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "_id": "lan1",
                        "name": "Default",
                        "purpose": "corporate",
                        "ip_subnet": "192.168.1.1/24",
                        "ipv6_interface_type": "none",
                        "ipv6_ra_enabled": False,
                    },
                    {
                        "_id": "wan1",
                        "name": "Internet 1",
                        "purpose": "wan",
                        "wan_networkgroup": "WAN",
                        "wan_type_v6": "dhcpv6",
                        "ipv6_wan_delegation_type": "pd",
                    },
                ]
            },
        )
    )
    put_route = respx.put(f"{BASE}/rest/networkconf/lan1").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "_id": "lan1",
                        "ipv6_interface_type": "pd",
                        "ipv6_pd_interface": "wan",
                        "ipv6_ra_enabled": True,
                    }
                ]
            },
        )
    )
    result = await _call(
        real_server,
        "set_lan_ipv6",
        {"network_id": "lan1", "interface_type": "pd", "ra_enabled": True},
    )
    assert result["updated"] is True
    assert put_route.called
    sent = put_route.calls[0].request
    import json as _json

    body = _json.loads(sent.content)
    # Strict read-modify-write: only IPv6 keys in the patch, no ip_subnet etc.
    # The PD path adds the mandatory WAN binding (auto-resolved from the WAN)
    # PLUS the complete PD scaffold a fresh LAN lacks (this mock record has none
    # of the PD-window / lease / RA-lifetime keys, so all defaults are filled).
    assert body == {
        "ipv6_interface_type": "pd",
        "ipv6_ra_enabled": True,
        "ipv6_pd_interface": "wan",
        "ipv6_setting_preference": "auto",
        "ipv6_pd_start": "::2",
        "ipv6_pd_stop": "::7d1",
        "dhcpdv6_start": "::2",
        "dhcpdv6_stop": "::7d1",
        "dhcpdv6_leasetime": 86400,
        "ipv6_ra_priority": "high",
        "ipv6_ra_preferred_lifetime": 14400,
        "ipv6_aliases": [],
    }


@respx.mock
async def test_real_set_lan_ipv6_pd_with_prefix_id(real_server: FastMCP) -> None:
    """An explicit ``prefix_id`` is forwarded as an integer ``ipv6_pd_prefixid``
    alongside the WAN binding AND pins ``ipv6_setting_preference="manual"`` (the
    only mode in which UniFi Network 10.4.57 honours a pinned sub-prefix, so a
    second PD LAN carves its OWN /64). Verified live 2026-06-14 (v0.15.4)."""
    respx.get(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "_id": "lan1",
                        "name": "TRUSTED",
                        "purpose": "corporate",
                        "ipv6_interface_type": "none",
                    },
                    {
                        "_id": "wan1",
                        "name": "Internet 1",
                        "purpose": "wan",
                        "wan_networkgroup": "WAN",
                        "wan_type_v6": "dhcpv6",
                        "ipv6_wan_delegation_type": "pd",
                    },
                ]
            },
        )
    )
    put_route = respx.put(f"{BASE}/rest/networkconf/lan1").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"_id": "lan1", "ipv6_interface_type": "pd"}]},
        )
    )
    result = await _call(
        real_server,
        "set_lan_ipv6",
        {"network_id": "lan1", "interface_type": "pd", "prefix_id": 1},
    )
    assert result["updated"] is True
    import json as _json

    body = _json.loads(put_route.calls[0].request.content)
    assert body == {
        "ipv6_interface_type": "pd",
        "ipv6_pd_interface": "wan",
        "ipv6_pd_prefixid": 1,
        "ipv6_setting_preference": "manual",
        "ipv6_pd_start": "::2",
        "ipv6_pd_stop": "::7d1",
        "dhcpdv6_start": "::2",
        "dhcpdv6_stop": "::7d1",
        "dhcpdv6_leasetime": 86400,
        "ipv6_ra_priority": "high",
        "ipv6_ra_preferred_lifetime": 14400,
        "ipv6_aliases": [],
    }


@respx.mock
async def test_real_set_lan_ipv6_pd_existing_window_not_clobbered(real_server: FastMCP) -> None:
    """A LAN that already carries a PD window (like the live Default LAN) keeps
    its own values; the scaffold only fills genuinely-missing keys.

    Mirrors the live Default record (``ipv6_pd_start=::2``/``ipv6_pd_stop=::7d1``
    already present): the PUT must NOT re-send those (read-modify-write would
    preserve them anyway), only the caller's change + the WAN binding + any
    still-missing scaffold key.
    """
    import json as _json

    respx.get(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "_id": "lan1",
                        "name": "Default",
                        "purpose": "corporate",
                        "ipv6_interface_type": "pd",
                        "ipv6_pd_interface": "wan",
                        "ipv6_setting_preference": "auto",
                        "ipv6_pd_start": "::2",
                        "ipv6_pd_stop": "::7d1",
                        "dhcpdv6_start": "::2",
                        "dhcpdv6_stop": "::7d1",
                        "dhcpdv6_leasetime": 86400,
                        "ipv6_ra_priority": "high",
                        "ipv6_ra_preferred_lifetime": 14400,
                        "ipv6_aliases": [],
                    },
                    {
                        "_id": "wan1",
                        "name": "Internet 1",
                        "purpose": "wan",
                        "wan_networkgroup": "WAN",
                        "wan_type_v6": "dhcpv6",
                        "ipv6_wan_delegation_type": "pd",
                    },
                ]
            },
        )
    )
    put_route = respx.put(f"{BASE}/rest/networkconf/lan1").mock(
        return_value=httpx.Response(
            200, json={"data": [{"_id": "lan1", "ipv6_interface_type": "pd"}]}
        )
    )
    result = await _call(
        real_server,
        "set_lan_ipv6",
        {"network_id": "lan1", "interface_type": "pd", "ra_enabled": True},
    )
    assert result["updated"] is True
    body = _json.loads(put_route.calls[0].request.content)
    # Only the caller's change + the WAN binding. No scaffold keys: every one
    # already exists on the record, so nothing is re-sent (and nothing clobbered).
    assert body == {
        "ipv6_interface_type": "pd",
        "ipv6_ra_enabled": True,
        "ipv6_pd_interface": "wan",
    }


@respx.mock
async def test_real_set_lan_ipv6_pd_no_wan_delegation_errors(real_server: FastMCP) -> None:
    """When no WAN has DHCPv6-PD enabled, enabling PD on a LAN returns a clear
    error instead of letting the controller reject it with a 400."""
    respx.get(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "_id": "lan1",
                        "name": "Default",
                        "purpose": "corporate",
                        "ipv6_interface_type": "none",
                    },
                    {
                        "_id": "wan1",
                        "name": "Internet 1",
                        "purpose": "wan",
                        "wan_networkgroup": "WAN",
                        "wan_type_v6": "disabled",
                        "ipv6_wan_delegation_type": "none",
                    },
                ]
            },
        )
    )
    put_route = respx.put(f"{BASE}/rest/networkconf/lan1").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    result = await _call(
        real_server,
        "set_lan_ipv6",
        {"network_id": "lan1", "interface_type": "pd"},
    )
    assert "error" in result
    assert "delegation" in result["error"].lower()
    # Nothing was written.
    assert not put_route.called


@respx.mock
async def test_real_set_wan_ipv6_handles_404(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/rest/networkconf").mock(
        return_value=httpx.Response(
            200, json={"data": [{"_id": "wan1", "name": "Internet 1", "purpose": "wan"}]}
        )
    )
    respx.put(f"{BASE}/rest/networkconf/wan1").mock(
        return_value=httpx.Response(404, text="not found")
    )
    result = await _call(real_server, "set_wan_ipv6", {"connection_type": "dhcpv6"})
    assert "error" in result
