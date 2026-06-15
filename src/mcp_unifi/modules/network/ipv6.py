"""IPv6 tools: read + set dual-stack config on WAN and LAN networkconf records.

Probed live against a UCG-Fiber on UniFi Network 10.4.57 (2026-06-12). IPv6 is
modelled entirely inside the ``/rest/networkconf`` records the VLAN tools
already read-modify-write, so these tools reuse ``list_networks`` /
``update_network`` rather than introducing a new endpoint.

Writable keys confirmed on this firmware:

WAN record (``purpose == "wan"``):
    ``wan_type_v6``               connection type: disabled/dhcpv6/pppoe/static
    ``ipv6_wan_delegation_type``  wire values ``none`` / ``pd`` (the tool also
                                  accepts the ``"prefix-delegation"`` alias and
                                  normalises it to ``"pd"``)
    ``wan_dhcpv6_pd_size_auto``   bool — auto-size the delegated prefix
    ``wan_dhcpv6_pd_size``        int  — PD size (only when PD + not auto;
                                  absent from the record until PD is enabled,
                                  so we only send it when explicitly requested)
    ``wan_ipv6_dns_preference``   auto / manual
    ``ipv6_setting_preference``   auto / manual

LAN record (``purpose in {"corporate", "guest"}``):
    ``ipv6_interface_type``            none / pd / static
    ``ipv6_pd_interface``              str  — the WAN networkgroup whose DHCPv6-PD
                                       delegation this LAN draws from (wire value
                                       ``"wan"`` on a single-uplink gateway). **A
                                       PD LAN is REJECTED without this binding**:
                                       ``ipv6_interface_type=pd`` alone returns
                                       HTTP 400 ``api.err.PdRequiresAssignedDhcpv6Wan``
                                       (probed live 2026-06-14). Adding
                                       ``ipv6_pd_interface="wan"`` → HTTP 200 and
                                       the LAN receives a global /64.
    ``ipv6_pd_prefixid``               int  — sub-prefix id selecting which /64
                                       to carve from the delegated /56. **Persists
                                       and carves a distinct /64 ONLY in MANUAL
                                       mode** (``ipv6_setting_preference=manual``).
                                       In ``auto`` mode the controller manages the
                                       carve itself and only the primary LAN
                                       (id 0) gets a slice; a second auto PD LAN
                                       stays empty (probed live 2026-06-14:
                                       Default=auto/id0 carved ``4ad::/64``, TRUSTED
                                       =auto/no-id stayed ``ipv6_subnets=[]``). So
                                       to give a SECOND LAN its own /64 the tool
                                       writes BOTH ``ipv6_pd_prefixid`` AND
                                       ``ipv6_setting_preference=manual`` (verified
                                       live 2026-06-14, v0.15.4).
    ``ipv6_client_address_assignment`` slaac / dhcpv6
    ``ipv6_ra_enabled``                bool — router advertisements
    ``dhcpdv6_dns_auto``               bool
    ``dhcpdv6_dns_1..4``               str  — explicit DHCPv6 DNS servers
    ``ipv6_setting_preference``        auto / manual

NOT writable here (documented, not built): IPv6 firewall rules. The
``/rest/firewallrule`` records on this firmware carry no IP-family field and
only the ``LAN_IN`` ruleset is present, so v4 and v6 cannot be distinguished
via this API surface. See ``set_wan_ipv6`` notes and the v0.14 changelog.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.dispatcher import resolve_backend
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules.network._common import format_json, make_err

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.backends import Backend
    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry
    from mcp_unifi.models import UniFiRecord

logger = logging.getLogger("mcp_unifi.network.ipv6")

#: Accepted WAN IPv6 connection types (``wan_type_v6``).
_WAN_V6_TYPES: frozenset[str] = frozenset({"disabled", "dhcpv6", "pppoe", "static"})
#: WAN prefix-delegation modes the caller may pass, mapped to the **wire value**
#: the controller actually accepts. UniFi Network 10.4.57 stores the
#: prefix-delegation mode as ``ipv6_wan_delegation_type: "pd"`` (NOT
#: ``"prefix-delegation"`` — that literal is rejected with
#: ``api.err.InvalidValue``). We accept the descriptive ``"prefix-delegation"``
#: alias for ergonomics and normalise it to ``"pd"`` before the PUT. Probed live
#: 2026-06-14: ``ipv6_wan_delegation_type: "pd"`` → HTTP 200;
#: ``"prefix-delegation"`` → HTTP 400 InvalidValue.
_WAN_DELEGATION_ALIASES: dict[str, str] = {
    "none": "none",
    "pd": "pd",
    "prefix-delegation": "pd",
}
#: The wire values the controller stores/accepts for ``ipv6_wan_delegation_type``.
_WAN_DELEGATION_WIRE: frozenset[str] = frozenset({"none", "pd"})
#: Accepted LAN interface types (``ipv6_interface_type``).
_LAN_V6_INTERFACE_TYPES: frozenset[str] = frozenset({"none", "pd", "static"})
#: Accepted LAN client address-assignment modes.
_LAN_V6_ASSIGNMENT: frozenset[str] = frozenset({"slaac", "dhcpv6"})
#: Accepted auto/manual preference values.
_PREFERENCE: frozenset[str] = frozenset({"auto", "manual"})

#: WAN record keys that describe IPv6 state (for the focused read view).
_WAN_V6_KEYS: tuple[str, ...] = (
    "wan_type_v6",
    "ipv6_wan_delegation_type",
    "wan_dhcpv6_pd_size_auto",
    "wan_dhcpv6_pd_size",
    "wan_ipv6_dns_preference",
    "ipv6_setting_preference",
)

#: PD-size bounds the UniFi UI allows. A /48..-/64 delegation window.
_PD_SIZE_MIN = 48
_PD_SIZE_MAX = 64

#: Complete PD-scaffold field set a LAN networkconf needs to be a VALID
#: DHCPv6-PD network on UniFi Network 10.4.57. Probed live 2026-06-14 by
#: diffing the WORKING Default LAN (PD enabled, carries a real global /64) against
#: a fresh ``ipv6_setting_preference=manual`` LAN (TRUSTED/IoT/GUEST) that has
#: every ``ipv6_*``/``dhcpdv6_*`` key unset.
#:
#: A fresh LAN is REJECTED with HTTP 400 ``api.err.InvalidIpv6Addr`` when PD is
#: enabled without these: the read-modify-write preserves nothing (the keys are
#: absent), so the merged record carries ``ipv6_pd_start: null`` and the
#: controller rejects it. Default succeeded earlier ONLY because it carried a
#: leftover PD-window scaffold (``ipv6_pd_start=::2``/``ipv6_pd_stop=::7d1``) from
#: a prior half-config that the strict read-modify-write preserved.
#:
#: These values are copied verbatim from Default's live working record:
#:   ipv6_pd_start "::2"               first /64 host offset of the PD window
#:   ipv6_pd_stop  "::7d1"             last  /64 host offset (2001 hosts)
#:   dhcpdv6_start "::2"               DHCPv6 lease-pool start (mirrors PD window)
#:   dhcpdv6_stop  "::7d1"             DHCPv6 lease-pool stop
#:   dhcpdv6_leasetime 86400          24h DHCPv6 lease
#:   ipv6_ra_priority "high"          Router Advertisement router preference
#:   ipv6_ra_preferred_lifetime 14400 RA preferred lifetime (seconds)
#:   ipv6_aliases []                  empty alias list (the UI always materialises it)
#:
#: Applied ONLY when enabling PD, ONLY for keys the live record lacks (so an
#: already-configured LAN like Default is never clobbered), and NEVER over a
#: value the caller set explicitly. This keeps strict read-modify-write intact
#: while making a blank LAN a complete, controller-valid PD network in one call.
_PD_SCAFFOLD_DEFAULTS: dict[str, Any] = {
    "ipv6_pd_start": "::2",
    "ipv6_pd_stop": "::7d1",
    "dhcpdv6_start": "::2",
    "dhcpdv6_stop": "::7d1",
    "dhcpdv6_leasetime": 86400,
    "ipv6_ra_priority": "high",
    "ipv6_ra_preferred_lifetime": 14400,
    "ipv6_aliases": [],
}


def _ipv6_view(record: UniFiRecord, keys: tuple[str, ...]) -> dict[str, Any]:
    """Project the IPv6-relevant keys out of a networkconf record."""
    return {k: record.get(k) for k in keys if k in record}


def _pd_wan_binding(networks: list[UniFiRecord]) -> str | None:
    """Return the ``ipv6_pd_interface`` wire value for the PD-enabled WAN.

    A PD LAN must reference WHICH DHCPv6 WAN's delegation it draws from via
    ``ipv6_pd_interface`` (the WAN's networkgroup, lowercased — e.g. ``"wan"``).
    We auto-target the WAN that actually has prefix-delegation turned on
    (``ipv6_wan_delegation_type == "pd"`` and a non-disabled
    ``wan_type_v6``); on a single-uplink gateway that is "Internet 1" with
    ``wan_networkgroup == "WAN"`` → ``"wan"``.

    Returns the lowercased networkgroup, or ``None`` when no WAN has DHCPv6-PD
    enabled (in which case enabling PD on a LAN would 400 anyway and the caller
    surfaces a clear error instead of letting the controller reject it).
    """
    for wan in networks:
        if not isinstance(wan, dict) or wan.get("purpose") != "wan":
            continue
        if wan.get("ipv6_wan_delegation_type") != "pd":
            continue
        if wan.get("wan_type_v6") in (None, "", "disabled"):
            continue
        group = wan.get("wan_networkgroup")
        if isinstance(group, str) and group:
            return group.lower()
    return None


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    async def _find_network(
        backend: Backend,
        *,
        network_id: str | None = None,
        wan_name: str | None = None,
    ) -> UniFiRecord | str:
        """Resolve a single networkconf record by id or WAN name.

        Returns the record dict, or an error-message string the caller wraps in
        ``err()``. When ``network_id`` is given it wins; otherwise the lookup is
        scoped to ``purpose == "wan"`` records and selected by ``wan_name`` (or
        the sole WAN on a single-WAN gateway).
        """
        networks = await backend.list_networks()
        if network_id is not None:
            target = next(
                (n for n in networks if isinstance(n, dict) and n.get("_id") == network_id),
                None,
            )
            if target is None:
                return f"network {network_id} not found"
            return target
        # WAN lookup by name (multi-WAN gear has "Internet 1"/"Internet 2").
        wans = [n for n in networks if isinstance(n, dict) and n.get("purpose") == "wan"]
        if not wans:
            return "no WAN network found on this controller"
        if wan_name:
            target = next((w for w in wans if w.get("name") == wan_name), None)
            if target is None:
                names = ", ".join(repr(w.get("name")) for w in wans)
                return f"WAN {wan_name!r} not found (available: {names})"
            return target
        if len(wans) > 1:
            names = ", ".join(repr(w.get("name")) for w in wans)
            return f"multiple WAN networks found; pass wan_name (available: {names})"
        return wans[0]

    @mcp.tool()
    @audited("get_wan_ipv6")
    async def get_wan_ipv6(wan_name: str = "", controller: str = "default") -> str:
        """Show the current IPv6 configuration of the WAN uplink(s).

        Side effects: None (read-only). Call this before ``set_wan_ipv6`` to
        see exactly what you are about to change.

        Returns one record per WAN interface with ``name``, ``_id``, and the
        IPv6 keys: ``wan_type_v6`` (connection type: ``disabled``/``dhcpv6``/
        ``pppoe``/``static``), ``ipv6_wan_delegation_type`` (``none`` or ``pd``),
        ``wan_dhcpv6_pd_size_auto``,
        ``wan_dhcpv6_pd_size`` (present only when PD is configured),
        ``wan_ipv6_dns_preference``, and ``ipv6_setting_preference``.

        Example: get_wan_ipv6(controller="default")

        Args:
            wan_name: Restrict the view to a single WAN by display name
                (e.g. ``"Internet 1"``). Empty (default) returns every WAN.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            networks = await backend.list_networks()
        except UniFiError as exc:
            logger.exception("get_wan_ipv6 failed")
            return err(str(exc))
        wans = [n for n in networks if isinstance(n, dict) and n.get("purpose") == "wan"]
        if wan_name:
            wans = [w for w in wans if w.get("name") == wan_name]
            if not wans:
                return err(f"WAN {wan_name!r} not found")
        view = [
            {"name": w.get("name"), "_id": w.get("_id"), **_ipv6_view(w, _WAN_V6_KEYS)}
            for w in wans
        ]
        return format_json({"controller": controller, "wan_ipv6": view})

    @mcp.tool()
    @audited("set_wan_ipv6")
    async def set_wan_ipv6(
        connection_type: str = "",
        prefix_delegation: str = "",
        pd_size: int = 0,
        dns_preference: str = "",
        wan_name: str = "",
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Set the WAN uplink's IPv6 connection type and prefix delegation.

        Side effects:
        - Changes how the gateway obtains IPv6 on the WAN. **Changing
          ``connection_type`` tears down and re-establishes the WAN IPv6
          session**: existing IPv6 connections drop and the gateway
          re-negotiates with the ISP (DHCPv6/SLAAC). IPv4 connectivity is not
          affected, but IPv6 hosts lose reachability for a few seconds to a
          minute. Enabling delegation (``prefix-delegation``) is what hands
          IPv6 prefixes down to your LANs.
        - Only the IPv6 keys you supply change; every other field on the WAN
          record is read first and written back unchanged (strict
          read-modify-write).
        - Mutates controller state. Use dry_run=True to preview the before/
          after diff without applying.

        Read first: call ``get_wan_ipv6`` to see the current values.

        BLAST RADIUS: this is a WAN-level change. On dual-WAN gateways it only
        touches the named WAN. Do not run this against the live gateway without
        intent: a mistyped ``connection_type`` can leave the WAN with no IPv6.

        Example: set_wan_ipv6(connection_type="dhcpv6", prefix_delegation="prefix-delegation", dry_run=True)

        Args:
            connection_type: ``"disabled"``, ``"dhcpv6"``, ``"pppoe"``, or
                ``"static"``. Empty leaves it unchanged. Most ISPs that hand
                out IPv6 (incl. Empire Access) use ``"dhcpv6"``.
            prefix_delegation: ``"none"`` or ``"prefix-delegation"`` (alias for
                the controller's wire value ``"pd"``; ``"pd"`` is also accepted).
                Empty leaves it unchanged. Prefix delegation is required for your
                LANs to receive IPv6 subnets.
            pd_size: DHCPv6-PD prefix size (48-64), e.g. ``56``. When enabling
                delegation, the controller requires a consistent
                ``wan_dhcpv6_pd_size_auto`` / ``wan_dhcpv6_pd_size`` pair: a
                non-zero ``pd_size`` pins ``wan_dhcpv6_pd_size_auto=false`` and
                sends that size; ``pd_size=0`` while enabling delegation pins
                ``wan_dhcpv6_pd_size_auto=true`` (controller auto-sizes). Leaving
                an inconsistent pair on the record is what triggers
                ``api.err.InvalidValue``, so the tool always emits a consistent
                pair when delegation is turned on.
            dns_preference: ``"auto"`` or ``"manual"`` for IPv6 DNS. Empty
                leaves it unchanged.
            wan_name: Display name of the WAN to target (e.g. ``"Internet 1"``).
                Required only on multi-WAN gateways; single-WAN gateways match
                automatically.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the before/after diff without applying it.
        """
        ct = connection_type.strip().lower()
        if ct and ct not in _WAN_V6_TYPES:
            return err(
                f"invalid connection_type {connection_type!r}: "
                "use disabled, dhcpv6, pppoe, or static"
            )
        pd_input = prefix_delegation.strip().lower()
        if pd_input and pd_input not in _WAN_DELEGATION_ALIASES:
            return err(
                f"invalid prefix_delegation {prefix_delegation!r}: use none or prefix-delegation"
            )
        # Normalise the caller-facing alias to the controller's wire value.
        pd = _WAN_DELEGATION_ALIASES.get(pd_input, "") if pd_input else ""
        dns = dns_preference.strip().lower()
        if dns and dns not in _PREFERENCE:
            return err(f"invalid dns_preference {dns_preference!r}: use auto or manual")
        if pd_size and not _PD_SIZE_MIN <= pd_size <= _PD_SIZE_MAX:
            return err(f"pd_size {pd_size} out of range ({_PD_SIZE_MIN}-{_PD_SIZE_MAX})")

        patch: dict[str, Any] = {}
        if ct:
            patch["wan_type_v6"] = ct
        if pd:
            patch["ipv6_wan_delegation_type"] = pd
        # The live WAN record can carry an inconsistent ``wan_dhcpv6_pd_size_auto:
        # false`` with no ``wan_dhcpv6_pd_size`` key. When we turn delegation ON
        # (``pd == "pd"``) we must emit a self-consistent auto/size pair or the
        # controller rejects the merged record with ``api.err.InvalidValue``.
        # An explicit ``pd_size`` always pins ``pd_size_auto=false`` + that size;
        # otherwise (enabling delegation with no explicit size) pin
        # ``pd_size_auto=true`` so the controller auto-sizes.
        if pd_size:
            patch["wan_dhcpv6_pd_size"] = pd_size
            patch["wan_dhcpv6_pd_size_auto"] = False
        elif pd == "pd":
            patch["wan_dhcpv6_pd_size_auto"] = True
        if dns:
            patch["wan_ipv6_dns_preference"] = dns
        if not patch:
            return err(
                "set_wan_ipv6 requires at least one of connection_type, "
                "prefix_delegation, pd_size, dns_preference"
            )

        try:
            backend = resolve_backend(registry, controller)
            found = await _find_network(backend, wan_name=wan_name or None)
            if isinstance(found, str):
                return err(found)
            wan_id = found.get("_id")
            if not isinstance(wan_id, str) or not wan_id:
                return err("WAN record has no _id")
            before = _ipv6_view(found, _WAN_V6_KEYS)
            after = {**before, **patch}
            if dry_run:
                return format_json(
                    {
                        "dry_run": True,
                        "controller": controller,
                        "would_update": {
                            "action": "set_wan_ipv6",
                            "wan_name": found.get("name"),
                            "network_id": wan_id,
                            "before": before,
                            "after": after,
                        },
                        "blast_radius": (
                            "Changing WAN IPv6 connection type re-establishes the "
                            "WAN IPv6 session; IPv6 hosts lose reachability briefly. "
                            "IPv4 is unaffected."
                        ),
                        "summary": f"Would update IPv6 on WAN {found.get('name')!r}",
                    }
                )
            updated = await backend.update_network(wan_id, patch)
            if updated is None:
                return err(f"WAN {wan_id} not found")
            return format_json(
                {
                    "updated": True,
                    "wan_name": found.get("name"),
                    "network_id": wan_id,
                    "before": before,
                    "after": _ipv6_view(updated, _WAN_V6_KEYS),
                }
            )
        except UniFiError as exc:
            logger.exception("set_wan_ipv6 failed", extra={"wan_name": wan_name})
            return err(str(exc))

    @mcp.tool()
    @audited("set_lan_ipv6")
    async def set_lan_ipv6(
        network_id: str,
        interface_type: str = "",
        ra_enabled: bool | None = None,
        address_assignment: str = "",
        dns_auto: bool | None = None,
        dns_servers: list[str] | None = None,
        prefix_id: int = -1,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Set the IPv6 configuration of one LAN/VLAN network.

        Side effects:
        - Changes how this network gets and advertises IPv6. Turning on
          ``interface_type="pd"`` plus ``ra_enabled=True`` is what makes the
          LAN's clients receive global IPv6 addresses from the prefix
          delegated by the WAN. Toggling router advertisements
          (``ra_enabled``) or the address-assignment mode causes clients on
          this network to re-acquire IPv6; IPv4 is unaffected.
        - Only the IPv6 keys you supply change; every other field on the
          network record is read first and written back unchanged (strict
          read-modify-write).
        - Mutates controller state. Use dry_run=True to preview the before/
          after diff without applying.

        Prefix-delegation binding: when ``interface_type="pd"`` the controller
        REQUIRES the LAN to reference which DHCPv6 WAN's delegation to draw
        from. ``ipv6_interface_type=pd`` on its own returns HTTP 400
        ``api.err.PdRequiresAssignedDhcpv6Wan``. This tool auto-binds the LAN to
        the WAN that actually has DHCPv6-PD enabled (on a single-uplink gateway
        that is the only internet uplink) by emitting ``ipv6_pd_interface`` =
        that WAN's networkgroup (e.g. ``"wan"``). No WAN with PD enabled → a
        clear error instead of a controller 400.

        Fresh-LAN PD scaffold: a brand-new LAN
        (``ipv6_setting_preference=manual``, every ipv6 key unset) has no PD
        window, DHCPv6 lease window, or RA lifetimes. Enabling PD on it without
        those returns HTTP 400 ``api.err.InvalidIpv6Addr`` (the merged record
        carries ``ipv6_pd_start: null``). When enabling PD, this tool fills the
        COMPLETE required scaffold with the controller's standard defaults
        (``ipv6_pd_start=::2``, ``ipv6_pd_stop=::7d1``, matching DHCPv6 lease
        window, ``ipv6_ra_priority=high``, RA lifetimes) — but ONLY for keys the
        live record lacks and the caller did not set explicitly, so an
        already-configured PD LAN keeps its own window untouched.

        Carving a DISTINCT /64 for a SECOND PD LAN (``prefix_id``): on UniFi
        Network 10.4.57 the controller's ``auto`` IPv6 mode hands the primary
        sub-prefix (id 0) to ONE LAN (the Default/MGMT LAN) and leaves a second
        auto PD LAN with an empty ``ipv6_subnets`` — it never carves its own /64
        (probed live 2026-06-14). To give a second LAN its own slice, pass an
        explicit ``prefix_id`` (e.g. ``1``). When ``prefix_id`` is supplied the
        tool writes ``ipv6_pd_prefixid=<id>`` AND pins
        ``ipv6_setting_preference="manual"`` (it does NOT flip to ``auto``),
        because only manual mode honours an operator-pinned sub-prefix. Both keys
        survive the strict read-modify-write and the scaffold-fill. Omitting
        ``prefix_id`` keeps the legacy ``auto`` behaviour unchanged.

        Read first: call ``list_networks`` to find the ``network_id`` and see
        the current ``ipv6_*`` state (now surfaced inline).

        Example: set_lan_ipv6(network_id="65f...", interface_type="pd", ra_enabled=True, dry_run=True)

        Args:
            network_id: The ``_id`` from ``list_networks`` (a LAN/VLAN, not a
                WAN).
            interface_type: ``"none"``, ``"pd"`` (use the WAN-delegated
                prefix), or ``"static"``. Empty leaves it unchanged. When set to
                ``"pd"`` the WAN binding is added automatically.
            ra_enabled: ``True``/``False`` to toggle IPv6 Router
                Advertisements (SLAAC). ``None`` (default) leaves it unchanged.
            address_assignment: ``"slaac"`` or ``"dhcpv6"``. Empty leaves it
                unchanged.
            dns_auto: ``True`` to advertise the gateway as DNS, ``False`` to
                use explicit servers from ``dns_servers``. ``None`` leaves it
                unchanged.
            dns_servers: Up to four IPv6 DNS server addresses, applied as
                ``dhcpdv6_dns_1..4`` when ``dns_auto=False``. ``None`` leaves
                them unchanged.
            prefix_id: Sub-prefix id (e.g. ``0``, ``1``) selecting which /64 to
                carve from the delegated /56, so multiple PD LANs don't collide.
                Only valid with ``interface_type="pd"``. Default ``-1`` means
                "not supplied" — the LAN keeps the controller-managed ``auto``
                carve (only the primary LAN gets a /64). Supplying a value (``0``
                and up) writes ``ipv6_pd_prefixid`` AND pins
                ``ipv6_setting_preference="manual"`` so the controller honours the
                pinned sub-prefix and the LAN carves its OWN /64. The
                Default/MGMT LAN already holds id ``0``, so a second LAN needs a
                distinct id (``1``, ``2``, ...).
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the before/after diff without applying it.
        """
        it = interface_type.strip().lower()
        if it and it not in _LAN_V6_INTERFACE_TYPES:
            return err(f"invalid interface_type {interface_type!r}: use none, pd, or static")
        aa = address_assignment.strip().lower()
        if aa and aa not in _LAN_V6_ASSIGNMENT:
            return err(f"invalid address_assignment {address_assignment!r}: use slaac or dhcpv6")
        if dns_servers is not None and len(dns_servers) > 4:
            return err("dns_servers accepts at most 4 addresses")
        # prefix_id is an int; the sentinel -1 means "not supplied" so that 0
        # (a legitimate, distinct sub-prefix id) is preserved as a real value.
        pid_supplied = prefix_id >= 0
        if pid_supplied and it != "pd":
            return err("prefix_id is only valid when interface_type='pd'")

        patch: dict[str, Any] = {}
        if it:
            patch["ipv6_interface_type"] = it
        if ra_enabled is not None:
            patch["ipv6_ra_enabled"] = ra_enabled
        if aa:
            patch["ipv6_client_address_assignment"] = aa
        if dns_auto is not None:
            patch["dhcpdv6_dns_auto"] = dns_auto
        if dns_servers is not None:
            for idx in range(1, 5):
                patch[f"dhcpdv6_dns_{idx}"] = (
                    dns_servers[idx - 1] if idx <= len(dns_servers) else ""
                )
        if not patch:
            return err(
                "set_lan_ipv6 requires at least one of interface_type, ra_enabled, "
                "address_assignment, dns_auto, dns_servers"
            )

        try:
            backend = resolve_backend(registry, controller)
            networks = await backend.list_networks()
        except UniFiError as exc:
            logger.exception("set_lan_ipv6 failed", extra={"network_id": network_id})
            return err(str(exc))

        found = next(
            (n for n in networks if isinstance(n, dict) and n.get("_id") == network_id),
            None,
        )
        if found is None:
            return err(f"network {network_id} not found")
        if found.get("purpose") == "wan":
            return err(f"network {network_id} is a WAN; use set_wan_ipv6 for WAN IPv6")

        # Enabling PD on a LAN requires the WAN-uplink binding + (optionally) a
        # prefix-id, or the controller rejects the record with
        # ``api.err.PdRequiresAssignedDhcpv6Wan``. Resolve the binding from the
        # PD-enabled WAN and inject it into the patch.
        if it == "pd":
            binding = _pd_wan_binding(networks)
            if binding is None:
                return err(
                    "cannot enable PD on this LAN: no WAN has DHCPv6 prefix "
                    "delegation enabled. Enable it on the WAN first with "
                    "set_wan_ipv6(connection_type='dhcpv6', "
                    "prefix_delegation='prefix-delegation')."
                )
            patch["ipv6_pd_interface"] = binding

            if pid_supplied:
                # Operator pinned a distinct sub-prefix. UniFi Network 10.4.57
                # only honours a pinned ``ipv6_pd_prefixid`` in MANUAL mode: in
                # ``auto`` mode the controller manages the carve and hands the
                # primary slice (id 0) to ONE LAN, leaving any second auto PD LAN
                # with an empty ``ipv6_subnets``. So when a prefix_id is supplied
                # we write it AND pin ``ipv6_setting_preference=manual`` so this
                # LAN carves its OWN /64. We do NOT flip to ``auto`` in this branch
                # (that would discard the pinned id). Both keys are added to the
                # patch and therefore preserved through the read-modify-write and
                # protected from the scaffold-fill below (which only fills keys
                # absent from the patch).
                patch["ipv6_pd_prefixid"] = prefix_id
                patch["ipv6_setting_preference"] = "manual"
            elif found.get("ipv6_setting_preference") in (None, "", "manual"):
                # Legacy auto path (no prefix_id): a fresh LAN sits at
                # ``ipv6_setting_preference=manual``; in that mode the controller
                # will NOT auto-carve a sub-prefix, so the LAN never gets a global
                # /64. The working Default LAN runs ``auto`` (verified live
                # 2026-06-14: Default=auto carves a /64; a manual LAN with no
                # pinned id does not). Flip manual/absent → ``auto`` so the
                # controller manages the carve, matching Default. An already-
                # ``auto`` LAN is left untouched.
                patch["ipv6_setting_preference"] = "auto"

            # Fill the COMPLETE PD scaffold a fresh (blank) LAN lacks. A LAN with
            # ``ipv6_setting_preference=manual`` and all ipv6 keys unset has no
            # ``ipv6_pd_start``/``ipv6_pd_stop`` (and no DHCPv6 lease window or RA
            # lifetimes), so the merged record carries ``ipv6_pd_start: null`` and
            # the controller rejects it with HTTP 400 ``api.err.InvalidIpv6Addr``.
            # We add each scaffold default ONLY when:
            #   1. the caller did not already set that key in this patch, AND
            #   2. the live record does not already carry a non-null value
            #      (so an already-configured PD LAN like Default keeps its own
            #      window via strict read-modify-write — we never clobber it).
            for key, default in _PD_SCAFFOLD_DEFAULTS.items():
                if key in patch:
                    continue
                existing = found.get(key)
                if existing in (None, ""):
                    patch[key] = default

        # Tracked keys for the before/after view: the patch keys plus the
        # stable identifiers callers expect to see move.
        view_keys = tuple(
            dict.fromkeys(
                (
                    "ipv6_interface_type",
                    "ipv6_pd_interface",
                    "ipv6_ra_enabled",
                    "ipv6_client_address_assignment",
                    "dhcpdv6_dns_auto",
                    *patch.keys(),
                )
            )
        )
        try:
            before = _ipv6_view(found, view_keys)
            after = {**before, **patch}
            if dry_run:
                return format_json(
                    {
                        "dry_run": True,
                        "controller": controller,
                        "would_update": {
                            "action": "set_lan_ipv6",
                            "network_id": network_id,
                            "name": found.get("name"),
                            "before": before,
                            "after": after,
                        },
                        "summary": (
                            f"Would update IPv6 on network {found.get('name')!r} "
                            f"({len(patch)} field(s))"
                        ),
                    }
                )
            updated = await backend.update_network(network_id, patch)
            if updated is None:
                return err(f"network {network_id} not found")
            return format_json(
                {
                    "updated": True,
                    "network_id": network_id,
                    "name": found.get("name"),
                    "before": before,
                    "after": _ipv6_view(updated, view_keys),
                }
            )
        except UniFiError as exc:
            logger.exception("set_lan_ipv6 failed", extra={"network_id": network_id})
            return err(str(exc))
