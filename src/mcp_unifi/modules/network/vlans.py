"""Network/VLAN tools: list, create, update, delete."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.dispatcher import resolve_backend
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules._params import (
    BoundedName,
)
from mcp_unifi.modules.network._common import (
    format_json,
    make_err,
    normalize_ip_subnet,
    subnet_to_dhcp,
)
from mcp_unifi.modules.network._pending import build_preview_envelope, get_pending_actions
from mcp_unifi.modules.network._verify import verified_update
from mcp_unifi.redaction import redact

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.network.vlans")


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool()
    @audited("list_networks", mutates=False)
    async def list_networks(controller: str = "default") -> str:
        """List every network/VLAN configured on the controller.

        Side effects: None (read-only).

        Returns one record per network with ``_id``, ``name``, ``purpose``,
        ``vlan``, ``vlan_enabled``, ``ip_subnet``, ``dhcpd_enabled``,
        ``dhcpd_start``, ``dhcpd_stop``, and ``enabled``. Records also carry
        their IPv6 state inline: ``ipv6_interface_type`` (``none``/``pd``/
        ``static``), ``ipv6_ra_enabled`` (router advertisements), and
        ``ipv6_client_address_assignment`` (``slaac``/``dhcpv6``). Use
        ``set_lan_ipv6`` to change those, or ``get_wan_ipv6`` /
        ``set_wan_ipv6`` for the WAN uplink's IPv6 config.

        Example: list_networks(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            # Network records carry VPN key material: WireGuard
            # ``x_private_key`` / ``x_preshared_key``, site-to-site
            # ``x_ipsec_pre_shared_key``, RADIUS ``x_secret``. See
            # mcp_unifi.redaction for why this is not optional.
            return format_json(redact(await backend.list_networks()))
        except UniFiError as exc:
            logger.exception("list_networks failed")
            return err(str(exc))

    @mcp.tool()
    @audited("get_network_details", mutates=False)
    async def get_network_details(
        network_id: str = "",
        name: BoundedName = "",
        controller: str = "default",
    ) -> str:
        """Show one network's full record, grouped into readable sections.

        Side effects: None (read-only). This is the deep view that complements
        ``list_networks`` (the summary). Use it to inspect a network's DHCP
        scope, IPv6 configuration, and VPN fields before editing with
        ``update_vlan`` / ``set_lan_ipv6``.

        Resolve the network by ``network_id`` (preferred, from
        ``list_networks``) or by ``name`` (case-insensitive; errors if the name
        is ambiguous). Returns:

        - ``network``: identity fields (``_id``, ``name``, ``purpose``,
          ``vlan``, ``vlan_enabled``, ``ip_subnet``, ``enabled``,
          ``networkgroup``).
        - ``dhcp``: every ``dhcpd_*`` key (lease window, gateway/DNS toggles,
          lease time, NTP/WINS) plus the IPv6 DHCP (``dhcpdv6_*``) keys.
        - ``ipv6``: the LAN IPv6 view: ``ipv6_interface_type``,
          ``ipv6_ra_enabled``, ``ipv6_client_address_assignment``,
          ``ipv6_pd_start`` / ``ipv6_pd_stop`` (the delegated-prefix window),
          and the RA tuning keys. Empty section on a network with no IPv6.
        - ``vpn``: VPN-related keys (``vpn_type``, ``*_vpn_*``,
          ``remote_vpn_*``) when the network is a VPN; empty otherwise.
        - ``raw``: the complete unfiltered record, so nothing is hidden.

        Example: get_network_details(name="Default")

        Args:
            network_id: The ``_id`` from ``list_networks``. Wins over ``name``
                when both are given.
            name: Network display name (case-insensitive) as an alternative to
                ``network_id``. Errors if more than one network matches.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        if not network_id and not name:
            return err("get_network_details requires network_id or name")
        try:
            backend = resolve_backend(registry, controller)
            networks = await backend.list_networks()
        except UniFiError as exc:
            logger.exception("get_network_details failed")
            return err(str(exc))

        target: dict[str, Any] | None = None
        if network_id:
            target = next(
                (n for n in networks if isinstance(n, dict) and n.get("_id") == network_id),
                None,
            )
            if target is None:
                return err(f"network {network_id} not found")
        else:
            matches = [
                n
                for n in networks
                if isinstance(n, dict) and str(n.get("name", "")).lower() == name.strip().lower()
            ]
            if not matches:
                return err(f"network named {name!r} not found")
            if len(matches) > 1:
                ids = ", ".join(str(m.get("_id")) for m in matches)
                return err(f"multiple networks named {name!r}; pass network_id (ids: {ids})")
            target = matches[0]

        identity_keys = (
            "_id",
            "name",
            "purpose",
            "vlan",
            "vlan_enabled",
            "ip_subnet",
            "enabled",
            "networkgroup",
            "domain_name",
            "is_nat",
        )
        sections = {
            "network": {k: target[k] for k in identity_keys if k in target},
            "dhcp": {
                k: v
                for k, v in target.items()
                if k.startswith("dhcpd_") or k.startswith("dhcpdv6_")
            },
            "ipv6": {k: v for k, v in target.items() if k.startswith("ipv6_")},
            "vpn": {
                k: v
                for k, v in target.items()
                if "vpn" in k.lower() or k.startswith("radiusprofile_")
            },
            "raw": target,
        }
        # ``raw`` and ``vpn`` both expose the whole record, key material
        # included; redact covers every section in one walk.
        return format_json(redact({"controller": controller, **sections}))

    @mcp.tool()
    @audited("create_vlan", mutates=True)
    async def create_vlan(
        name: BoundedName,
        vlan_id: int,
        subnet: str,
        dhcp_start: str = "",
        dhcp_stop: str = "",
        purpose: BoundedName = "corporate",
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Create a VLAN-tagged network on the controller.

        Side effects:
        - Adds a new network record with the given VLAN ID, IP subnet, and
          DHCP scope. The first usable address (.1) becomes the gateway.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: create_vlan(name="iot", vlan_id=50, subnet="10.50.0.0/24")

        Args:
            name: Network display name (e.g. ``"iot"``, ``"cameras"``).
            vlan_id: 802.1Q VLAN ID, 2-4094.
            subnet: Subnet in either gateway-IP form (``"10.50.0.1/24"``,
                what the UniFi controller stores) or network form
                (``"10.50.0.0/24"``). Network form is auto-promoted to
                gateway form before the POST so callers don't have to
                remember which one UniFi wants. /24 only.
            dhcp_start: First DHCP lease address. Empty = derived from
                ``IOT_DHCP_START_OFFSET``.
            dhcp_stop: Last DHCP lease address. Empty = derived from
                ``IOT_DHCP_STOP_OFFSET``.
            purpose: ``"corporate"`` for normal LANs, ``"guest"`` for
                hotspot-style isolation.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        if not 2 <= vlan_id <= 4094:
            return err(f"vlan_id {vlan_id} out of range (2-4094)")

        normalized_subnet = normalize_ip_subnet(subnet)

        if not dhcp_start or not dhcp_stop:
            _, default_start, default_stop = subnet_to_dhcp(
                normalized_subnet,
                settings.iot_dhcp_start_offset,
                settings.iot_dhcp_stop_offset,
            )
            dhcp_start = dhcp_start or default_start
            dhcp_stop = dhcp_stop or default_stop

        payload: dict[str, Any] = {
            "name": name,
            "purpose": purpose,
            "vlan_enabled": True,
            "vlan": vlan_id,
            "ip_subnet": normalized_subnet,
            "dhcpd_enabled": True,
            "dhcpd_start": dhcp_start,
            "dhcpd_stop": dhcp_stop,
            "enabled": True,
        }
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_create": {"network": payload},
                    "summary": (f"Would create VLAN '{name}' (id={vlan_id}) on {subnet}"),
                }
            )
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.create_network(payload))
        except UniFiError as exc:
            logger.exception("create_vlan failed", extra={"vlan_name": name})
            return err(str(exc))

    @mcp.tool()
    @audited("update_vlan", mutates=True)
    async def update_vlan(
        network_id: str,
        updates: dict[str, Any],
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Patch fields on an existing VLAN/network record.

        Side effects:
        - Modifies the named network in place. Only fields supplied in
          ``updates`` change; everything else is preserved.
        - Changes to ``vlan`` or ``ip_subnet`` may disconnect clients on the
          affected network.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Verified write: after applying, the network is re-read from the
        controller and the response carries a ``verification`` block listing
        ``persisted_fields``, ``unchanged_fields`` (already correct before
        the write), ``dropped_fields`` (silently discarded by the
        controller), ``coerced_fields`` (stored with a different value or
        type), and ``unverifiable_fields``. ``purpose`` is a known coercion
        site: controllers running the zone-based firewall model may accept
        ``purpose="guest"`` and store ``"corporate"``. A response with
        ``verified: false`` and ``mutation_applied: true`` means the
        controller accepted the write but did not store it exactly — that is
        **not a rollback**, and the record may be in a mixed state.

        Example: update_vlan(network_id="65f...", updates={"enabled": False})

        Args:
            network_id: The ``_id`` from ``list_networks``.
            updates: Partial network record. Common keys: ``name``, ``vlan``,
                ``ip_subnet``, ``dhcpd_start``, ``dhcpd_stop``, ``enabled``,
                ``mdns_enabled`` (toggle the per-VLAN mDNS reflector
                independently of network creation), ``purpose``.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_update": {"network_id": network_id, "patch": updates},
                    "summary": f"Would update VLAN {network_id} ({len(updates)} field(s))",
                }
            )
        try:
            backend = resolve_backend(registry, controller)
            outcome = await verified_update(
                lister=backend.list_networks,
                updater=lambda: backend.update_network(network_id, updates),
                record_id=network_id,
                updates=updates,
            )
            if outcome is None:
                return err(f"network {network_id} not found")
            record, verification = outcome
            return format_json(
                {
                    "network_id": network_id,
                    "verification": verification,
                    "network": record,
                }
            )
        except UniFiError as exc:
            logger.exception("update_vlan failed", extra={"network_id": network_id})
            return err(str(exc))

    @mcp.tool()
    # Classified mutating even though this first phase only mints a preview
    # token: it is half of one destructive operation, and preview-then-confirm
    # is an interlock against mistakes, not an access control. Every ``delete_*``
    # tool is classified the same way, as is ``confirm_destructive_action``.
    @audited("delete_vlan", mutates=True)
    async def delete_vlan(
        network_id: str,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Preview deletion of a VLAN/network.

        v0.7.0: this tool no longer deletes on its own. It returns a preview
        envelope with a ``token``; call ``confirm_destructive_action(token)``
        to commit the delete. Tokens expire after 5 minutes.

        Side effects:
        - None until ``confirm_destructive_action`` runs against the token.
        - On confirm: removes the network record. Any WLANs, firewall rules,
          or DHCP reservations still referencing it must be detached first
          or the controller will reject the request. Clients on this VLAN
          lose connectivity.
        - ``dry_run=True`` returns the legacy ``would_delete`` envelope with
          no token — purely informational, no commit step possible.

        Example: delete_vlan(network_id="65f...")

        Args:
            network_id: The ``_id`` from ``list_networks``.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: ``True`` skips token generation and returns the legacy
                ``{"dry_run": true, ...}`` envelope. ``False`` (default)
                generates a preview token that must be confirmed.
        """
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_delete": {"network_id": network_id},
                    "summary": f"Would delete VLAN {network_id}",
                }
            )
        try:
            backend = resolve_backend(registry, controller)
            networks = await backend.list_networks()
        except UniFiError as exc:
            logger.exception("delete_vlan preview lookup failed", extra={"network_id": network_id})
            return err(str(exc))

        target = next(
            (n for n in networks if isinstance(n, dict) and n.get("_id") == network_id), None
        )
        if target is None:
            return err(f"network {network_id} not found")

        resource = {
            "_id": network_id,
            "name": target.get("name"),
            "vlan": target.get("vlan"),
            "ip_subnet": target.get("ip_subnet"),
        }

        async def _execute() -> str:
            try:
                ok = await backend.delete_network(network_id)
                return format_json({"deleted": ok, "network_id": network_id})
            except UniFiError as exc:
                logger.exception("delete_vlan failed", extra={"network_id": network_id})
                return err(str(exc))

        pending = get_pending_actions().put(
            action="delete_vlan",
            controller=controller,
            resource=resource,
            executor=_execute,
        )
        return format_json(build_preview_envelope(pending))
