"""MCP UniFi — local-API gateway management for self-hosted UniFi.

Forty-three tools covering devices, networks/VLANs, WLANs (CRUD), firewall rules
(CRUD), switch port profiles (CRUD), connected clients (block/unblock/
reconnect), per-port state (PoE + enable + profile assignment), static DHCP
leases (CRUD), port forwarding (CRUD), site health, WAN status, events,
alarms, speed tests, DPI top talkers, and four composite operations:
:func:`create_iot_network`, :func:`provision_homelab_service`,
:func:`quarantine_client`, :func:`create_guest_network`, and the read-only
:func:`audit_open_ports`. Composites with multiple write steps roll back on
partial failure.

Stub mode (``STUB_MODE=true``, default) returns realistic mock payloads so the
server is useful before the gateway hardware is on the network. Flip
``STUB_MODE=false`` and supply ``UNIFI_HOST`` plus ``UNIFI_API_KEY`` to talk to
a real UCG-Fiber, UDM Pro, or other UniFi OS gateway.

Transport: Streamable HTTP via FastMCP (current MCP spec).
"""

from __future__ import annotations

import json
import logging
from typing import Any

from fastmcp import FastMCP

from mcp_unifi.clients.stubs import STUB, StubState
from mcp_unifi.clients.unifi import UniFiClient, UniFiError
from mcp_unifi.config import Settings, load_settings
from mcp_unifi.logging_setup import configure_logging

logger = logging.getLogger("mcp_unifi.server")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _format(data: object) -> str:
    return json.dumps(data, indent=2, default=str)


def _err(msg: str, *, stub_mode: bool) -> str:
    return _format({"error": msg, "stub_mode": stub_mode})


def _subnet_to_dhcp(
    subnet: str, dhcp_start_offset: int, dhcp_stop_offset: int
) -> tuple[str, str, str]:
    """Compute (gateway, dhcp_start, dhcp_stop) from a /24 subnet string.

    Only handles /24s — that is what create_iot_network templates produce. For
    arbitrary CIDRs the caller can pass explicit dhcp_start/dhcp_stop to
    create_vlan instead.
    """
    base = subnet.split("/")[0].rsplit(".", 1)[0]
    return (
        f"{base}.1",
        f"{base}.{dhcp_start_offset}",
        f"{base}.{dhcp_stop_offset}",
    )


# ---------------------------------------------------------------------------
# Server factory
# ---------------------------------------------------------------------------


def build_server(
    settings: Settings,
    *,
    stub: StubState | None = None,
    unifi: UniFiClient | None = None,
) -> FastMCP:
    """Construct a FastMCP instance with all 15 tools wired up.

    Tests use this to build an isolated server bound to a custom ``StubState``
    or a mocked ``UniFiClient`` (via ``respx``) without touching module-level
    singletons.
    """
    state = stub if stub is not None else STUB
    client = unifi
    if not settings.stub_mode and client is None:
        client = UniFiClient(
            host=settings.unifi_host,
            api_key=settings.unifi_api_key,
            port=settings.unifi_port,
            site=settings.unifi_site,
            verify_ssl=settings.unifi_verify_ssl,
        )

    mcp = FastMCP("UniFi")

    def err(msg: str) -> str:
        return _err(msg, stub_mode=settings.stub_mode)

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    @mcp.tool()
    async def list_devices() -> str:
        """List every UniFi device adopted by this gateway.

        Returns:
            JSON list with _id, mac, type, model, name, ip, version, state,
            uptime, num_sta, satisfaction per device.
        """
        try:
            if settings.stub_mode:
                return _format(state.list_devices())
            assert client is not None
            return _format(await client.list_devices())
        except UniFiError as exc:
            logger.exception("list_devices failed")
            return err(str(exc))

    @mcp.tool()
    async def list_networks() -> str:
        """List all configured networks/VLANs on the gateway.

        Returns:
            JSON list of network records: _id, name, purpose, vlan,
            vlan_enabled, ip_subnet, dhcpd_enabled, dhcpd_start, dhcpd_stop,
            enabled.
        """
        try:
            if settings.stub_mode:
                return _format(state.list_networks())
            assert client is not None
            return _format(await client.list_networks())
        except UniFiError as exc:
            logger.exception("list_networks failed")
            return err(str(exc))

    @mcp.tool()
    async def create_vlan(
        name: str,
        vlan_id: int,
        subnet: str,
        dhcp_start: str = "",
        dhcp_stop: str = "",
        purpose: str = "corporate",
    ) -> str:
        """Create a new VLAN-tagged network.

        Args:
            name: Network display name (e.g. "IoT", "Guest").
            vlan_id: 802.1Q VLAN ID, 2-4094.
            subnet: CIDR for the VLAN gateway IP, e.g. "10.0.20.0/24". The
                first usable address (.1) becomes the router/DHCP server.
            dhcp_start: First DHCP lease address. If empty, defaults to
                ``.<IOT_DHCP_START_OFFSET>`` of the subnet.
            dhcp_stop: Last DHCP lease address. If empty, defaults to
                ``.<IOT_DHCP_STOP_OFFSET>`` of the subnet.
            purpose: UniFi network purpose. "corporate" for normal LANs,
                "guest" for hotspot-style isolation.

        Returns:
            JSON of the created network record (with assigned _id).
        """
        if not 2 <= vlan_id <= 4094:
            return err(f"vlan_id {vlan_id} out of range (2-4094)")

        if not dhcp_start or not dhcp_stop:
            _, default_start, default_stop = _subnet_to_dhcp(
                subnet,
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
            "ip_subnet": subnet,
            "dhcpd_enabled": True,
            "dhcpd_start": dhcp_start,
            "dhcpd_stop": dhcp_stop,
            "enabled": True,
        }
        try:
            if settings.stub_mode:
                return _format(state.create_network(payload))
            assert client is not None
            return _format(await client.create_network(payload))
        except UniFiError as exc:
            logger.exception("create_vlan failed", extra={"vlan_name": name})
            return err(str(exc))

    @mcp.tool()
    async def update_vlan(network_id: str, updates: dict[str, Any]) -> str:
        """Update fields on an existing VLAN/network.

        Only the fields you supply are changed; everything else is preserved.

        Args:
            network_id: The ``_id`` from list_networks.
            updates: Partial network record. Common keys: name, vlan,
                ip_subnet, dhcpd_start, dhcpd_stop, enabled.

        Returns:
            JSON of the updated network record, or error if not found.
        """
        try:
            if settings.stub_mode:
                updated = state.update_network(network_id, updates)
                if updated is None:
                    return err(f"network {network_id} not found")
                return _format(updated)
            assert client is not None
            return _format(await client.update_network(network_id, updates))
        except UniFiError as exc:
            logger.exception("update_vlan failed", extra={"network_id": network_id})
            return err(str(exc))

    @mcp.tool()
    async def delete_vlan(network_id: str) -> str:
        """Delete a VLAN/network.

        Args:
            network_id: The ``_id`` from list_networks. Be sure no SSIDs or
                firewall rules still reference it; the controller will reject
                otherwise.

        Returns:
            JSON ``{"deleted": true}`` on success.
        """
        try:
            if settings.stub_mode:
                ok = state.delete_network(network_id)
                return _format({"deleted": ok, "network_id": network_id})
            assert client is not None
            await client.delete_network(network_id)
            return _format({"deleted": True, "network_id": network_id})
        except UniFiError as exc:
            logger.exception("delete_vlan failed", extra={"network_id": network_id})
            return err(str(exc))

    @mcp.tool()
    async def list_wlans() -> str:
        """List all WiFi SSIDs configured on the gateway.

        Returns:
            JSON list of WLAN records: _id, name, enabled, security, wpa_mode,
            networkconf_id, is_guest, hide_ssid, wlan_band.
        """
        try:
            if settings.stub_mode:
                return _format(state.list_wlans())
            assert client is not None
            return _format(await client.list_wlans())
        except UniFiError as exc:
            logger.exception("list_wlans failed")
            return err(str(exc))

    @mcp.tool()
    async def create_wlan(
        name: str,
        passphrase: str,
        network_id: str,
        security: str = "wpapsk",
        wpa_mode: str = "wpa2",
        is_guest: bool = False,
        hide_ssid: bool = False,
        wlan_band: str = "both",
    ) -> str:
        """Create a new WiFi SSID bound to a specific network/VLAN.

        Args:
            name: SSID broadcast name.
            passphrase: WPA pre-shared key (8-63 chars). Required unless
                ``security="open"``.
            network_id: The ``_id`` of the network/VLAN this SSID lives on.
                Get it from list_networks.
            security: ``"wpapsk"`` (default), ``"wpaeap"``, or ``"open"``.
            wpa_mode: ``"wpa2"`` (default) or ``"wpa3"`` if all clients
                support it.
            is_guest: True isolates clients from each other and the rest of
                the LAN.
            hide_ssid: True suppresses the SSID broadcast.
            wlan_band: ``"2g"``, ``"5g"``, ``"6g"``, or ``"both"`` (default).

        Returns:
            JSON of the created WLAN record.
        """
        payload: dict[str, Any] = {
            "name": name,
            "enabled": True,
            "security": security,
            "wpa_mode": wpa_mode,
            "networkconf_id": network_id,
            "is_guest": is_guest,
            "hide_ssid": hide_ssid,
            "wlan_band": wlan_band,
        }
        if security != "open":
            payload["x_passphrase"] = passphrase
        try:
            if settings.stub_mode:
                return _format(state.create_wlan(payload))
            assert client is not None
            return _format(await client.create_wlan(payload))
        except UniFiError as exc:
            logger.exception("create_wlan failed", extra={"wlan_name": name})
            return err(str(exc))

    @mcp.tool()
    async def update_wlan(wlan_id: str, updates: dict[str, Any]) -> str:
        """Update fields on an existing WiFi SSID.

        Only the fields you supply are changed; everything else is preserved.
        Passphrases are accepted via the ``x_passphrase`` key in ``updates``
        and are redacted in the response.

        Args:
            wlan_id: The ``_id`` from list_wlans.
            updates: Partial WLAN record. Common keys: name, enabled,
                x_passphrase, wpa_mode, hide_ssid, wlan_band, is_guest.

        Returns:
            JSON of the updated WLAN record, or error if not found.
        """
        try:
            if settings.stub_mode:
                updated = state.update_wlan(wlan_id, updates)
                if updated is None:
                    return err(f"wlan {wlan_id} not found")
                return _format(updated)
            assert client is not None
            return _format(await client.update_wlan(wlan_id, updates))
        except UniFiError as exc:
            logger.exception("update_wlan failed", extra={"wlan_id": wlan_id})
            return err(str(exc))

    @mcp.tool()
    async def delete_wlan(wlan_id: str) -> str:
        """Delete a WiFi SSID.

        Args:
            wlan_id: The ``_id`` from list_wlans.

        Returns:
            JSON ``{"deleted": true, "wlan_id": "..."}`` on success, or an
            error object if the gateway rejects the request.
        """
        try:
            if settings.stub_mode:
                ok = state.delete_wlan(wlan_id)
                return _format({"deleted": ok, "wlan_id": wlan_id})
            assert client is not None
            await client.delete_wlan(wlan_id)
            return _format({"deleted": True, "wlan_id": wlan_id})
        except UniFiError as exc:
            logger.exception("delete_wlan failed", extra={"wlan_id": wlan_id})
            return err(str(exc))

    @mcp.tool()
    async def list_firewall_rules() -> str:
        """List all firewall rules on the gateway.

        Returns:
            JSON list with _id, name, ruleset, rule_index, action, enabled,
            protocol, src_*, dst_* per rule.
        """
        try:
            if settings.stub_mode:
                return _format(state.list_firewall_rules())
            assert client is not None
            return _format(await client.list_firewall_rules())
        except UniFiError as exc:
            logger.exception("list_firewall_rules failed")
            return err(str(exc))

    @mcp.tool()
    async def create_firewall_rule(
        name: str,
        ruleset: str,
        action: str,
        rule_index: int = 2500,
        protocol: str = "all",
        src_address: str = "",
        dst_address: str = "",
        src_networkconf_id: str = "",
        dst_networkconf_id: str = "",
        enabled: bool = True,
    ) -> str:
        """Create a firewall rule.

        Args:
            name: Display name for the rule.
            ruleset: Where the rule is enforced. Common values:
                ``"LAN_IN"``, ``"LAN_OUT"``, ``"LAN_LOCAL"``,
                ``"WAN_IN"``, ``"WAN_OUT"``, ``"WAN_LOCAL"``,
                ``"GUEST_IN"``, ``"GUEST_OUT"``, ``"GUEST_LOCAL"``.
            action: ``"accept"``, ``"drop"``, or ``"reject"``.
            rule_index: Rule order. Lower = evaluated first. UniFi
                user-defined rules typically live in the 2000-3999 range; 2500
                is a safe default.
            protocol: ``"all"``, ``"tcp"``, ``"udp"``, ``"icmp"``, etc.
            src_address: Source CIDR (e.g. ``"10.0.20.0/24"``). Empty = any.
            dst_address: Destination CIDR. Empty = any.
            src_networkconf_id: Source network ``_id``. Use this OR
                src_address.
            dst_networkconf_id: Destination network ``_id``. Use this OR
                dst_address.
            enabled: Set False to create the rule disabled for staging.

        Returns:
            JSON of the created firewall rule.
        """
        payload: dict[str, Any] = {
            "name": name,
            "ruleset": ruleset,
            "rule_index": rule_index,
            "action": action,
            "protocol": protocol,
            "enabled": enabled,
        }
        if src_address:
            payload["src_address"] = src_address
        if dst_address:
            payload["dst_address"] = dst_address
        if src_networkconf_id:
            payload["src_networkconf_id"] = src_networkconf_id
        if dst_networkconf_id:
            payload["dst_networkconf_id"] = dst_networkconf_id
        try:
            if settings.stub_mode:
                return _format(state.create_firewall_rule(payload))
            assert client is not None
            return _format(await client.create_firewall_rule(payload))
        except UniFiError as exc:
            logger.exception("create_firewall_rule failed", extra={"rule_name": name})
            return err(str(exc))

    @mcp.tool()
    async def update_firewall_rule(rule_id: str, updates: dict[str, Any]) -> str:
        """Update fields on an existing firewall rule.

        Only the fields you supply are changed. Common partial keys:
        ``enabled``, ``action``, ``protocol``, ``rule_index``, ``src_address``,
        ``dst_address``, ``src_networkconf_id``, ``dst_networkconf_id``,
        ``name``.

        Args:
            rule_id: The ``_id`` from ``list_firewall_rules``.
            updates: Partial firewall-rule record.

        Returns:
            JSON of the updated rule, or an error if not found.
        """
        try:
            if settings.stub_mode:
                updated = state.update_firewall_rule(rule_id, updates)
                if updated is None:
                    return err(f"firewall rule {rule_id} not found")
                return _format(updated)
            assert client is not None
            return _format(await client.update_firewall_rule(rule_id, updates))
        except UniFiError as exc:
            logger.exception("update_firewall_rule failed", extra={"rule_id": rule_id})
            return err(str(exc))

    @mcp.tool()
    async def delete_firewall_rule(rule_id: str) -> str:
        """Delete a firewall rule.

        Args:
            rule_id: The ``_id`` from list_firewall_rules.

        Returns:
            JSON ``{"deleted": true, "rule_id": "..."}`` on success, or an
            error object if the gateway rejects the request.
        """
        try:
            if settings.stub_mode:
                ok = state.delete_firewall_rule(rule_id)
                return _format({"deleted": ok, "rule_id": rule_id})
            assert client is not None
            await client.delete_firewall_rule(rule_id)
            return _format({"deleted": True, "rule_id": rule_id})
        except UniFiError as exc:
            logger.exception("delete_firewall_rule failed", extra={"rule_id": rule_id})
            return err(str(exc))

    @mcp.tool()
    async def list_port_profiles() -> str:
        """List switch port profiles configured on the gateway.

        Port profiles control PoE, native VLAN, tagged VLANs, and STP per
        switch port. Use these IDs when assigning ports on a switch.

        Returns:
            JSON list of profiles: _id, name, native_networkconf_id, forward,
            poe_mode.
        """
        try:
            if settings.stub_mode:
                return _format(state.list_port_profiles())
            assert client is not None
            return _format(await client.list_port_profiles())
        except UniFiError as exc:
            logger.exception("list_port_profiles failed")
            return err(str(exc))

    @mcp.tool()
    async def create_port_profile(
        name: str,
        native_networkconf_id: str = "",
        forward: str = "all",
        poe_mode: str = "auto",
        tagged_networkconf_ids: list[str] | None = None,
    ) -> str:
        """Create a new switch port profile.

        Port profiles define how a switch port behaves: which VLAN is native,
        which are tagged, whether PoE is on, and how traffic is forwarded.

        Args:
            name: Display name for the profile.
            native_networkconf_id: ``_id`` of the native (untagged) network.
                Empty for trunk ports.
            forward: ``"all"`` (default), ``"native"``, ``"customize"``, or
                ``"disabled"``.
            poe_mode: ``"auto"`` (default), ``"passive24v"``, ``"passthrough"``,
                or ``"off"``.
            tagged_networkconf_ids: Optional list of network ``_id``s carried as
                tagged VLANs.

        Returns:
            JSON of the created profile (with assigned ``_id``).
        """
        payload: dict[str, Any] = {
            "name": name,
            "forward": forward,
            "poe_mode": poe_mode,
        }
        if native_networkconf_id:
            payload["native_networkconf_id"] = native_networkconf_id
        if tagged_networkconf_ids:
            payload["tagged_networkconf_ids"] = tagged_networkconf_ids
        try:
            if settings.stub_mode:
                return _format(state.create_port_profile(payload))
            assert client is not None
            return _format(await client.create_port_profile(payload))
        except UniFiError as exc:
            logger.exception("create_port_profile failed", extra={"profile_name": name})
            return err(str(exc))

    @mcp.tool()
    async def update_port_profile(profile_id: str, updates: dict[str, Any]) -> str:
        """Update fields on an existing port profile.

        Args:
            profile_id: The ``_id`` from ``list_port_profiles``.
            updates: Partial profile record. Common keys: ``name``, ``forward``,
                ``poe_mode``, ``native_networkconf_id``, ``tagged_networkconf_ids``.

        Returns:
            JSON of the updated profile, or an error if not found.
        """
        try:
            if settings.stub_mode:
                updated = state.update_port_profile(profile_id, updates)
                if updated is None:
                    return err(f"port profile {profile_id} not found")
                return _format(updated)
            assert client is not None
            return _format(await client.update_port_profile(profile_id, updates))
        except UniFiError as exc:
            logger.exception("update_port_profile failed", extra={"profile_id": profile_id})
            return err(str(exc))

    @mcp.tool()
    async def delete_port_profile(profile_id: str) -> str:
        """Delete a switch port profile.

        Args:
            profile_id: The ``_id`` from ``list_port_profiles``. The controller
                will reject the delete if any switch port still references the
                profile.

        Returns:
            JSON ``{"deleted": true, "profile_id": "..."}`` on success.
        """
        try:
            if settings.stub_mode:
                ok = state.delete_port_profile(profile_id)
                return _format({"deleted": ok, "profile_id": profile_id})
            assert client is not None
            await client.delete_port_profile(profile_id)
            return _format({"deleted": True, "profile_id": profile_id})
        except UniFiError as exc:
            logger.exception("delete_port_profile failed", extra={"profile_id": profile_id})
            return err(str(exc))

    @mcp.tool()
    async def list_clients() -> str:
        """List currently active wireless and wired clients on the gateway.

        Returns the same data the controller's Insights → Clients view shows:
        MAC, hostname, IP, network, signal/satisfaction (wireless only), AP
        or switch port (when wired), and uptime/last_seen timestamps.

        Returns:
            JSON list of client records. Empty list if no clients are
            connected.
        """
        try:
            if settings.stub_mode:
                return _format(state.list_clients())
            assert client is not None
            return _format(await client.list_clients())
        except UniFiError as exc:
            logger.exception("list_clients failed")
            return err(str(exc))

    # ------------------------------------------------------------------
    # Tier 2 — high-frequency client and device ops
    # ------------------------------------------------------------------

    @mcp.tool()
    async def block_client(mac: str) -> str:
        """Block a client by MAC. The client cannot rejoin until unblocked.

        Args:
            mac: Client MAC address (e.g. ``"aa:bb:cc:00:00:01"``).

        Returns:
            JSON of the blocked client record, or an error if not found.
        """
        try:
            if settings.stub_mode:
                blocked = state.block_client(mac)
                if blocked is None:
                    return err(f"client {mac} not found")
                return _format(blocked)
            assert client is not None
            return _format(await client.block_client(mac))
        except UniFiError as exc:
            logger.exception("block_client failed", extra={"mac": mac})
            return err(str(exc))

    @mcp.tool()
    async def unblock_client(mac: str) -> str:
        """Unblock a previously-blocked client by MAC.

        Args:
            mac: Client MAC address.

        Returns:
            JSON of the unblocked client record, or an error if not found.
        """
        try:
            if settings.stub_mode:
                unblocked = state.unblock_client(mac)
                if unblocked is None:
                    return err(f"client {mac} not found")
                return _format(unblocked)
            assert client is not None
            return _format(await client.unblock_client(mac))
        except UniFiError as exc:
            logger.exception("unblock_client failed", extra={"mac": mac})
            return err(str(exc))

    @mcp.tool()
    async def reconnect_client(mac: str) -> str:
        """Force a client to reconnect (kick-sta).

        Useful for fixing a stuck client without having to power-cycle it.

        Args:
            mac: Client MAC address.

        Returns:
            JSON ``{"reconnected": true, "mac": "..."}`` on success.
        """
        try:
            if settings.stub_mode:
                ok = state.reconnect_client(mac)
                return _format({"reconnected": ok, "mac": mac})
            assert client is not None
            await client.reconnect_client(mac)
            return _format({"reconnected": True, "mac": mac})
        except UniFiError as exc:
            logger.exception("reconnect_client failed", extra={"mac": mac})
            return err(str(exc))

    @mcp.tool()
    async def restart_device(mac: str) -> str:
        """Restart an adopted UniFi device (gateway, AP, or switch).

        Args:
            mac: Device MAC address (from ``list_devices``).

        Returns:
            JSON ``{"restarted": true, "mac": "..."}`` on success.
        """
        try:
            if settings.stub_mode:
                ok = state.restart_device(mac)
                if not ok:
                    return err(f"device {mac} not found")
                return _format({"restarted": True, "mac": mac})
            assert client is not None
            await client.restart_device(mac)
            return _format({"restarted": True, "mac": mac})
        except UniFiError as exc:
            logger.exception("restart_device failed", extra={"mac": mac})
            return err(str(exc))

    @mcp.tool()
    async def locate_device(mac: str, on: bool = True) -> str:
        """Toggle the LED locate beacon on a device.

        Helpful for finding which physical AP or switch maps to a record in the
        controller.

        Args:
            mac: Device MAC address.
            on: ``True`` (default) flashes the LED; ``False`` stops the flash.

        Returns:
            JSON ``{"locating": bool, "mac": "..."}`` on success.
        """
        try:
            if settings.stub_mode:
                ok = state.locate_device(mac, on)
                if not ok:
                    return err(f"device {mac} not found")
                return _format({"locating": on, "mac": mac})
            assert client is not None
            await client.locate_device(mac, on)
            return _format({"locating": on, "mac": mac})
        except UniFiError as exc:
            logger.exception("locate_device failed", extra={"mac": mac})
            return err(str(exc))

    @mcp.tool()
    async def set_port_state(
        device_mac: str,
        port_idx: int,
        enable: bool | None = None,
        poe_mode: str = "",
        portconf_id: str = "",
    ) -> str:
        """Override settings on a single switch port.

        UniFi switches store per-port overrides on the device record. This tool
        modifies one port's ``enable``, ``poe_mode``, and/or ``portconf_id``
        without touching the others.

        Args:
            device_mac: Switch MAC address (from ``list_devices``).
            port_idx: 1-based port index.
            enable: ``True`` to bring the port up, ``False`` to disable. Pass
                ``None`` (the default) to leave it unchanged.
            poe_mode: ``"auto"``, ``"passive24v"``, ``"passthrough"``, ``"off"``,
                or empty to leave unchanged.
            portconf_id: ``_id`` of a port profile to apply, or empty to leave
                unchanged.

        Returns:
            JSON of the updated port record, or an error if device/port not found.
        """
        if enable is None and not poe_mode and not portconf_id:
            return err("set_port_state requires at least one of enable, poe_mode, portconf_id")
        try:
            if settings.stub_mode:
                updated = state.set_port_state(
                    device_mac,
                    port_idx,
                    enable=enable,
                    poe_mode=poe_mode or None,
                    portconf_id=portconf_id or None,
                )
                if updated is None:
                    return err(f"device {device_mac} or port {port_idx} not found")
                return _format(updated)

            assert client is not None
            # Real mode: read the device, merge overrides, PUT back.
            device = state.find_device_by_mac(device_mac) if settings.stub_mode else None
            # In real mode we have to look up the device id from /stat/device.
            devices = await client.list_devices()
            target = next((d for d in devices if d.get("mac") == device_mac), device)
            if target is None:
                return err(f"device {device_mac} not found")
            device_id = target.get("_id")
            if not device_id:
                return err(f"device {device_mac} has no _id")
            existing = list(target.get("port_overrides") or [])
            override: dict[str, Any] = {"port_idx": port_idx}
            if enable is not None:
                override["enable"] = enable
            if poe_mode:
                override["poe_mode"] = poe_mode
            if portconf_id:
                override["portconf_id"] = portconf_id
            # Replace any existing override for this port_idx.
            existing = [o for o in existing if o.get("port_idx") != port_idx]
            existing.append(override)
            return _format(await client.set_port_state(device_id, existing))
        except UniFiError as exc:
            logger.exception(
                "set_port_state failed",
                extra={"mac": device_mac, "port_idx": port_idx},
            )
            return err(str(exc))

    # ------------------------------------------------------------------
    # Tier 2 — static DHCP leases
    # ------------------------------------------------------------------

    @mcp.tool()
    async def list_dhcp_leases() -> str:
        """List static DHCP reservations on the gateway.

        UniFi stores fixed leases on the user object with ``use_fixedip=true``.
        This returns just those entries.

        Returns:
            JSON list of lease records: ``_id``, ``mac``, ``name``,
            ``hostname``, ``fixed_ip``, ``network_id``.
        """
        try:
            if settings.stub_mode:
                return _format(state.list_dhcp_leases())
            assert client is not None
            return _format(await client.list_dhcp_leases())
        except UniFiError as exc:
            logger.exception("list_dhcp_leases failed")
            return err(str(exc))

    @mcp.tool()
    async def create_static_dhcp_lease(
        mac: str,
        ip: str,
        network_id: str,
        name: str = "",
        hostname: str = "",
    ) -> str:
        """Reserve a fixed IP for a client.

        Args:
            mac: Client MAC address.
            ip: IPv4 address to reserve. Must fall inside the network's subnet.
            network_id: ``_id`` of the network/VLAN this client lives on.
            name: Friendly display name (optional).
            hostname: DHCP hostname (optional).

        Returns:
            JSON of the created reservation.
        """
        payload: dict[str, Any] = {
            "mac": mac,
            "use_fixedip": True,
            "fixed_ip": ip,
            "network_id": network_id,
        }
        if name:
            payload["name"] = name
        if hostname:
            payload["hostname"] = hostname
        try:
            if settings.stub_mode:
                return _format(state.create_dhcp_lease(payload))
            assert client is not None
            return _format(await client.create_dhcp_lease(payload))
        except UniFiError as exc:
            logger.exception("create_static_dhcp_lease failed", extra={"mac": mac})
            return err(str(exc))

    @mcp.tool()
    async def delete_static_dhcp_lease(lease_id: str) -> str:
        """Delete a static DHCP reservation.

        Args:
            lease_id: The ``_id`` from ``list_dhcp_leases``.

        Returns:
            JSON ``{"deleted": true, "lease_id": "..."}``.
        """
        try:
            if settings.stub_mode:
                ok = state.delete_dhcp_lease(lease_id)
                return _format({"deleted": ok, "lease_id": lease_id})
            assert client is not None
            await client.delete_dhcp_lease(lease_id)
            return _format({"deleted": True, "lease_id": lease_id})
        except UniFiError as exc:
            logger.exception("delete_static_dhcp_lease failed", extra={"lease_id": lease_id})
            return err(str(exc))

    # ------------------------------------------------------------------
    # Tier 2 — port forwarding (CRUD)
    # ------------------------------------------------------------------

    @mcp.tool()
    async def list_port_forwards() -> str:
        """List all port-forward (DNAT) rules.

        Returns:
            JSON list of records: ``_id``, ``name``, ``enabled``, ``proto``,
            ``src``, ``fwd``, ``fwd_port``, ``dst_port``.
        """
        try:
            if settings.stub_mode:
                return _format(state.list_port_forwards())
            assert client is not None
            return _format(await client.list_port_forwards())
        except UniFiError as exc:
            logger.exception("list_port_forwards failed")
            return err(str(exc))

    @mcp.tool()
    async def create_port_forward(
        name: str,
        fwd: str,
        fwd_port: str,
        dst_port: str,
        proto: str = "tcp",
        src: str = "any",
        enabled: bool = True,
        log: bool = False,
    ) -> str:
        """Create a port-forward (DNAT) rule.

        Args:
            name: Display name.
            fwd: Internal IP to forward to.
            fwd_port: Internal port (string; UniFi accepts ranges like
                ``"8000-8010"``).
            dst_port: External / WAN port to listen on.
            proto: ``"tcp"``, ``"udp"``, or ``"tcp_udp"``.
            src: Source restriction. ``"any"`` (default) or a CIDR.
            enabled: ``True`` to enable immediately.
            log: ``True`` to log forwarded packets.

        Returns:
            JSON of the created rule.
        """
        payload: dict[str, Any] = {
            "name": name,
            "fwd": fwd,
            "fwd_port": fwd_port,
            "dst_port": dst_port,
            "proto": proto,
            "src": src,
            "enabled": enabled,
            "log": log,
        }
        try:
            if settings.stub_mode:
                return _format(state.create_port_forward(payload))
            assert client is not None
            return _format(await client.create_port_forward(payload))
        except UniFiError as exc:
            logger.exception("create_port_forward failed", extra={"forward_name": name})
            return err(str(exc))

    @mcp.tool()
    async def update_port_forward(forward_id: str, updates: dict[str, Any]) -> str:
        """Update a port-forward rule.

        Args:
            forward_id: The ``_id`` from ``list_port_forwards``.
            updates: Partial record. Common keys: ``enabled``, ``fwd_port``,
                ``dst_port``, ``proto``, ``src``, ``fwd``, ``name``.

        Returns:
            JSON of the updated rule, or an error if not found.
        """
        try:
            if settings.stub_mode:
                updated = state.update_port_forward(forward_id, updates)
                if updated is None:
                    return err(f"port forward {forward_id} not found")
                return _format(updated)
            assert client is not None
            return _format(await client.update_port_forward(forward_id, updates))
        except UniFiError as exc:
            logger.exception("update_port_forward failed", extra={"forward_id": forward_id})
            return err(str(exc))

    @mcp.tool()
    async def delete_port_forward(forward_id: str) -> str:
        """Delete a port-forward rule.

        Args:
            forward_id: The ``_id`` from ``list_port_forwards``.

        Returns:
            JSON ``{"deleted": true, "forward_id": "..."}``.
        """
        try:
            if settings.stub_mode:
                ok = state.delete_port_forward(forward_id)
                return _format({"deleted": ok, "forward_id": forward_id})
            assert client is not None
            await client.delete_port_forward(forward_id)
            return _format({"deleted": True, "forward_id": forward_id})
        except UniFiError as exc:
            logger.exception("delete_port_forward failed", extra={"forward_id": forward_id})
            return err(str(exc))

    # ------------------------------------------------------------------
    # Tier 3 — observability
    # ------------------------------------------------------------------

    @mcp.tool()
    async def get_site_health() -> str:
        """Per-subsystem health (wan, lan, wlan, www, vpn).

        Returns:
            JSON list with one record per subsystem: ``subsystem``, ``status``,
            and subsystem-specific metrics (e.g. WAN throughput, LAN client
            counts).
        """
        try:
            if settings.stub_mode:
                return _format(state.get_site_health())
            assert client is not None
            return _format(await client.get_site_health())
        except UniFiError as exc:
            logger.exception("get_site_health failed")
            return err(str(exc))

    @mcp.tool()
    async def get_wan_status() -> str:
        """Current WAN status: link state, ISP, public IP, throughput, latency.

        Convenience wrapper around ``get_site_health`` that returns just the
        WAN subsystem record.

        Returns:
            JSON object for the WAN subsystem, or ``{"subsystem": "wan",
            "status": "unknown"}`` if not reported.
        """
        try:
            if settings.stub_mode:
                return _format(state.get_wan_status())
            assert client is not None
            health = await client.get_site_health()
            for h in health:
                if isinstance(h, dict) and h.get("subsystem") == "wan":
                    return _format(h)
            return _format({"subsystem": "wan", "status": "unknown"})
        except UniFiError as exc:
            logger.exception("get_wan_status failed")
            return err(str(exc))

    @mcp.tool()
    async def list_events(limit: int = 50) -> str:
        """List recent controller events (connections, disconnections, etc.).

        Args:
            limit: Max number of events to return (default 50, max 1000).

        Returns:
            JSON list of event records.
        """
        if not 1 <= limit <= 1000:
            return err("limit must be between 1 and 1000")
        try:
            if settings.stub_mode:
                return _format(state.list_events(limit))
            assert client is not None
            return _format(await client.list_events(limit))
        except UniFiError as exc:
            logger.exception("list_events failed")
            return err(str(exc))

    @mcp.tool()
    async def list_alarms(limit: int = 50, archived: bool = False) -> str:
        """List controller alarms.

        Args:
            limit: Max number of alarms to return (default 50, max 1000).
            archived: ``True`` to list dismissed/archived alarms; ``False``
                (default) for active alarms only.

        Returns:
            JSON list of alarm records.
        """
        if not 1 <= limit <= 1000:
            return err("limit must be between 1 and 1000")
        try:
            if settings.stub_mode:
                return _format(state.list_alarms(limit, archived))
            assert client is not None
            return _format(await client.list_alarms(limit, archived))
        except UniFiError as exc:
            logger.exception("list_alarms failed")
            return err(str(exc))

    @mcp.tool()
    async def trigger_speedtest() -> str:
        """Kick off a UniFi speed test on the WAN link.

        The test runs server-side; this returns when the controller acks the
        command. Use ``get_speedtest_results`` to read the results once the
        test finishes (typically 30-60 seconds).

        Returns:
            JSON of the controller's response.
        """
        try:
            if settings.stub_mode:
                return _format(state.trigger_speedtest())
            assert client is not None
            return _format(await client.trigger_speedtest())
        except UniFiError as exc:
            logger.exception("trigger_speedtest failed")
            return err(str(exc))

    @mcp.tool()
    async def get_speedtest_results(limit: int = 10) -> str:
        """Return recent speed-test results, newest first.

        Args:
            limit: Max number of results to return (default 10).

        Returns:
            JSON list of speed-test records: ``time``, ``xput_up``,
            ``xput_download``, ``latency``, ``server``.
        """
        if not 1 <= limit <= 1000:
            return err("limit must be between 1 and 1000")
        try:
            if settings.stub_mode:
                return _format(state.get_speedtest_results(limit))
            assert client is not None
            return _format(await client.get_speedtest_results(limit))
        except UniFiError as exc:
            logger.exception("get_speedtest_results failed")
            return err(str(exc))

    @mcp.tool()
    async def list_top_talkers(limit: int = 10) -> str:
        """Top clients by total bytes (DPI by-station report).

        Returns:
            JSON list ranked by ``total_bytes`` descending: ``mac``,
            ``hostname``, ``ip``, ``tx_bytes``, ``rx_bytes``, ``total_bytes``.
        """
        if not 1 <= limit <= 1000:
            return err("limit must be between 1 and 1000")
        try:
            if settings.stub_mode:
                return _format(state.top_talkers(limit))
            assert client is not None
            return _format(await client.list_top_talkers(limit))
        except UniFiError as exc:
            logger.exception("list_top_talkers failed")
            return err(str(exc))

    @mcp.tool()
    async def create_iot_network(
        name: str,
        vlan_id: int,
        passphrase: str,
        main_lan_subnet: str = "192.168.1.0/24",
        subnet: str = "",
        isolate: bool = True,
        hide_ssid: bool = False,
    ) -> str:
        """One-shot IoT network: VLAN + matching SSID + isolation firewall rule.

        Wraps three calls into a single safe operation. Defaults give you a
        fully isolated subnet at ``10.0.<vlan_id>.0/24`` with a WPA2 SSID of
        the same name and a LAN_IN drop rule preventing the IoT subnet from
        reaching your main LAN.

        On partial failure the tool **rolls back** any resources it created
        before the failing step. The response surfaces what was rolled back so
        you can re-run the call with confidence.

        Args:
            name: Used for both the network name and the SSID.
            vlan_id: 802.1Q VLAN ID, 2-4094. Also drives the default subnet.
            passphrase: WPA2 PSK for the IoT SSID (8-63 chars).
            main_lan_subnet: CIDR of your main/trusted LAN. The isolation rule
                blocks IoT → this subnet. Defaults to ``"192.168.1.0/24"``.
            subnet: Override the IoT subnet. Empty uses the
                ``IOT_SUBNET_TEMPLATE`` env var (default
                ``10.0.{vlan_id}.0/24``).
            isolate: If True (default), create a LAN_IN drop rule from the
                IoT subnet to the main LAN. Set False if you actually want
                IoT devices to reach the main LAN (rare).
            hide_ssid: If True, the IoT SSID is hidden.

        Returns:
            JSON with three keys: ``network``, ``wlan``, ``firewall_rule``.
            Each is the created object. On failure the response includes
            ``error``, the partial state at failure time, and a
            ``rolled_back`` list of what was cleaned up.
        """
        if not 2 <= vlan_id <= 4094:
            return err(f"vlan_id {vlan_id} out of range (2-4094)")

        iot_subnet = subnet or settings.iot_subnet_template.format(vlan_id=vlan_id)
        _, dhcp_start, dhcp_stop = _subnet_to_dhcp(
            iot_subnet,
            settings.iot_dhcp_start_offset,
            settings.iot_dhcp_stop_offset,
        )

        created: dict[str, Any] = {
            "network": None,
            "wlan": None,
            "firewall_rule": None,
        }

        async def _rollback(failed_step: str) -> list[dict[str, Any]]:
            """Tear down anything created so far. Returns per-step results."""
            actions: list[dict[str, Any]] = []
            # Reverse order: firewall, then WLAN, then network.
            if created["firewall_rule"] and (fw_id := created["firewall_rule"].get("_id")):
                ok = await _delete("firewall_rule", fw_id)
                actions.append({"firewall_rule": fw_id, "deleted": ok})
            if created["wlan"] and (wlan_id := created["wlan"].get("_id")):
                ok = await _delete("wlan", wlan_id)
                actions.append({"wlan": wlan_id, "deleted": ok})
            if created["network"] and (net_id := created["network"].get("_id")):
                ok = await _delete("network", net_id)
                actions.append({"network": net_id, "deleted": ok})
            logger.warning(
                "create_iot_network rolled back",
                extra={"failed_step": failed_step, "rolled_back": actions},
            )
            return actions

        async def _delete(kind: str, resource_id: str) -> bool:
            """Best-effort cleanup. Logs but does not raise on failure."""
            try:
                if settings.stub_mode:
                    if kind == "network":
                        return state.delete_network(resource_id)
                    if kind == "wlan":
                        return state.delete_wlan(resource_id)
                    if kind == "firewall_rule":
                        return state.delete_firewall_rule(resource_id)
                    return False
                assert client is not None
                if kind == "network":
                    return await client.delete_network(resource_id)
                if kind == "wlan":
                    return await client.delete_wlan(resource_id)
                if kind == "firewall_rule":
                    return await client.delete_firewall_rule(resource_id)
                return False
            except UniFiError as exc:
                logger.error(
                    "rollback delete failed",
                    extra={"kind": kind, "resource_id": resource_id, "error": str(exc)},
                )
                return False

        async def _fail(step: str, exc: Exception) -> str:
            rolled_back = await _rollback(step)
            return _format(
                {
                    "error": f"create_iot_network failed at {step}: {exc}",
                    "stub_mode": settings.stub_mode,
                    "partial": created,
                    "rolled_back": rolled_back,
                }
            )

        # Step 1: VLAN ----------------------------------------------------
        net_payload: dict[str, Any] = {
            "name": name,
            "purpose": "corporate",
            "vlan_enabled": True,
            "vlan": vlan_id,
            "ip_subnet": iot_subnet,
            "dhcpd_enabled": True,
            "dhcpd_start": dhcp_start,
            "dhcpd_stop": dhcp_stop,
            "enabled": True,
        }
        try:
            if settings.stub_mode:
                created["network"] = state.create_network(net_payload)
            else:
                assert client is not None
                created["network"] = await client.create_network(net_payload)
        except UniFiError as exc:
            logger.exception("create_iot_network: VLAN step failed")
            return await _fail("vlan", exc)

        net_id = (created["network"] or {}).get("_id")
        if not net_id:
            return await _fail("vlan", UniFiError("VLAN created but no _id returned"))

        # Step 2: SSID ----------------------------------------------------
        wlan_payload: dict[str, Any] = {
            "name": name,
            "enabled": True,
            "security": "wpapsk",
            "wpa_mode": "wpa2",
            "x_passphrase": passphrase,
            "networkconf_id": net_id,
            "is_guest": False,
            "hide_ssid": hide_ssid,
            "wlan_band": "both",
        }
        try:
            if settings.stub_mode:
                created["wlan"] = state.create_wlan(wlan_payload)
            else:
                assert client is not None
                created["wlan"] = await client.create_wlan(wlan_payload)
        except UniFiError as exc:
            logger.exception("create_iot_network: WLAN step failed")
            return await _fail("wlan", exc)

        # Step 3: isolation rule (optional) -------------------------------
        if isolate:
            fw_payload: dict[str, Any] = {
                "name": f"Block {name} -> Main LAN",
                "ruleset": "LAN_IN",
                "rule_index": 2000 + vlan_id,
                "action": "drop",
                "protocol": "all",
                "enabled": True,
                "src_address": iot_subnet,
                "dst_address": main_lan_subnet,
            }
            try:
                if settings.stub_mode:
                    created["firewall_rule"] = state.create_firewall_rule(fw_payload)
                else:
                    assert client is not None
                    created["firewall_rule"] = await client.create_firewall_rule(fw_payload)
            except UniFiError as exc:
                logger.exception("create_iot_network: firewall step failed")
                return await _fail("firewall_rule", exc)

        return _format(
            {
                "summary": (
                    f"IoT network '{name}' (VLAN {vlan_id}) on {iot_subnet}"
                    f"{' with isolation' if isolate else ''}"
                ),
                **created,
            }
        )

    # ------------------------------------------------------------------
    # Tier 4 — composite operations
    # ------------------------------------------------------------------

    async def _delete_resource(kind: str, resource_id: str) -> bool:
        """Best-effort cleanup helper shared by the composites."""
        try:
            if settings.stub_mode:
                if kind == "network":
                    return state.delete_network(resource_id)
                if kind == "wlan":
                    return state.delete_wlan(resource_id)
                if kind == "firewall_rule":
                    return state.delete_firewall_rule(resource_id)
                if kind == "dhcp_lease":
                    return state.delete_dhcp_lease(resource_id)
                if kind == "port_forward":
                    return state.delete_port_forward(resource_id)
                return False
            assert client is not None
            if kind == "network":
                return await client.delete_network(resource_id)
            if kind == "wlan":
                return await client.delete_wlan(resource_id)
            if kind == "firewall_rule":
                return await client.delete_firewall_rule(resource_id)
            if kind == "dhcp_lease":
                return await client.delete_dhcp_lease(resource_id)
            if kind == "port_forward":
                return await client.delete_port_forward(resource_id)
            return False
        except UniFiError as exc:
            logger.error(
                "rollback delete failed",
                extra={"kind": kind, "resource_id": resource_id, "error": str(exc)},
            )
            return False

    @mcp.tool()
    async def provision_homelab_service(
        name: str,
        mac: str,
        ip: str,
        network_id: str,
        ports: list[int] | None = None,
        wan_expose: bool = False,
    ) -> str:
        """Stand up a homelab service end-to-end: lease + firewall allow + (optional) port forwards.

        Creates a static DHCP reservation for ``mac`` at ``ip``, an
        ``accept`` LAN_LOCAL firewall rule pinned to that IP for the requested
        ports, and (when ``wan_expose=True``) one port-forward rule per port.
        On any partial failure the tool **rolls back** what it created so far,
        in reverse order.

        Args:
            name: Display name (used for both the lease and the firewall rule).
            mac: Client MAC address.
            ip: IPv4 address to reserve.
            network_id: ``_id`` of the network/VLAN this service lives on.
            ports: TCP ports the service listens on (e.g. ``[80, 443]``). Empty
                list creates only the lease.
            wan_expose: If ``True``, also create port-forward rules so the
                service is reachable from the WAN. Default ``False`` (LAN-only).

        Returns:
            JSON with keys ``lease``, ``firewall_rule``, ``port_forwards``
            (list). On failure the response includes ``error``, ``partial``
            (what was created), and ``rolled_back`` (cleanup actions).
        """
        ports = ports or []
        created: dict[str, Any] = {
            "lease": None,
            "firewall_rule": None,
            "port_forwards": [],
        }

        async def _rollback(failed_step: str) -> list[dict[str, Any]]:
            actions: list[dict[str, Any]] = []
            for pf in reversed(created["port_forwards"]):
                pf_id = pf.get("_id")
                if pf_id:
                    ok = await _delete_resource("port_forward", pf_id)
                    actions.append({"port_forward": pf_id, "deleted": ok})
            if created["firewall_rule"] and (fw_id := created["firewall_rule"].get("_id")):
                ok = await _delete_resource("firewall_rule", fw_id)
                actions.append({"firewall_rule": fw_id, "deleted": ok})
            if created["lease"] and (lease_id := created["lease"].get("_id")):
                ok = await _delete_resource("dhcp_lease", lease_id)
                actions.append({"dhcp_lease": lease_id, "deleted": ok})
            logger.warning(
                "provision_homelab_service rolled back",
                extra={"failed_step": failed_step, "rolled_back": actions},
            )
            return actions

        async def _fail(step: str, exc: Exception) -> str:
            rolled_back = await _rollback(step)
            return _format(
                {
                    "error": f"provision_homelab_service failed at {step}: {exc}",
                    "stub_mode": settings.stub_mode,
                    "partial": created,
                    "rolled_back": rolled_back,
                }
            )

        # Step 1: lease
        lease_payload: dict[str, Any] = {
            "mac": mac,
            "use_fixedip": True,
            "fixed_ip": ip,
            "network_id": network_id,
            "name": name,
        }
        try:
            if settings.stub_mode:
                created["lease"] = state.create_dhcp_lease(lease_payload)
            else:
                assert client is not None
                created["lease"] = await client.create_dhcp_lease(lease_payload)
        except UniFiError as exc:
            return await _fail("lease", exc)

        # Step 2: firewall allow rule (LAN_LOCAL accept to the service IP)
        if ports:
            fw_payload: dict[str, Any] = {
                "name": f"Allow {name}",
                "ruleset": "LAN_LOCAL",
                "rule_index": 2400,
                "action": "accept",
                "protocol": "tcp",
                "enabled": True,
                "dst_address": f"{ip}/32",
                "dst_port": ",".join(str(p) for p in ports),
            }
            try:
                if settings.stub_mode:
                    created["firewall_rule"] = state.create_firewall_rule(fw_payload)
                else:
                    assert client is not None
                    created["firewall_rule"] = await client.create_firewall_rule(fw_payload)
            except UniFiError as exc:
                return await _fail("firewall_rule", exc)

        # Step 3: port forwards (optional)
        if wan_expose and ports:
            for port in ports:
                pf_payload: dict[str, Any] = {
                    "name": f"{name} :{port}",
                    "fwd": ip,
                    "fwd_port": str(port),
                    "dst_port": str(port),
                    "proto": "tcp",
                    "src": "any",
                    "enabled": True,
                    "log": False,
                }
                try:
                    if settings.stub_mode:
                        created["port_forwards"].append(state.create_port_forward(pf_payload))
                    else:
                        assert client is not None
                        created["port_forwards"].append(
                            await client.create_port_forward(pf_payload)
                        )
                except UniFiError as exc:
                    return await _fail("port_forward", exc)

        return _format(
            {
                "summary": (
                    f"Provisioned '{name}' at {ip}"
                    + (f" with {len(ports)} port(s)" if ports else "")
                    + (" (WAN-exposed)" if wan_expose and ports else "")
                ),
                **created,
            }
        )

    @mcp.tool()
    async def quarantine_client(mac: str, reason: str = "") -> str:
        """Block a client and log the action with a reason.

        Equivalent to ``block_client`` but appends a structured audit log
        entry. The reason flows into structured logs for later forensics.

        Args:
            mac: Client MAC address.
            reason: Free-form justification (kept in logs only).

        Returns:
            JSON ``{"quarantined": true, "mac": "...", "reason": "..."}``, or
            an error if the client is not found.
        """
        try:
            if settings.stub_mode:
                blocked = state.block_client(mac)
                if blocked is None:
                    return err(f"client {mac} not found")
            else:
                assert client is not None
                await client.block_client(mac)
            logger.warning(
                "client quarantined",
                extra={"mac": mac, "reason": reason or "(none provided)"},
            )
            return _format({"quarantined": True, "mac": mac, "reason": reason})
        except UniFiError as exc:
            logger.exception("quarantine_client failed", extra={"mac": mac})
            return err(str(exc))

    @mcp.tool()
    async def create_guest_network(
        name: str,
        ssid: str,
        passphrase: str,
        vlan_id: int,
        main_lan_subnet: str = "192.168.1.0/24",
        subnet: str = "",
        schedule: str = "",
        hide_ssid: bool = False,
    ) -> str:
        """One-shot guest network: VLAN + guest SSID + LAN_IN drop rule.

        Like ``create_iot_network`` but provisions a *guest* SSID (client
        isolation enabled by default) and supports an optional schedule string
        echoed back in the SSID record.

        Args:
            name: Display name for the network record.
            ssid: SSID to broadcast.
            passphrase: WPA2 PSK (8-63 chars).
            vlan_id: 802.1Q VLAN ID, 2-4094.
            main_lan_subnet: CIDR of your main LAN. The drop rule blocks
                guest → this subnet.
            subnet: Override the guest subnet. Empty uses the IoT subnet
                template (``10.0.<vlan>.0/24`` by default).
            schedule: Optional schedule descriptor (controller field
                ``schedule``). Empty = always on.
            hide_ssid: ``True`` to suppress SSID broadcast (rare for guest).

        Returns:
            JSON with ``network``, ``wlan``, ``firewall_rule``. Rolls back on
            partial failure (firewall → WLAN → VLAN).
        """
        if not 2 <= vlan_id <= 4094:
            return err(f"vlan_id {vlan_id} out of range (2-4094)")

        guest_subnet = subnet or settings.iot_subnet_template.format(vlan_id=vlan_id)
        _, dhcp_start, dhcp_stop = _subnet_to_dhcp(
            guest_subnet,
            settings.iot_dhcp_start_offset,
            settings.iot_dhcp_stop_offset,
        )

        created: dict[str, Any] = {
            "network": None,
            "wlan": None,
            "firewall_rule": None,
        }

        async def _rollback(failed_step: str) -> list[dict[str, Any]]:
            actions: list[dict[str, Any]] = []
            if created["firewall_rule"] and (fw_id := created["firewall_rule"].get("_id")):
                ok = await _delete_resource("firewall_rule", fw_id)
                actions.append({"firewall_rule": fw_id, "deleted": ok})
            if created["wlan"] and (wlan_id := created["wlan"].get("_id")):
                ok = await _delete_resource("wlan", wlan_id)
                actions.append({"wlan": wlan_id, "deleted": ok})
            if created["network"] and (net_id := created["network"].get("_id")):
                ok = await _delete_resource("network", net_id)
                actions.append({"network": net_id, "deleted": ok})
            logger.warning(
                "create_guest_network rolled back",
                extra={"failed_step": failed_step, "rolled_back": actions},
            )
            return actions

        async def _fail(step: str, exc: Exception) -> str:
            rolled_back = await _rollback(step)
            return _format(
                {
                    "error": f"create_guest_network failed at {step}: {exc}",
                    "stub_mode": settings.stub_mode,
                    "partial": created,
                    "rolled_back": rolled_back,
                }
            )

        # VLAN — guest purpose
        net_payload: dict[str, Any] = {
            "name": name,
            "purpose": "guest",
            "vlan_enabled": True,
            "vlan": vlan_id,
            "ip_subnet": guest_subnet,
            "dhcpd_enabled": True,
            "dhcpd_start": dhcp_start,
            "dhcpd_stop": dhcp_stop,
            "enabled": True,
        }
        try:
            if settings.stub_mode:
                created["network"] = state.create_network(net_payload)
            else:
                assert client is not None
                created["network"] = await client.create_network(net_payload)
        except UniFiError as exc:
            return await _fail("vlan", exc)

        net_id = (created["network"] or {}).get("_id")
        if not net_id:
            return await _fail("vlan", UniFiError("VLAN created but no _id returned"))

        # Guest WLAN
        wlan_payload: dict[str, Any] = {
            "name": ssid,
            "enabled": True,
            "security": "wpapsk",
            "wpa_mode": "wpa2",
            "x_passphrase": passphrase,
            "networkconf_id": net_id,
            "is_guest": True,
            "hide_ssid": hide_ssid,
            "wlan_band": "both",
        }
        if schedule:
            wlan_payload["schedule"] = schedule
        try:
            if settings.stub_mode:
                created["wlan"] = state.create_wlan(wlan_payload)
            else:
                assert client is not None
                created["wlan"] = await client.create_wlan(wlan_payload)
        except UniFiError as exc:
            return await _fail("wlan", exc)

        # Isolation rule
        fw_payload: dict[str, Any] = {
            "name": f"Block {name} -> Main LAN",
            "ruleset": "LAN_IN",
            "rule_index": 2000 + vlan_id,
            "action": "drop",
            "protocol": "all",
            "enabled": True,
            "src_address": guest_subnet,
            "dst_address": main_lan_subnet,
        }
        try:
            if settings.stub_mode:
                created["firewall_rule"] = state.create_firewall_rule(fw_payload)
            else:
                assert client is not None
                created["firewall_rule"] = await client.create_firewall_rule(fw_payload)
        except UniFiError as exc:
            return await _fail("firewall_rule", exc)

        return _format(
            {
                "summary": (
                    f"Guest network '{name}' (VLAN {vlan_id}) on {guest_subnet}"
                    f"{' with schedule' if schedule else ''}"
                ),
                **created,
            }
        )

    @mcp.tool()
    async def audit_open_ports() -> str:
        """Read-only audit of WAN-facing exposure.

        Cross-references firewall rules and port forwards to summarise:
        - Active port forwards (DNAT into the LAN).
        - WAN_IN ``accept`` rules (anything reachable from the internet).

        No writes, no rollback. Useful as a "did I leave something open?"
        sanity check.

        Returns:
            JSON ``{"port_forwards": [...], "wan_accept_rules": [...],
            "summary": "..."}``.
        """
        try:
            if settings.stub_mode:
                fw_rules = state.list_firewall_rules()
                port_forwards = state.list_port_forwards()
            else:
                assert client is not None
                fw_rules = await client.list_firewall_rules()
                port_forwards = await client.list_port_forwards()

            active_pfs = [pf for pf in port_forwards if pf.get("enabled", True)]
            wan_accept_rules = [
                r
                for r in fw_rules
                if isinstance(r, dict)
                and r.get("ruleset", "").startswith("WAN_")
                and r.get("action") == "accept"
                and r.get("enabled", True)
                and not (
                    # Filter out the boilerplate "accept established/related" rule
                    r.get("state_established") and r.get("state_related")
                )
            ]

            summary_parts: list[str] = []
            summary_parts.append(f"{len(active_pfs)} active port forward(s)")
            summary_parts.append(f"{len(wan_accept_rules)} WAN accept rule(s)")
            summary = "; ".join(summary_parts)

            return _format(
                {
                    "port_forwards": active_pfs,
                    "wan_accept_rules": wan_accept_rules,
                    "summary": summary,
                }
            )
        except UniFiError as exc:
            logger.exception("audit_open_ports failed")
            return err(str(exc))

    return mcp


# ---------------------------------------------------------------------------
# Module-level entrypoint
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entrypoint. Dispatches on MCP_TRANSPORT.

    - ``streamable-http`` (default): long-running container / multi-client.
    - ``stdio``: per-session subprocess (Claude Desktop, ``uvx mcp-unifi``).
    """
    settings = load_settings()
    configure_logging(level=settings.log_level, fmt=settings.log_format)
    logger.info("MCP UniFi starting", extra={"config": settings.safe_repr()})
    server = build_server(settings)

    if settings.mcp_transport == "stdio":
        # stdio transport owns stdout for the JSON-RPC framing. Logging is
        # already on stderr (see logging_setup.configure_logging).
        server.run(transport="stdio")
    else:
        server.run(
            transport="streamable-http",
            host=settings.mcp_host,
            port=settings.mcp_port,
        )


if __name__ == "__main__":
    main()
