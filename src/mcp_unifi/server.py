"""MCP UniFi — local-API gateway management for self-hosted UniFi.

Eleven tools covering devices, networks/VLANs, WLANs, firewall rules, switch
port profiles, and a higher-level :func:`create_iot_network` that provisions a
fully isolated IoT VLAN + SSID + firewall block in one call (with rollback on
partial failure).

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
    """Construct a FastMCP instance with all 11 tools wired up.

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

    return mcp


# ---------------------------------------------------------------------------
# Module-level entrypoint
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entrypoint used by the Docker image."""
    settings = load_settings()
    configure_logging(level=settings.log_level, fmt=settings.log_format)
    logger.info("MCP UniFi starting", extra={"config": settings.safe_repr()})
    server = build_server(settings)
    server.run(
        transport="streamable-http",
        host=settings.mcp_host,
        port=settings.mcp_port,
    )


if __name__ == "__main__":
    main()
