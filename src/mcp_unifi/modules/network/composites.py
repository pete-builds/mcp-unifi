"""Composite tools that wrap multiple primitives with rollback on failure.

- ``create_iot_network``: VLAN + WLAN + isolation rule, rolled back if any step fails.
- ``create_guest_network``: like IoT but with ``is_guest=True``.
- ``provision_homelab_service``: lease + firewall + (optional) port forwards.
- ``quarantine_client``: block + structured log entry.
- ``audit_open_ports``: read-only summary of WAN exposure.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from mcp_unifi.backends import Backend
from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules.network._common import format_json, make_err, subnet_to_dhcp

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.network.composites")

# Composite dry-runs surface placeholder IDs so the predicted graph reads
# as a complete shape. Real applies replace these with real ``_id`` strings
# returned by the controller.
DRY_RUN_NETWORK_ID = "<dry-run-network-id>"
DRY_RUN_WLAN_ID = "<dry-run-wlan-id>"
DRY_RUN_FIREWALL_ID = "<dry-run-firewall-rule-id>"
DRY_RUN_LEASE_ID = "<dry-run-dhcp-lease-id>"
DRY_RUN_PORT_FORWARD_ID = "<dry-run-port-forward-id>"


async def _delete_resource(backend: Backend, kind: str, resource_id: str) -> bool:
    """Best-effort cleanup helper shared by the composites."""
    try:
        if kind == "network":
            return await backend.delete_network(resource_id)
        if kind == "wlan":
            return await backend.delete_wlan(resource_id)
        if kind == "firewall_rule":
            return await backend.delete_firewall_rule(resource_id)
        if kind == "dhcp_lease":
            return await backend.delete_dhcp_lease(resource_id)
        if kind == "port_forward":
            return await backend.delete_port_forward(resource_id)
        return False
    except UniFiError as exc:
        logger.error(
            "rollback delete failed",
            extra={"kind": kind, "resource_id": resource_id, "error": str(exc)},
        )
        return False


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool()
    @audited("create_iot_network")
    async def create_iot_network(
        name: str,
        vlan_id: int,
        passphrase: str,
        main_lan_subnet: str = "192.168.1.0/24",
        subnet: str = "",
        isolate: bool = True,
        hide_ssid: bool = False,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Provision an isolated IoT network end-to-end: VLAN + SSID + drop rule.

        Side effects:
        - Step 1: creates a VLAN-tagged network at the given ``subnet`` (or
          ``10.0.<vlan_id>.0/24`` by default).
        - Step 2: creates a WPA2 WiFi SSID bound to the new network. Access
          points start broadcasting within seconds.
        - Step 3 (when ``isolate=True``): creates a LAN_IN drop rule blocking
          the IoT subnet from reaching ``main_lan_subnet``.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.
        - Rollback: if any sub-step fails, all prior sub-steps are reverted
          (firewall_rule → wlan → network) and the response includes
          ``rolled_back`` and ``partial`` keys.

        Example: create_iot_network(name="iot", vlan_id=50, passphrase="hunter2hunter2", main_lan_subnet="192.168.1.0/24")

        Args:
            name: Used for both the network name and the SSID (e.g. ``"iot"``).
            vlan_id: 802.1Q VLAN ID, 2-4094. Also drives the default subnet.
            passphrase: WPA2 PSK for the IoT SSID (8-63 chars).
            main_lan_subnet: CIDR of the main/trusted LAN. The isolation rule
                blocks IoT → this subnet. Defaults to ``"192.168.1.0/24"``.
            subnet: Override the IoT subnet. Empty uses
                ``IOT_SUBNET_TEMPLATE`` (default ``10.0.{vlan_id}.0/24``).
            isolate: ``True`` (default) creates the LAN_IN drop rule. ``False``
                lets IoT devices reach the main LAN (rare).
            hide_ssid: ``True`` suppresses SSID broadcast.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        if not 2 <= vlan_id <= 4094:
            return err(f"vlan_id {vlan_id} out of range (2-4094)")

        iot_subnet = subnet or settings.iot_subnet_template.format(vlan_id=vlan_id)
        _, dhcp_start, dhcp_stop = subnet_to_dhcp(
            iot_subnet,
            settings.iot_dhcp_start_offset,
            settings.iot_dhcp_stop_offset,
        )

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
        wlan_payload: dict[str, Any] = {
            "name": name,
            "enabled": True,
            "security": "wpapsk",
            "wpa_mode": "wpa2",
            "x_passphrase": passphrase,
            "networkconf_id": DRY_RUN_NETWORK_ID,
            "is_guest": False,
            "hide_ssid": hide_ssid,
            "wlan_band": "both",
        }
        fw_payload: dict[str, Any] | None = None
        if isolate:
            fw_payload = {
                "name": f"Block {name} -> Main LAN",
                "ruleset": "LAN_IN",
                "rule_index": 2000 + vlan_id,
                "action": "drop",
                "protocol": "all",
                "enabled": True,
                "src_address": iot_subnet,
                "dst_address": main_lan_subnet,
            }

        if dry_run:
            would_create: dict[str, Any] = {
                "network": net_payload,
                "wlan": wlan_payload,
            }
            if fw_payload is not None:
                would_create["firewall_rule"] = fw_payload
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_create": would_create,
                    "summary": (
                        f"Would create IoT network '{name}' (VLAN {vlan_id}) "
                        f"on {iot_subnet}"
                        f"{', SSID, and isolation rule' if isolate else ' and SSID'}"
                    ),
                    "note": (
                        "WLAN.networkconf_id and downstream IDs are placeholders; "
                        "the real apply substitutes the controller-assigned _id."
                    ),
                }
            )

        backend = registry.get(controller)
        created: dict[str, Any] = {
            "network": None,
            "wlan": None,
            "firewall_rule": None,
        }

        async def _rollback(failed_step: str) -> list[dict[str, Any]]:
            actions: list[dict[str, Any]] = []
            if created["firewall_rule"] and (fw_id := created["firewall_rule"].get("_id")):
                ok = await _delete_resource(backend, "firewall_rule", fw_id)
                actions.append({"firewall_rule": fw_id, "deleted": ok})
            if created["wlan"] and (wlan_id := created["wlan"].get("_id")):
                ok = await _delete_resource(backend, "wlan", wlan_id)
                actions.append({"wlan": wlan_id, "deleted": ok})
            if created["network"] and (net_id := created["network"].get("_id")):
                ok = await _delete_resource(backend, "network", net_id)
                actions.append({"network": net_id, "deleted": ok})
            logger.warning(
                "create_iot_network rolled back",
                extra={"failed_step": failed_step, "rolled_back": actions},
            )
            return actions

        async def _fail(step: str, exc: Exception) -> str:
            rolled_back = await _rollback(step)
            return format_json(
                {
                    "error": f"create_iot_network failed at {step}: {exc}",
                    "stub_mode": settings.stub_mode,
                    "partial": created,
                    "rolled_back": rolled_back,
                }
            )

        # Step 1: VLAN
        try:
            created["network"] = await backend.create_network(net_payload)
        except UniFiError as exc:
            logger.exception("create_iot_network: VLAN step failed")
            return await _fail("vlan", exc)

        net_id = (created["network"] or {}).get("_id")
        if not net_id:
            return await _fail("vlan", UniFiError("VLAN created but no _id returned"))

        # Step 2: SSID
        wlan_payload_real = dict(wlan_payload)
        wlan_payload_real["networkconf_id"] = net_id
        try:
            created["wlan"] = await backend.create_wlan(wlan_payload_real)
        except UniFiError as exc:
            logger.exception("create_iot_network: WLAN step failed")
            return await _fail("wlan", exc)

        # Step 3: isolation rule (optional)
        if fw_payload is not None:
            try:
                created["firewall_rule"] = await backend.create_firewall_rule(fw_payload)
            except UniFiError as exc:
                logger.exception("create_iot_network: firewall step failed")
                return await _fail("firewall_rule", exc)

        return format_json(
            {
                "summary": (
                    f"IoT network '{name}' (VLAN {vlan_id}) on {iot_subnet}"
                    f"{' with isolation' if isolate else ''}"
                ),
                **created,
            }
        )

    @mcp.tool()
    @audited("provision_homelab_service")
    async def provision_homelab_service(
        name: str,
        mac: str,
        ip: str,
        network_id: str,
        ports: list[int] | None = None,
        wan_expose: bool = False,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Stand up a homelab service: DHCP lease + firewall allow + (optional) port forwards.

        Side effects:
        - Step 1: creates a static DHCP reservation pinning ``mac`` to
          ``ip`` on the named network.
        - Step 2 (when ``ports`` is non-empty): creates a LAN_LOCAL accept
          firewall rule for ``ip`` on the requested TCP ports.
        - Step 3 (when ``wan_expose=True`` and ``ports`` is non-empty):
          creates one port-forward rule per port, exposing the service to
          the WAN.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.
        - Rollback: if any sub-step fails, all prior sub-steps are reverted
          in reverse order (port_forwards → firewall_rule → lease) and the
          response includes ``rolled_back`` and ``partial`` keys.

        Example: provision_homelab_service(name="plex", mac="aa:bb:cc:00:00:01", ip="10.50.0.10", network_id="65f...", ports=[32400], wan_expose=False)

        Args:
            name: Display name (used for both the lease and the firewall
                rule, e.g. ``"plex"``).
            mac: Client MAC address (e.g. ``"aa:bb:cc:00:00:01"``).
            ip: IPv4 address to reserve (must fall inside the network's
                subnet).
            network_id: ``_id`` of the network/VLAN this service lives on.
            ports: TCP ports the service listens on (e.g. ``[80, 443]``).
                Empty creates only the lease.
            wan_expose: ``True`` also creates port-forward rules so the
                service is reachable from the WAN. Default ``False``
                (LAN-only).
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        ports = ports or []

        lease_payload: dict[str, Any] = {
            "mac": mac,
            "use_fixedip": True,
            "fixed_ip": ip,
            "network_id": network_id,
            "name": name,
        }
        fw_payload: dict[str, Any] | None = None
        if ports:
            fw_payload = {
                "name": f"Allow {name}",
                "ruleset": "LAN_LOCAL",
                "rule_index": 2400,
                "action": "accept",
                "protocol": "tcp",
                "enabled": True,
                "dst_address": f"{ip}/32",
                "dst_port": ",".join(str(p) for p in ports),
            }
        pf_payloads: list[dict[str, Any]] = []
        if wan_expose and ports:
            for port in ports:
                pf_payloads.append(
                    {
                        "name": f"{name} :{port}",
                        "fwd": ip,
                        "fwd_port": str(port),
                        "dst_port": str(port),
                        "proto": "tcp",
                        "src": "any",
                        "enabled": True,
                        "log": False,
                    }
                )

        if dry_run:
            would_create: dict[str, Any] = {"lease": lease_payload}
            if fw_payload is not None:
                would_create["firewall_rule"] = fw_payload
            if pf_payloads:
                would_create["port_forwards"] = pf_payloads
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_create": would_create,
                    "summary": (
                        f"Would provision '{name}' at {ip}"
                        + (f" with {len(ports)} port(s)" if ports else "")
                        + (" (WAN-exposed)" if wan_expose and ports else "")
                    ),
                    "note": (
                        "Composite preview. Real apply rolls back on partial failure."
                    ),
                }
            )

        backend = registry.get(controller)
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
                    ok = await _delete_resource(backend, "port_forward", pf_id)
                    actions.append({"port_forward": pf_id, "deleted": ok})
            if created["firewall_rule"] and (fw_id := created["firewall_rule"].get("_id")):
                ok = await _delete_resource(backend, "firewall_rule", fw_id)
                actions.append({"firewall_rule": fw_id, "deleted": ok})
            if created["lease"] and (lease_id := created["lease"].get("_id")):
                ok = await _delete_resource(backend, "dhcp_lease", lease_id)
                actions.append({"dhcp_lease": lease_id, "deleted": ok})
            logger.warning(
                "provision_homelab_service rolled back",
                extra={"failed_step": failed_step, "rolled_back": actions},
            )
            return actions

        async def _fail(step: str, exc: Exception) -> str:
            rolled_back = await _rollback(step)
            return format_json(
                {
                    "error": f"provision_homelab_service failed at {step}: {exc}",
                    "stub_mode": settings.stub_mode,
                    "partial": created,
                    "rolled_back": rolled_back,
                }
            )

        # Step 1: lease
        try:
            created["lease"] = await backend.create_dhcp_lease(lease_payload)
        except UniFiError as exc:
            return await _fail("lease", exc)

        # Step 2: firewall allow rule (LAN_LOCAL accept to the service IP)
        if fw_payload is not None:
            try:
                created["firewall_rule"] = await backend.create_firewall_rule(fw_payload)
            except UniFiError as exc:
                return await _fail("firewall_rule", exc)

        # Step 3: port forwards (optional)
        for pf_payload in pf_payloads:
            try:
                created["port_forwards"].append(await backend.create_port_forward(pf_payload))
            except UniFiError as exc:
                return await _fail("port_forward", exc)

        return format_json(
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
    @audited("quarantine_client")
    async def quarantine_client(
        mac: str,
        reason: str = "",
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Block a client and log the quarantine action with a reason.

        Side effects:
        - Step 1: adds the MAC to the controller's user-block list (same as
          ``block_client``). The client is immediately disconnected and
          prevented from re-associating until ``unblock_client`` is called.
        - Step 2: appends a WARNING-level structured log entry capturing
          ``mac`` and ``reason`` for later forensics.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.
        - Rollback: if any sub-step fails, all prior sub-steps are reverted
          (the log entry is best-effort and not unwound; only step 1
          mutates the controller).

        Example: quarantine_client(mac="aa:bb:cc:00:00:01", reason="suspected malware c2")

        Args:
            mac: Client MAC address (e.g. ``"aa:bb:cc:00:00:01"``).
            reason: Free-form justification (kept in logs only,
                e.g. ``"suspected malware c2"``).
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
                    "would_apply": {
                        "action": "quarantine",
                        "mac": mac,
                        "reason": reason or "(none provided)",
                    },
                    "summary": f"Would quarantine client {mac}",
                }
            )
        try:
            backend = registry.get(controller)
            blocked = await backend.block_client(mac)
            if blocked is None:
                return err(f"client {mac} not found")
            logger.warning(
                "client quarantined",
                extra={"mac": mac, "reason": reason or "(none provided)"},
            )
            return format_json({"quarantined": True, "mac": mac, "reason": reason})
        except UniFiError as exc:
            logger.exception("quarantine_client failed", extra={"mac": mac})
            return err(str(exc))

    @mcp.tool()
    @audited("create_guest_network")
    async def create_guest_network(
        name: str,
        ssid: str,
        passphrase: str,
        vlan_id: int,
        main_lan_subnet: str = "192.168.1.0/24",
        subnet: str = "",
        schedule: str = "",
        hide_ssid: bool = False,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Provision an isolated guest network end-to-end: VLAN + guest SSID + drop rule.

        Side effects:
        - Step 1: creates a VLAN-tagged network with ``purpose="guest"`` at
          the given ``subnet`` (or ``10.0.<vlan_id>.0/24`` by default).
        - Step 2: creates a guest WPA2 WiFi SSID (client isolation enabled)
          bound to the new network. Access points start broadcasting within
          seconds.
        - Step 3: creates a LAN_IN drop rule blocking the guest subnet from
          reaching ``main_lan_subnet``.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.
        - Rollback: if any sub-step fails, all prior sub-steps are reverted
          (firewall_rule → wlan → network) and the response includes
          ``rolled_back`` and ``partial`` keys.

        Example: create_guest_network(name="guest", ssid="guest-wifi", passphrase="hunter2hunter2", vlan_id=60, main_lan_subnet="192.168.1.0/24")

        Args:
            name: Display name for the network record (e.g. ``"guest"``).
            ssid: SSID to broadcast (e.g. ``"guest-wifi"``).
            passphrase: WPA2 PSK (8-63 chars).
            vlan_id: 802.1Q VLAN ID, 2-4094.
            main_lan_subnet: CIDR of the main LAN. The drop rule blocks
                guest → this subnet.
            subnet: Override the guest subnet. Empty uses
                ``IOT_SUBNET_TEMPLATE`` (default ``10.0.{vlan_id}.0/24``).
            schedule: Optional schedule descriptor (controller field
                ``schedule``). Empty = always on.
            hide_ssid: ``True`` suppresses SSID broadcast (rare for guest).
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        if not 2 <= vlan_id <= 4094:
            return err(f"vlan_id {vlan_id} out of range (2-4094)")

        guest_subnet = subnet or settings.iot_subnet_template.format(vlan_id=vlan_id)
        _, dhcp_start, dhcp_stop = subnet_to_dhcp(
            guest_subnet,
            settings.iot_dhcp_start_offset,
            settings.iot_dhcp_stop_offset,
        )

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
        wlan_payload: dict[str, Any] = {
            "name": ssid,
            "enabled": True,
            "security": "wpapsk",
            "wpa_mode": "wpa2",
            "x_passphrase": passphrase,
            "networkconf_id": DRY_RUN_NETWORK_ID,
            "is_guest": True,
            "hide_ssid": hide_ssid,
            "wlan_band": "both",
        }
        if schedule:
            wlan_payload["schedule"] = schedule

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

        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_create": {
                        "network": net_payload,
                        "wlan": wlan_payload,
                        "firewall_rule": fw_payload,
                    },
                    "summary": (
                        f"Would create guest network '{name}' (VLAN {vlan_id}) "
                        f"on {guest_subnet}"
                        f"{' with schedule' if schedule else ''}"
                    ),
                    "note": (
                        "WLAN.networkconf_id is a placeholder; the real apply "
                        "substitutes the controller-assigned _id."
                    ),
                }
            )

        backend = registry.get(controller)
        created: dict[str, Any] = {
            "network": None,
            "wlan": None,
            "firewall_rule": None,
        }

        async def _rollback(failed_step: str) -> list[dict[str, Any]]:
            actions: list[dict[str, Any]] = []
            if created["firewall_rule"] and (fw_id := created["firewall_rule"].get("_id")):
                ok = await _delete_resource(backend, "firewall_rule", fw_id)
                actions.append({"firewall_rule": fw_id, "deleted": ok})
            if created["wlan"] and (wlan_id := created["wlan"].get("_id")):
                ok = await _delete_resource(backend, "wlan", wlan_id)
                actions.append({"wlan": wlan_id, "deleted": ok})
            if created["network"] and (net_id := created["network"].get("_id")):
                ok = await _delete_resource(backend, "network", net_id)
                actions.append({"network": net_id, "deleted": ok})
            logger.warning(
                "create_guest_network rolled back",
                extra={"failed_step": failed_step, "rolled_back": actions},
            )
            return actions

        async def _fail(step: str, exc: Exception) -> str:
            rolled_back = await _rollback(step)
            return format_json(
                {
                    "error": f"create_guest_network failed at {step}: {exc}",
                    "stub_mode": settings.stub_mode,
                    "partial": created,
                    "rolled_back": rolled_back,
                }
            )

        # VLAN — guest purpose
        try:
            created["network"] = await backend.create_network(net_payload)
        except UniFiError as exc:
            return await _fail("vlan", exc)

        net_id = (created["network"] or {}).get("_id")
        if not net_id:
            return await _fail("vlan", UniFiError("VLAN created but no _id returned"))

        # Guest WLAN
        wlan_payload_real = dict(wlan_payload)
        wlan_payload_real["networkconf_id"] = net_id
        try:
            created["wlan"] = await backend.create_wlan(wlan_payload_real)
        except UniFiError as exc:
            return await _fail("wlan", exc)

        # Isolation rule
        try:
            created["firewall_rule"] = await backend.create_firewall_rule(fw_payload)
        except UniFiError as exc:
            return await _fail("firewall_rule", exc)

        return format_json(
            {
                "summary": (
                    f"Guest network '{name}' (VLAN {vlan_id}) on {guest_subnet}"
                    f"{' with schedule' if schedule else ''}"
                ),
                **created,
            }
        )

    @mcp.tool()
    @audited("audit_open_ports")
    async def audit_open_ports(controller: str = "default") -> str:
        """Audit WAN-facing exposure (port forwards and WAN_IN accept rules).

        Side effects: None (read-only).

        Cross-references firewall rules and port forwards to summarise what
        is reachable from the public internet:
        - Active port forwards (DNAT into the LAN).
        - WAN_IN ``accept`` rules, excluding the boilerplate
          established/related rule.

        Useful as a "did I leave something open?" sanity check before
        publishing a service or shipping a config.

        Example: audit_open_ports(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = registry.get(controller)
            fw_rules = await backend.list_firewall_rules()
            port_forwards = await backend.list_port_forwards()

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

            return format_json(
                {
                    "port_forwards": active_pfs,
                    "wan_accept_rules": wan_accept_rules,
                    "summary": summary,
                }
            )
        except UniFiError as exc:
            logger.exception("audit_open_ports failed")
            return err(str(exc))
