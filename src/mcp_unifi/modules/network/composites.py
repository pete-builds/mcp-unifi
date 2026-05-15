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
