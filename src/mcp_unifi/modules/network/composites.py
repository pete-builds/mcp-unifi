"""Composite tools that wrap multiple primitives with rollback on failure.

- ``create_iot_network``: VLAN + WLAN + isolation rule, rolled back if any step fails.
- ``create_guest_network``: like IoT but with ``is_guest=True``.
- ``provision_homelab_service``: lease + firewall + (optional) port forwards.
- ``quarantine_client``: block + structured log entry.
- ``audit_open_ports``: read-only summary of WAN exposure.

On a site running the Zone-Based Firewall, the three provisioning composites
create a zone policy through the Integration API where they would otherwise
create a legacy rule (ADR 0009, :mod:`._zone_policy`). Detection runs before
the first write, so a site that cannot be classified fails with nothing
created.

Every payload and record these tools emit goes through
:func:`mcp_unifi.redaction.redact` on the way out, matching ``wlans``. The IoT
and guest composites take a ``passphrase`` argument and build a WLAN payload
around it, so all three emission points leak it otherwise: the ``dry_run``
preview echoes the payload back verbatim, the success response carries the
WLAN record the controller echoes back, and the rollback response carries the
same record under ``partial``. The rollback path is the one that is easy to
miss — it fires precisely when something went wrong, which is when the output
is most likely to be pasted somewhere.
"""

from __future__ import annotations

import copy
import ipaddress
import logging
from typing import TYPE_CHECKING, Any

from mcp_unifi.annotations import CREATE, DESTRUCTIVE, READ_ONLY
from mcp_unifi.backends import Backend
from mcp_unifi.clients.integration import CreatedButUnreadError
from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.clients.zone_policy import PolicyBodyError
from mcp_unifi.dispatcher import resolve_backend
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules._params import (
    BoundedName,
    BoundedSecret,
    BoundedSsid,
    BoundedText,
)
from mcp_unifi.modules.network._common import (
    check_composite_subnet,
    format_json,
    make_err,
    normalize_ip_subnet,
    resolve_default_ap_group,
    subnet_to_dhcp,
    subnet_to_network_form,
    upsert_dhcp_lease,
    wan_zone_ids,
    zone_names_by_id,
)
from mcp_unifi.modules.network._zone_policy import (
    isolation_policy,
    policy_preview,
    service_policy,
    site_is_zone_based,
)
from mcp_unifi.redaction import redact

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
        if kind == "firewall_policy":
            return await backend.delete_v1_firewall_policy(resource_id)
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


async def _undo_create(
    backend: Backend, kind: str, record: dict[str, Any]
) -> dict[str, Any] | None:
    """Delete a network or WLAN this call created, by ``_id`` or by v1 id.

    A create that landed through the Integration API but could not be read
    back is recorded as ``{"external_id": <v1 id>}`` (see
    :class:`CreatedButUnreadError`). By rollback time the private API usually
    shows it, so it is looked up by ``external_id`` and deleted like any
    other. If it still cannot be found the action says so, and the record is
    left on the console for the caller to remove. ``None`` when the record
    carries neither id, so there is nothing to act on.
    """
    resource_id = record.get("_id")
    external_id = record.get("external_id")
    if not resource_id and not isinstance(external_id, str):
        return None
    if not resource_id:
        lister = backend.list_networks if kind == "network" else backend.list_wlans
        try:
            resource_id = next(
                (r.get("_id") for r in await lister() if r.get("external_id") == external_id),
                None,
            )
        except UniFiError as exc:
            logger.error(
                "rollback lookup failed",
                extra={"kind": kind, "external_id": external_id, "error": str(exc)},
            )
        if not isinstance(resource_id, str) or not resource_id:
            return {kind: None, "external_id": external_id, "deleted": False}
    ok = await _delete_resource(backend, kind, str(resource_id))
    return {kind: resource_id, "deleted": ok}


#: User-record keys ``provision_homelab_service`` writes, and so may restore.
_LEASE_KEYS = ("use_fixedip", "fixed_ip", "network_id", "name")


async def _restore_lease(
    backend: Backend, lease_id: str, prior: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any]:
    """Put back what this call changed on a user record that existed before it.

    Each key the call wrote gets its previous value. A record that held no
    reservation gets ``use_fixedip`` false, which is how a reservation is
    cleared (issue #124). A key the record did not have before cannot be
    removed through ``PUT /rest/user``, so it is listed in ``not_restored``
    instead of guessed at.
    """
    restore: dict[str, Any] = {}
    not_restored: list[str] = []
    for key in _LEASE_KEYS:
        if key not in payload:
            continue
        if key in prior:
            if prior[key] != payload[key]:
                restore[key] = prior[key]
        elif key == "use_fixedip":
            restore[key] = False
        else:
            not_restored.append(key)
    action: dict[str, Any] = {"dhcp_lease": lease_id, "restored_fields": sorted(restore)}
    if not_restored:
        action["not_restored"] = not_restored
    ok = True
    if restore:
        try:
            await backend.update_dhcp_lease(lease_id, restore)
        except UniFiError as exc:
            logger.error(
                "rollback restore failed",
                extra={"kind": "dhcp_lease", "resource_id": lease_id, "error": str(exc)},
            )
            ok = False
    action["restored"] = ok
    return action


async def _main_lan_error(backend: Backend, main_lan_subnet: str) -> str | None:
    """Why ``main_lan_subnet`` cannot anchor an isolation rule, or ``None``.

    A drop rule toward a subnet no network on the site uses isolates nothing,
    yet the composite would still report "with isolation". The site's own
    subnets are listed so the caller can pass the right one; none is guessed.
    """
    trusted = ipaddress.IPv4Network(main_lan_subnet, strict=False)
    seen: list[str] = []
    for net in await backend.list_networks():
        raw = net.get("ip_subnet")
        if not isinstance(raw, str):
            continue
        try:
            have = ipaddress.IPv4Interface(raw).network
        except ValueError:
            continue
        if have.overlaps(trusted):
            return None
        seen.append(f"{net.get('name', '?')} {have}")
    return (
        f"main_lan_subnet {trusted} overlaps no network on this site, so an isolation "
        f"rule toward it would block nothing. Pass the subnet of the LAN to protect; "
        f"this site's subnets are: {', '.join(seen) if seen else 'none found'}"
    )


def _subnet_input_error(main_lan_subnet: str) -> str | None:
    try:
        ipaddress.IPv4Network(main_lan_subnet, strict=False)
    except ValueError:
        return f"main_lan_subnet {main_lan_subnet!r} is not an IPv4 subnet"
    return None


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    async def _dry_run_zone_based(controller: str) -> bool:
        # A dry run only previews, so a failed detection read falls back to the
        # legacy preview; the real apply detects again and fails before writing.
        try:
            return await site_is_zone_based(resolve_backend(registry, controller))
        except UniFiError:
            logger.warning("dry run could not read the firewall model", exc_info=True)
            return False

    @mcp.tool(annotations=CREATE)
    @audited("create_iot_network", mutates=True)
    async def create_iot_network(
        name: BoundedName,
        vlan_id: int,
        passphrase: BoundedSecret,
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
          the IoT subnet from reaching ``main_lan_subnet``. On a site running
          the Zone-Based Firewall it creates a BLOCK zone policy with the same
          subnets instead, through the Integration API (``firewall_policy`` in
          the response).
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.
        - Rollback: if any sub-step fails, all prior sub-steps are reverted
          (firewall_rule or firewall_policy → wlan → network) and the response
          includes ``rolled_back`` and ``partial`` keys.

        The ``passphrase`` is **redacted** to ``"[REDACTED]"`` everywhere this
        tool emits it: the ``dry_run`` preview, the created WLAN record, and
        the ``partial`` record on a rollback. There is no opt-in flag.

        Checked before anything is written, ``dry_run`` included: the IoT
        subnet and its DHCP range must be valid IPv4 (a ``vlan_id`` above 255
        does not fit the default template), and with ``isolate=True``
        ``main_lan_subnet`` must overlap a network that exists on the site.
        Otherwise the call is refused, and for ``main_lan_subnet`` the error
        lists the site's subnets; the default ``192.168.1.0/24`` is not right
        for every site.

        Example: create_iot_network(name="iot", vlan_id=50, passphrase="hunter2hunter2", main_lan_subnet="192.168.1.0/24")

        Args:
            name: Used for both the network name and the SSID (e.g. ``"iot"``).
            vlan_id: 802.1Q VLAN ID, 2-4094. Also drives the default subnet.
            passphrase: WPA2 PSK for the IoT SSID (8-63 chars).
            main_lan_subnet: CIDR of the main/trusted LAN. The isolation rule
                blocks IoT → this subnet. Defaults to ``"192.168.1.0/24"``.
                Must overlap an existing network's subnet when ``isolate``.
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

        iot_subnet = normalize_ip_subnet(
            subnet or settings.iot_subnet_template.format(vlan_id=vlan_id)
        )
        _, dhcp_start, dhcp_stop = subnet_to_dhcp(
            iot_subnet,
            settings.iot_dhcp_start_offset,
            settings.iot_dhcp_stop_offset,
        )
        input_error = check_composite_subnet(iot_subnet, dhcp_start, dhcp_stop)
        if input_error is not None:
            source = "subnet" if subnet else f"IOT_SUBNET_TEMPLATE and vlan_id {vlan_id}"
            return err(f"{input_error} (from {source}); nothing was created")
        if isolate and (input_error := _subnet_input_error(main_lan_subnet)) is not None:
            return err(f"{input_error}; nothing was created")

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
            "ap_group_ids": ["<auto-resolve-default>"],
            "ap_group_mode": "all",
        }
        fw_payload: dict[str, Any] | None = None
        if isolate:
            fw_payload = {
                "name": f"Block {name} -> Main LAN",
                "ruleset": "LAN_IN",
                "rule_index": 20000 + vlan_id,
                "action": "drop",
                "protocol": "all",
                "enabled": True,
                "src_address": subnet_to_network_form(iot_subnet),
                "dst_address": main_lan_subnet,
            }

        if dry_run:
            if isolate:
                try:
                    lan_error = await _main_lan_error(
                        resolve_backend(registry, controller), main_lan_subnet
                    )
                except UniFiError as exc:
                    return err(str(exc))
                if lan_error is not None:
                    return err(lan_error)
            would_create: dict[str, Any] = {
                "network": net_payload,
                "wlan": wlan_payload,
            }
            if fw_payload is not None:
                if await _dry_run_zone_based(controller):
                    would_create["firewall_policy"] = policy_preview(
                        "isolation",
                        name=fw_payload["name"],
                        action="BLOCK",
                        source_addresses=[fw_payload["src_address"]],
                        destination_addresses=[main_lan_subnet],
                    )
                else:
                    would_create["firewall_rule"] = fw_payload
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    # The WLAN payload carries the caller's passphrase.
                    "would_create": redact(would_create),
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

        try:
            backend = resolve_backend(registry, controller)
            zone_based = fw_payload is not None and await site_is_zone_based(backend)
            lan_error = await _main_lan_error(backend, main_lan_subnet) if isolate else None
        except UniFiError as exc:
            return err(str(exc))
        if lan_error is not None:
            return err(lan_error)
        created: dict[str, Any] = {
            "network": None,
            "wlan": None,
            "firewall_rule": None,
        }
        if zone_based:
            created["firewall_policy"] = None

        async def _rollback(failed_step: str) -> list[dict[str, Any]]:
            actions: list[dict[str, Any]] = []
            if created.get("firewall_policy") and (fp_id := created["firewall_policy"].get("id")):
                ok = await _delete_resource(backend, "firewall_policy", fp_id)
                actions.append({"firewall_policy": fp_id, "deleted": ok})
            if created["firewall_rule"] and (fw_id := created["firewall_rule"].get("_id")):
                ok = await _delete_resource(backend, "firewall_rule", fw_id)
                actions.append({"firewall_rule": fw_id, "deleted": ok})
            if created["wlan"] and (undone := await _undo_create(backend, "wlan", created["wlan"])):
                actions.append(undone)
            if created["network"] and (
                undone := await _undo_create(backend, "network", created["network"])
            ):
                actions.append(undone)
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
                    # ``partial`` holds whatever the controller already
                    # created, WLAN record and passphrase included.
                    "partial": redact(created),
                    "rolled_back": rolled_back,
                }
            )

        # Step 1: VLAN
        try:
            created["network"] = await backend.create_network(net_payload)
        except UniFiError as exc:
            logger.exception("create_iot_network: VLAN step failed")
            if isinstance(exc, CreatedButUnreadError):
                # It exists; rollback finds it by v1 id.
                created["network"] = {"external_id": exc.v1_id}
            return await _fail("vlan", exc)

        net_id = (created["network"] or {}).get("_id")
        if not net_id:
            return await _fail("vlan", UniFiError("VLAN created but no _id returned"))

        # Step 2: SSID
        wlan_payload_real = dict(wlan_payload)
        wlan_payload_real["networkconf_id"] = net_id
        try:
            wlan_payload_real["ap_group_ids"] = await resolve_default_ap_group(backend)
        except UniFiError as exc:
            logger.exception("create_iot_network: AP-group resolve failed")
            return await _fail("wlan", exc)
        if not wlan_payload_real["ap_group_ids"]:
            return await _fail(
                "wlan",
                UniFiError("no AP groups found on controller; cannot create WLAN"),
            )
        try:
            created["wlan"] = await backend.create_wlan(wlan_payload_real)
        except UniFiError as exc:
            logger.exception("create_iot_network: WLAN step failed")
            if isinstance(exc, CreatedButUnreadError):
                created["wlan"] = {"external_id": exc.v1_id}
            return await _fail("wlan", exc)

        # Step 3: isolation rule (optional); a zone policy on a zone-based site
        if fw_payload is not None and zone_based:
            try:
                body = await isolation_policy(
                    backend,
                    name=name,
                    network_id=net_id,
                    subnet=iot_subnet,
                    main_lan_subnet=main_lan_subnet,
                )
                created["firewall_policy"] = await backend.create_v1_firewall_policy(body)
            except (UniFiError, PolicyBodyError) as exc:
                # PolicyBodyError is a ValueError: without it here a bad body
                # skipped rollback and left the SSID broadcasting.
                logger.exception("create_iot_network: firewall policy step failed")
                return await _fail("firewall_policy", exc)
        elif fw_payload is not None:
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
                # The controller echoes the WLAN record back with the
                # passphrase it was just given.
                **redact(created),
            }
        )

    @mcp.tool(annotations=CREATE)
    @audited("provision_homelab_service", mutates=True)
    async def provision_homelab_service(
        name: BoundedName,
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
          firewall rule for ``ip`` on the requested TCP ports. On a site
          running the Zone-Based Firewall it creates an ALLOW zone policy from
          the ``Internal`` zone to ``ip`` on those ports instead, through the
          Integration API (``firewall_policy`` in the response).
        - Step 3 (when ``wan_expose=True`` and ``ports`` is non-empty):
          creates one port-forward rule per port, exposing the service to
          the WAN.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.
        - Rollback: if any sub-step fails, all prior sub-steps are reverted
          in reverse order (port_forwards → firewall_rule or
          firewall_policy → lease) and the
          response includes ``rolled_back`` and ``partial`` keys. A
          reservation this call created is cleared; one that already existed
          for ``mac`` gets its previous values back instead.
        - ``ip`` must be an IPv4 address and every port 1-65535; anything else
          is refused before the first write, ``dry_run`` included.

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
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            return err(f"ip {ip!r} is not an IPv4 address; nothing was created")
        bad_ports = [p for p in ports if not 1 <= p <= 65535]
        if bad_ports:
            return err(f"port(s) {bad_ports} out of range (1-65535); nothing was created")

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
                "rule_index": 20400,
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
                if await _dry_run_zone_based(controller):
                    would_create["firewall_policy"] = policy_preview(
                        "service_allow",
                        name=fw_payload["name"],
                        action="ALLOW",
                        source_zone="Internal",
                        destination_addresses=[ip],
                        protocol="tcp",
                        destination_ports=fw_payload["dst_port"],
                    )
                else:
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
                    "note": ("Composite preview. Real apply rolls back on partial failure."),
                }
            )

        try:
            backend = resolve_backend(registry, controller)
            zone_based = fw_payload is not None and await site_is_zone_based(backend)
        except UniFiError as exc:
            return err(str(exc))
        created: dict[str, Any] = {
            "lease": None,
            "firewall_rule": None,
            "port_forwards": [],
        }
        if zone_based:
            created["firewall_policy"] = None
        # The user record for ``mac`` as it was before step 1, if there was one.
        prior_user: dict[str, Any] | None = None

        async def _rollback(failed_step: str) -> list[dict[str, Any]]:
            actions: list[dict[str, Any]] = []
            for pf in reversed(created["port_forwards"]):
                pf_id = pf.get("_id")
                if pf_id:
                    ok = await _delete_resource(backend, "port_forward", pf_id)
                    actions.append({"port_forward": pf_id, "deleted": ok})
            if created.get("firewall_policy") and (fp_id := created["firewall_policy"].get("id")):
                ok = await _delete_resource(backend, "firewall_policy", fp_id)
                actions.append({"firewall_policy": fp_id, "deleted": ok})
            if created["firewall_rule"] and (fw_id := created["firewall_rule"].get("_id")):
                ok = await _delete_resource(backend, "firewall_rule", fw_id)
                actions.append({"firewall_rule": fw_id, "deleted": ok})
            if created["lease"] and (lease_id := created["lease"].get("_id")):
                if prior_user is None:
                    ok = await _delete_resource(backend, "dhcp_lease", lease_id)
                    actions.append({"dhcp_lease": lease_id, "deleted": ok})
                else:
                    # The record was there before this call: undo the edit,
                    # never clear a reservation someone else made.
                    actions.append(
                        await _restore_lease(backend, lease_id, prior_user, lease_payload)
                    )
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

        # Step 1: lease. A known client (anything that ever connected) has a
        # user record already and the controller refuses a second one with
        # api.err.MacUsed, so this is an upsert: PUT to the existing record
        # or POST a new one. The record as it was is kept so rollback can
        # tell the two apart: clear a reservation this call created, restore
        # one it edited.
        try:
            found = await backend.find_user_by_mac(mac)
            # A copy: the stub hands back its live record, which the upsert edits.
            prior_user = copy.deepcopy(found) if found is not None else None
            created["lease"] = await upsert_dhcp_lease(backend, lease_payload)
        except UniFiError as exc:
            return await _fail("lease", exc)

        # Step 2: firewall allow (LAN_LOCAL accept to the service IP, or a zone
        # policy on a zone-based site)
        if fw_payload is not None and zone_based:
            try:
                body = await service_policy(
                    backend, name=name, network_id=network_id, ip=ip, ports=ports
                )
                created["firewall_policy"] = await backend.create_v1_firewall_policy(body)
            except (UniFiError, PolicyBodyError) as exc:
                return await _fail("firewall_policy", exc)
        elif fw_payload is not None:
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

    @mcp.tool(annotations=DESTRUCTIVE)
    @audited("quarantine_client", mutates=True)
    async def quarantine_client(
        mac: str,
        reason: BoundedText = "",
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
            backend = resolve_backend(registry, controller)
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

    @mcp.tool(annotations=CREATE)
    @audited("create_guest_network", mutates=True)
    async def create_guest_network(
        name: BoundedName,
        ssid: BoundedSsid,
        passphrase: BoundedSecret,
        vlan_id: int,
        main_lan_subnet: str = "192.168.1.0/24",
        subnet: str = "",
        schedule: BoundedText = "",
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
          reaching ``main_lan_subnet``. On a site running the Zone-Based
          Firewall it creates a BLOCK zone policy with the same subnets
          instead, through the Integration API (``firewall_policy`` in the
          response).
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.
        - Rollback: if any sub-step fails, all prior sub-steps are reverted
          (firewall_rule or firewall_policy → wlan → network) and the response
          includes ``rolled_back`` and ``partial`` keys.

        The ``passphrase`` is **redacted** to ``"[REDACTED]"`` everywhere this
        tool emits it: the ``dry_run`` preview, the created WLAN record, and
        the ``partial`` record on a rollback. There is no opt-in flag.

        Checked before anything is written, ``dry_run`` included: the guest
        subnet and its DHCP range must be valid IPv4 (a ``vlan_id`` above 255
        does not fit the default template), and ``main_lan_subnet`` must
        overlap a network that exists on the site. Otherwise the call is
        refused, and for ``main_lan_subnet`` the error lists the site's
        subnets; the default ``192.168.1.0/24`` is not right for every site.

        Example: create_guest_network(name="guest", ssid="guest-wifi", passphrase="hunter2hunter2", vlan_id=60, main_lan_subnet="192.168.1.0/24")

        Args:
            name: Display name for the network record (e.g. ``"guest"``).
            ssid: SSID to broadcast (e.g. ``"guest-wifi"``).
            passphrase: WPA2 PSK (8-63 chars).
            vlan_id: 802.1Q VLAN ID, 2-4094.
            main_lan_subnet: CIDR of the main LAN. The drop rule blocks
                guest → this subnet. Must overlap an existing network's
                subnet.
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

        guest_subnet = normalize_ip_subnet(
            subnet or settings.iot_subnet_template.format(vlan_id=vlan_id)
        )
        _, dhcp_start, dhcp_stop = subnet_to_dhcp(
            guest_subnet,
            settings.iot_dhcp_start_offset,
            settings.iot_dhcp_stop_offset,
        )
        input_error = check_composite_subnet(guest_subnet, dhcp_start, dhcp_stop)
        if input_error is not None:
            source = "subnet" if subnet else f"IOT_SUBNET_TEMPLATE and vlan_id {vlan_id}"
            return err(f"{input_error} (from {source}); nothing was created")
        if (input_error := _subnet_input_error(main_lan_subnet)) is not None:
            return err(f"{input_error}; nothing was created")

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
            "ap_group_ids": ["<auto-resolve-default>"],
            "ap_group_mode": "all",
        }
        if schedule:
            wlan_payload["schedule"] = schedule

        fw_payload: dict[str, Any] = {
            "name": f"Block {name} -> Main LAN",
            "ruleset": "LAN_IN",
            "rule_index": 20000 + vlan_id,
            "action": "drop",
            "protocol": "all",
            "enabled": True,
            "src_address": subnet_to_network_form(guest_subnet),
            "dst_address": main_lan_subnet,
        }

        if dry_run:
            try:
                lan_error = await _main_lan_error(
                    resolve_backend(registry, controller), main_lan_subnet
                )
            except UniFiError as exc:
                return err(str(exc))
            if lan_error is not None:
                return err(lan_error)
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    # The WLAN payload carries the caller's passphrase.
                    "would_create": redact(
                        {
                            "network": net_payload,
                            "wlan": wlan_payload,
                            **(
                                {
                                    "firewall_policy": policy_preview(
                                        "isolation",
                                        name=fw_payload["name"],
                                        action="BLOCK",
                                        source_addresses=[fw_payload["src_address"]],
                                        destination_addresses=[main_lan_subnet],
                                    )
                                }
                                if await _dry_run_zone_based(controller)
                                else {"firewall_rule": fw_payload}
                            ),
                        }
                    ),
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

        try:
            backend = resolve_backend(registry, controller)
            zone_based = await site_is_zone_based(backend)
            lan_error = await _main_lan_error(backend, main_lan_subnet)
        except UniFiError as exc:
            return err(str(exc))
        if lan_error is not None:
            return err(lan_error)
        created: dict[str, Any] = {
            "network": None,
            "wlan": None,
            "firewall_rule": None,
        }
        if zone_based:
            created["firewall_policy"] = None

        async def _rollback(failed_step: str) -> list[dict[str, Any]]:
            actions: list[dict[str, Any]] = []
            if created.get("firewall_policy") and (fp_id := created["firewall_policy"].get("id")):
                ok = await _delete_resource(backend, "firewall_policy", fp_id)
                actions.append({"firewall_policy": fp_id, "deleted": ok})
            if created["firewall_rule"] and (fw_id := created["firewall_rule"].get("_id")):
                ok = await _delete_resource(backend, "firewall_rule", fw_id)
                actions.append({"firewall_rule": fw_id, "deleted": ok})
            if created["wlan"] and (undone := await _undo_create(backend, "wlan", created["wlan"])):
                actions.append(undone)
            if created["network"] and (
                undone := await _undo_create(backend, "network", created["network"])
            ):
                actions.append(undone)
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
                    # ``partial`` holds whatever the controller already
                    # created, WLAN record and passphrase included.
                    "partial": redact(created),
                    "rolled_back": rolled_back,
                }
            )

        # VLAN — guest purpose
        try:
            created["network"] = await backend.create_network(net_payload)
        except UniFiError as exc:
            if isinstance(exc, CreatedButUnreadError):
                created["network"] = {"external_id": exc.v1_id}
            return await _fail("vlan", exc)

        net_id = (created["network"] or {}).get("_id")
        if not net_id:
            return await _fail("vlan", UniFiError("VLAN created but no _id returned"))

        # Guest WLAN
        wlan_payload_real = dict(wlan_payload)
        wlan_payload_real["networkconf_id"] = net_id
        try:
            wlan_payload_real["ap_group_ids"] = await resolve_default_ap_group(backend)
        except UniFiError as exc:
            return await _fail("wlan", exc)
        if not wlan_payload_real["ap_group_ids"]:
            return await _fail(
                "wlan",
                UniFiError("no AP groups found on controller; cannot create WLAN"),
            )
        try:
            created["wlan"] = await backend.create_wlan(wlan_payload_real)
        except UniFiError as exc:
            if isinstance(exc, CreatedButUnreadError):
                created["wlan"] = {"external_id": exc.v1_id}
            return await _fail("wlan", exc)

        # Isolation rule; a zone policy on a zone-based site
        if zone_based:
            try:
                body = await isolation_policy(
                    backend,
                    name=name,
                    network_id=net_id,
                    subnet=guest_subnet,
                    main_lan_subnet=main_lan_subnet,
                )
                created["firewall_policy"] = await backend.create_v1_firewall_policy(body)
            except (UniFiError, PolicyBodyError) as exc:
                return await _fail("firewall_policy", exc)
        else:
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
                # The controller echoes the WLAN record back with the
                # passphrase it was just given.
                **redact(created),
            }
        )

    @mcp.tool(annotations=READ_ONLY)
    @audited("audit_open_ports", mutates=False)
    async def audit_open_ports(controller: str = "default") -> str:
        """Audit WAN-facing exposure: port forwards plus WAN accept rules and policies.

        Side effects: None (read-only).

        Cross-references port forwards with BOTH firewall models a controller
        can run, so a site on the Zone-Based Firewall is not reported as
        clean just because its legacy rulesets are empty (issue #112):
        - Active port forwards (DNAT into the LAN).
        - Legacy ``WAN_*`` ``accept`` rules, excluding the boilerplate
          established/related rule (a rule that also matches new
          connections is kept).
        - Zone-Based Firewall ``ALLOW`` policies whose source zone is the WAN
          (``External``) zone, excluding return-traffic allowances
          (``connection_state_type == "RESPOND_ONLY"``); the number excluded
          is reported. ``predefined`` policies are NOT excluded: the zone
          matrix implements "External to Internal: Allow" as a predefined
          "Allow All Traffic" policy, which is exactly the exposure this
          audit exists to surface, so each record carries ``predefined`` and
          the caller can tell matrix defaults from hand-written policies.

        A controller mirrors each port forward into its own predefined WAN
        policy, so the same exposure can appear in both halves of this audit.
        Those carry ``duplicates_port_forward: true`` and are counted in
        ``port_forward_mirror_policies``; they are tagged rather than dropped,
        and a ``port_forward`` policy whose origin matches no listed forward
        stays untagged, because it admits traffic the port-forward half does
        not show.

        Returns ``{"port_forwards", "wan_accept_rules", "wan_accept_policies",
        "firewall_model", "wan_zone_resolved",
        "return_traffic_policies_excluded", "port_forward_mirror_policies",
        "summary"}``. Each entry in ``wan_accept_policies`` carries
        ``source_zone``, ``destination_zone`` and ``duplicates_port_forward``
        alongside the controller's own fields. ``firewall_model``
        is ``legacy``, ``zone-based``, ``mixed`` or ``none`` from what the
        controller actually returned. If the zone-based read fails the audit
        still answers from the legacy side and carries the failure in
        ``firewall_policies_error`` rather than reporting a clean WAN. If
        policies exist but no zone could be identified as WAN,
        ``wan_zone_resolved`` is false and none are classified.

        Useful as a "did I leave something open?" sanity check before
        publishing a service or shipping a config.

        Example: audit_open_ports(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
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
                    # Filter out the boilerplate "accept established/related"
                    # rule. A rule that also matches new connections admits
                    # inbound traffic and is a finding.
                    r.get("state_established") and r.get("state_related") and not r.get("state_new")
                )
            ]

            # Zone-Based Firewall side. A failure here must not turn into a
            # clean report: keep the legacy answer and carry the error.
            policies: list[Any] = []
            zones: list[Any] = []
            policies_error: str | None = None
            try:
                policies = list(await backend.list_firewall_policies())
                zones = list(await backend.list_firewall_zones())
            except UniFiError as exc:
                logger.warning("audit_open_ports: zone-based firewall read failed: %s", exc)
                policies_error = str(exc)

            wan_ids = wan_zone_ids(zones)
            zone_names = zone_names_by_id(zones)
            # A port forward the controller already gave us above reappears
            # here as its own mirror policy. Match on the forward's own id so
            # a policy whose origin is NOT in that set stays a finding.
            active_pf_ids = {
                str(pf.get("_id")) for pf in active_pfs if isinstance(pf, dict) and pf.get("_id")
            }
            wan_accept_policies: list[dict[str, Any]] = []
            return_traffic_excluded = 0
            port_forward_mirrors = 0
            for policy in policies:
                if not isinstance(policy, dict):
                    continue
                source = policy.get("source")
                source = source if isinstance(source, dict) else {}
                if str(policy.get("action", "")).upper() != "ALLOW":
                    continue
                if not policy.get("enabled", True):
                    continue
                if str(source.get("zone_id")) not in wan_ids:
                    continue
                # Return-traffic allowances only admit replies to connections
                # the inside opened; they expose nothing. Captured controller
                # data marks them RESPOND_ONLY. Do NOT key this on
                # ``predefined``: the matrix's "Allow All Traffic" is
                # predefined too, and from the WAN zone it is the finding.
                if str(policy.get("connection_state_type", "")).upper() == "RESPOND_ONLY":
                    return_traffic_excluded += 1
                    continue
                destination = policy.get("destination")
                destination = destination if isinstance(destination, dict) else {}
                # The controller mirrors every port forward into a predefined
                # WAN policy, so without this the same exposure is counted in
                # both halves of one audit (issue #112 field report). Tag it,
                # do NOT drop it: an origin id matching no listed forward is a
                # policy admitting traffic the port-forward half never shows,
                # which is a finding and not a duplicate.
                mirrors_pf = (
                    str(policy.get("origin_type", "")) == "port_forward"
                    and str(policy.get("origin_id", "")) in active_pf_ids
                )
                if mirrors_pf:
                    port_forward_mirrors += 1
                wan_accept_policies.append(
                    {
                        **policy,
                        "source_zone": zone_names.get(str(source.get("zone_id")), ""),
                        "destination_zone": zone_names.get(str(destination.get("zone_id")), ""),
                        "duplicates_port_forward": mirrors_pf,
                    }
                )

            if fw_rules and policies:
                firewall_model = "mixed"
            elif policies:
                firewall_model = "zone-based"
            elif fw_rules:
                firewall_model = "legacy"
            else:
                firewall_model = "none"

            summary_parts: list[str] = []
            summary_parts.append(f"{len(active_pfs)} active port forward(s)")
            summary_parts.append(f"{len(wan_accept_rules)} WAN accept rule(s)")
            policy_part = f"{len(wan_accept_policies)} WAN allow policy(ies)"
            if port_forward_mirrors:
                policy_part += f" ({port_forward_mirrors} mirroring a listed port forward)"
            summary_parts.append(policy_part)
            if return_traffic_excluded:
                summary_parts.append(
                    f"{return_traffic_excluded} return-traffic WAN policy(ies) excluded"
                )
            if policies_error:
                summary_parts.append("zone-based firewall read FAILED, policies not audited")
            elif policies and not wan_ids:
                summary_parts.append("WAN zone unresolved, policies not classified")
            summary = "; ".join(summary_parts)

            result: dict[str, Any] = {
                "port_forwards": active_pfs,
                "wan_accept_rules": wan_accept_rules,
                "wan_accept_policies": wan_accept_policies,
                "firewall_model": firewall_model,
                "wan_zone_resolved": bool(wan_ids),
                "return_traffic_policies_excluded": return_traffic_excluded,
                "port_forward_mirror_policies": port_forward_mirrors,
                "summary": summary,
            }
            if policies_error:
                result["firewall_policies_error"] = policies_error
            return format_json(result)
        except UniFiError as exc:
            logger.exception("audit_open_ports failed")
            return err(str(exc))
