"""Zone-Based Firewall policy writes through the Integration API (ADR 0009).

The read tools for zone policies and zones live in :mod:`.firewall` and read
the private v2 API. These three write through ``/integration/v1`` only, and
speak its shapes: policies and zones are addressed by their v1 ``id`` or by
name. Network references are taken as private ``_id`` values, the ones
``list_networks`` returns, and translated through ``external_id``.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from mcp_unifi.annotations import CREATE, DESTRUCTIVE, WRITE_IDEMPOTENT
from mcp_unifi.clients import zone_policy as zp
from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.dispatcher import resolve_backend
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules._params import BoundedName, BoundedText
from mcp_unifi.modules.network._common import format_json, make_err
from mcp_unifi.modules.network._pending import format_preview_envelope, get_pending_actions
from mcp_unifi.modules.network._verify import verified_update

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.backends import Backend
    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.network.firewall_policies")

_LEGACY_HINT = (
    "this site still runs legacy firewall rules, not the Zone-Based Firewall; "
    "use create_firewall_rule / update_firewall_rule / delete_firewall_rule"
)


class PolicyLookupError(Exception):
    """A zone, network or policy reference did not resolve to exactly one record."""


async def require_zone_based(backend: Backend) -> None:
    """Raise :class:`PolicyLookupError` unless the site is zone-based."""
    state = await backend.zone_firewall_state()
    if state == "configured":
        return
    if state == "legacy":
        raise PolicyLookupError(_LEGACY_HINT)
    if state == "disabled":
        raise PolicyLookupError(
            "zone policies are written through the Integration API only, and this "
            "controller is set to write_api=private"
        )
    raise PolicyLookupError("this console's Integration API has no firewall/zones route")


def pick_zone(zones: list[dict[str, Any]], ref: str, label: str) -> str:
    """Resolve a zone name or v1 id to its v1 id."""
    matches = zp.find_by_id_or_name(zones, ref)
    if len(matches) == 1 and isinstance(matches[0].get("id"), str):
        return str(matches[0]["id"])
    names = ", ".join(sorted(str(z.get("name")) for z in zones if isinstance(z, dict)))
    raise PolicyLookupError(f"{label} {ref!r} matches no single zone; zones are: {names}")


async def v1_networks(backend: Backend, private_ids: list[str] | None, label: str) -> list[str]:
    """Translate private network ``_id`` values to Integration API ids."""
    out: list[str] = []
    for private_id in private_ids or []:
        v1_id = await backend.v1_network_id(private_id)
        if v1_id is None:
            raise PolicyLookupError(
                f"{label}: network {private_id!r} not found, or it has no Integration API id"
            )
        out.append(v1_id)
    return out


async def pick_policy(backend: Backend, ref: str) -> dict[str, Any]:
    """Resolve a policy v1 id or exact name to its record."""
    matches = zp.find_by_id_or_name(await backend.list_v1_firewall_policies(), ref)
    if not matches:
        raise PolicyLookupError(f"firewall policy {ref!r} not found")
    if len(matches) > 1:
        ids = ", ".join(str(m.get("id")) for m in matches)
        raise PolicyLookupError(f"{len(matches)} policies are named {ref!r}; pass one id: {ids}")
    return matches[0]


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool(annotations=CREATE)
    @audited("create_firewall_policy", mutates=True)
    async def create_firewall_policy(
        name: BoundedName,
        action: str,
        source_zone: str,
        destination_zone: str,
        protocol: str = "all",
        ip_version: str = "IPV4",
        source_network_ids: list[str] | None = None,
        destination_network_ids: list[str] | None = None,
        source_addresses: list[str] | None = None,
        destination_addresses: list[str] | None = None,
        destination_ports: str = "",
        allow_return_traffic: bool = True,
        connection_states: list[str] | None = None,
        logging: bool = False,
        enabled: bool = True,
        description: BoundedText = "",
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Create a Zone-Based Firewall policy (Integration API).

        Side effects:
        - Adds a policy from ``source_zone`` to ``destination_zone``. Takes
          effect on the next packet. The console places it in its own
          evaluation order (``index`` in the response).
        - Mutates controller state. Use dry_run=True to preview the change
          without applying. A dry run still reads zones and networks, so it
          also reports a bad zone name or network id.
        - Sites still on legacy rulesets get an error pointing at
          ``create_firewall_rule``; nothing is written.

        Written through ``/proxy/network/integration/v1`` only, with no
        private-API fallback (ADR 0009). If the console refuses the body, the
        error carries its own message, which names the field it wanted.
        Returns the created v1 policy record, including its ``id``, which is
        what ``update_firewall_policy`` and ``delete_firewall_policy`` take.

        Each side matches by networks or by addresses, not both; leaving both
        empty matches the whole zone.

        Example: create_firewall_policy(name="Allow IoT to Plex", action="allow", source_zone="Internal", destination_zone="Internal", protocol="tcp", source_network_ids=["6a1240..."], destination_addresses=["192.168.86.20"], destination_ports="32400")

        Args:
            name: Display name for the policy.
            action: ``"allow"``, ``"block"`` or ``"reject"``.
            source_zone: Zone name (``"Internal"``, ``"External"``,
                ``"Hotspot"``, ``"Vpn"``, ``"Dmz"``, ``"Gateway"``, or a custom
                zone) or its v1 id.
            destination_zone: Zone name or v1 id, as ``source_zone``.
            protocol: ``"all"`` (default), ``"tcp"``, ``"udp"``, ``"tcp_udp"``,
                ``"icmp"`` (IPv4) or ``"icmpv6"`` (IPv6). A port match needs
                tcp, udp or tcp_udp.
            ip_version: ``"IPV4"`` (default), ``"IPV6"`` or ``"IPV4_AND_IPV6"``.
            source_network_ids: Private network ``_id`` values from
                ``list_networks`` to match as the source.
            destination_network_ids: Private network ``_id`` values to match
                as the destination.
            source_addresses: IPs, CIDRs or ``"a-b"`` ranges to match as the
                source.
            destination_addresses: IPs, CIDRs or ranges to match as the
                destination.
            destination_ports: Destination port match: ``"443"``,
                ``"80,443"`` or ``"8000-8100"``. Empty = any.
            allow_return_traffic: For ``allow`` only: also allow the reply
                traffic. Default ``True``.
            connection_states: Optional connection-state match, e.g.
                ``["NEW"]``. Empty = every state.
            logging: ``True`` logs every match.
            enabled: ``False`` creates the policy disabled, for staging.
            description: Optional free-text description.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                exact body that would be sent.
        """
        try:
            backend = resolve_backend(registry, controller)
            await require_zone_based(backend)
            zones = await backend.list_v1_firewall_zones()
            body = zp.create_body(
                name=name,
                action=action,
                source=zp.endpoint(
                    pick_zone(zones, source_zone, "source_zone"),
                    network_ids=await v1_networks(backend, source_network_ids, "source"),
                    addresses=source_addresses or [],
                ),
                destination=zp.endpoint(
                    pick_zone(zones, destination_zone, "destination_zone"),
                    network_ids=await v1_networks(backend, destination_network_ids, "destination"),
                    addresses=destination_addresses or [],
                    ports=destination_ports,
                ),
                protocol=protocol,
                ip_version=ip_version,
                allow_return_traffic=allow_return_traffic,
                enabled=enabled,
                logging=logging,
                description=description,
                connection_states=connection_states or [],
            )
        except (PolicyLookupError, zp.PolicyBodyError) as exc:
            return err(str(exc))
        except UniFiError as exc:
            logger.exception("create_firewall_policy lookup failed", extra={"policy_name": name})
            return err(str(exc))
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_create": {"firewall_policy": body},
                    "summary": (
                        f"Would create zone policy '{name}' "
                        f"({body['action']['type']} {source_zone} -> {destination_zone})"
                    ),
                }
            )
        try:
            return format_json(await backend.create_v1_firewall_policy(body))
        except UniFiError as exc:
            logger.exception("create_firewall_policy failed", extra={"policy_name": name})
            return err(str(exc))

    @mcp.tool(annotations=WRITE_IDEMPOTENT)
    @audited("update_firewall_policy", mutates=True)
    async def update_firewall_policy(
        policy: str,
        name: BoundedName = "",
        action: str = "",
        enabled: bool | None = None,
        logging: bool | None = None,
        description: BoundedText | None = None,
        updates: dict[str, Any] | None = None,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Change a Zone-Based Firewall policy you created (Integration API).

        Side effects:
        - Reads the policy, applies the changes, and PUTs the whole policy
          back, since the v1 PUT replaces it. Takes effect on the next packet.
        - Refuses controller-managed policies (predefined or derived return
          traffic): only ``metadata.origin == "USER_DEFINED"`` is editable.
        - Mutates controller state. Use dry_run=True to preview the before and
          after bodies without applying.

        Verified write: after the PUT the policy is re-read and the response
        carries it plus a ``verification`` block (``verified``,
        ``persisted_fields``, ``dropped_fields`` and the rest), the same block
        the other ``update_*`` tools return. Written through the Integration
        API only (ADR 0009).

        The named arguments cover the common edits. ``updates`` takes any
        other top-level v1 field (``source``, ``destination``,
        ``ipProtocolScope``, ``connectionStateFilter``, ``schedule``) in v1
        shape, replacing that field whole; it is applied after the named
        arguments.

        Example: update_firewall_policy(policy="Allow IoT to Plex", enabled=False)

        Args:
            policy: The policy's v1 ``id`` (from ``create_firewall_policy``) or
                its exact name. A name shared by two policies is refused.
            name: New name. Empty keeps the current one.
            action: New action: ``"allow"``, ``"block"`` or ``"reject"``.
                Empty keeps the current one.
            enabled: ``True``/``False`` to enable or disable. ``None`` keeps it.
            logging: ``True``/``False`` to turn match logging on or off.
            description: New description. ``None`` keeps it.
            updates: Other top-level v1 fields to replace whole.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the before/after bodies without applying.
        """
        changes: dict[str, Any] = {}
        try:
            backend = resolve_backend(registry, controller)
            await require_zone_based(backend)
            current = await pick_policy(backend, policy)
            if not zp.is_user_defined(current):
                raise PolicyLookupError(
                    f"policy {current.get('name')!r} is controller-managed and cannot be edited"
                )
            policy_id = str(current["id"])
            if name:
                changes["name"] = name
            if action:
                keep = current.get("action", {})
                changes["action"] = zp.action_body(
                    action,
                    allow_return_traffic=bool(
                        keep.get("allowReturnTraffic", True) if isinstance(keep, dict) else True
                    ),
                )
            if enabled is not None:
                changes["enabled"] = enabled
            if logging is not None:
                changes["loggingEnabled"] = logging
            if description is not None:
                changes["description"] = description
            changes.update(updates or {})
            if not changes:
                raise PolicyLookupError("update_firewall_policy needs at least one change")
            body = zp.put_body(current, changes)
        except (PolicyLookupError, zp.PolicyBodyError) as exc:
            return err(str(exc))
        except UniFiError as exc:
            logger.exception("update_firewall_policy lookup failed", extra={"policy": policy})
            return err(str(exc))
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_update": {
                        "policy_id": policy_id,
                        "before": zp.put_body(current, {}),
                        "after": body,
                    },
                    "summary": f"Would update zone policy {current.get('name')!r}",
                }
            )

        async def _lister() -> list[dict[str, Any]]:
            record = await backend.get_v1_firewall_policy(policy_id)
            return [{**record, "_id": policy_id}] if record is not None else []

        try:
            outcome = await verified_update(
                lister=_lister,
                updater=lambda: backend.update_v1_firewall_policy(policy_id, body),
                record_id=policy_id,
                updates=changes,
            )
        except UniFiError as exc:
            logger.exception("update_firewall_policy failed", extra={"policy_id": policy_id})
            return err(str(exc))
        if outcome is None:
            return err(f"firewall policy {policy_id} not found")
        record, verification = outcome
        shown = {k: v for k, v in (record or {}).items() if k != "_id"}
        return format_json({**shown, "verification": verification})

    @mcp.tool(annotations=DESTRUCTIVE)
    @audited("delete_firewall_policy", mutates=True)
    async def delete_firewall_policy(
        policy: str,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Preview deletion of a Zone-Based Firewall policy you created.

        This tool does not delete on its own. It returns a preview envelope
        with a ``token``; call ``confirm_destructive_action(token)`` to commit
        the delete. Tokens expire after 5 minutes.

        Side effects:
        - None until ``confirm_destructive_action`` runs against the token.
        - On confirm: removes the policy through the Integration API. Traffic
          it matched falls through to the next policy or the zone pair's
          default.
        - Controller-managed policies are refused.
        - ``dry_run=True`` returns the ``would_delete`` envelope with no token,
          purely informational.

        Example: delete_firewall_policy(policy="Allow IoT to Plex")

        Args:
            policy: The policy's v1 ``id`` or its exact name.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: ``True`` skips token generation and returns the
                ``{"dry_run": true, ...}`` envelope.
        """
        try:
            backend = resolve_backend(registry, controller)
            await require_zone_based(backend)
            target = await pick_policy(backend, policy)
            if not zp.is_user_defined(target):
                raise PolicyLookupError(
                    f"policy {target.get('name')!r} is controller-managed and cannot be deleted"
                )
        except PolicyLookupError as exc:
            return err(str(exc))
        except UniFiError as exc:
            logger.exception("delete_firewall_policy lookup failed", extra={"policy": policy})
            return err(str(exc))
        policy_id = str(target["id"])
        action = target.get("action")
        resource = {
            "_id": policy_id,
            "name": target.get("name"),
            "action": action.get("type") if isinstance(action, dict) else None,
            "enabled": target.get("enabled"),
        }
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_delete": resource,
                    "summary": f"Would delete zone policy {target.get('name')!r}",
                }
            )

        async def _execute() -> str:
            try:
                ok = await backend.delete_v1_firewall_policy(policy_id)
                return format_json({"deleted": ok, "policy_id": policy_id})
            except UniFiError as exc:
                logger.exception("delete_firewall_policy failed", extra={"policy_id": policy_id})
                return err(str(exc))

        pending = get_pending_actions().put(
            action="delete_firewall_policy",
            controller=controller,
            resource=resource,
            executor=_execute,
        )
        return format_preview_envelope(pending)
