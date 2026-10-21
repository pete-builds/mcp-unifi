"""Zone-policy equivalents of the composites' legacy firewall rules (ADR 0009).

On a legacy site the composites write a ``LAN_IN`` drop or a ``LAN_LOCAL``
accept. On a zone-based site those rulesets are gone, so the same intent is
expressed as a zone policy matched by address, which carries the composite's
meaning without depending on which zone a new network lands in:

- isolation (``create_iot_network``, ``create_guest_network``): BLOCK from the
  new subnet to the main LAN subnet.
- service allow (``provision_homelab_service``): ALLOW from the ``Internal``
  zone to the service IP on its TCP ports.

Zones are resolved from the networks involved. When a network's zone cannot
be found (for example a network created a moment ago that the zone list does
not show yet), the zone named ``Internal`` is used and the policy description
says so, so the substitution is visible on the console.
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING, Any

from mcp_unifi.clients import zone_policy as zp
from mcp_unifi.clients.unifi import UniFiError

if TYPE_CHECKING:
    from mcp_unifi.backends import Backend

FALLBACK_ZONE = "Internal"


async def site_is_zone_based(backend: Backend) -> bool:
    """True only when the Integration API reports a configured Zone-Based Firewall."""
    return await backend.zone_firewall_state() == "configured"


def _zone_id(zones: list[dict[str, Any]], name: str) -> str:
    matches = zp.find_by_id_or_name(zones, name)
    if len(matches) != 1 or not isinstance(matches[0].get("id"), str):
        raise UniFiError(f"zone-based site has no single zone named {name!r}")
    return str(matches[0]["id"])


async def _zone_for_network(
    backend: Backend, zones: list[dict[str, Any]], private_id: str | None, notes: list[str]
) -> str:
    v1_id = await backend.v1_network_id(private_id) if private_id else None
    zone = zp.zone_of_network(zones, v1_id) if v1_id else None
    if zone is not None and isinstance(zone.get("id"), str):
        return str(zone["id"])
    notes.append(f"zone of network {private_id} not found; used {FALLBACK_ZONE}")
    return _zone_id(zones, FALLBACK_ZONE)


async def _network_holding(backend: Backend, subnet: str) -> str | None:
    """Private ``_id`` of the network whose ``ip_subnet`` contains ``subnet``."""
    try:
        wanted = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return None
    for net in await backend.list_networks():
        raw = net.get("ip_subnet")
        if not isinstance(raw, str):
            continue
        try:
            have = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if wanted.version == have.version and wanted.subnet_of(have):  # type: ignore[arg-type]
            nid = net.get("_id")
            return nid if isinstance(nid, str) else None
    return None


async def isolation_policy(
    backend: Backend,
    *,
    name: str,
    network_id: str,
    subnet: str,
    main_lan_subnet: str,
) -> dict[str, Any]:
    """BLOCK ``subnet`` from reaching ``main_lan_subnet``, as a v1 policy body."""
    zones = await backend.list_v1_firewall_zones()
    notes: list[str] = []
    source_zone = await _zone_for_network(backend, zones, network_id, notes)
    dest_zone = await _zone_for_network(
        backend, zones, await _network_holding(backend, main_lan_subnet), notes
    )
    return zp.create_body(
        name=f"Block {name} -> Main LAN",
        action="BLOCK",
        source=zp.endpoint(source_zone, addresses=[subnet]),
        destination=zp.endpoint(dest_zone, addresses=[main_lan_subnet]),
        description="; ".join(["created by mcp-unifi", *notes]),
    )


async def service_policy(
    backend: Backend,
    *,
    name: str,
    network_id: str,
    ip: str,
    ports: list[int],
) -> dict[str, Any]:
    """ALLOW ``Internal`` to reach ``ip`` on TCP ``ports``, as a v1 policy body."""
    zones = await backend.list_v1_firewall_zones()
    notes: list[str] = []
    dest_zone = await _zone_for_network(backend, zones, network_id, notes)
    return zp.create_body(
        name=f"Allow {name}",
        action="ALLOW",
        source=zp.endpoint(_zone_id(zones, FALLBACK_ZONE)),
        destination=zp.endpoint(
            dest_zone,
            addresses=[ip],
            ports=",".join(str(p) for p in ports),
        ),
        protocol="tcp",
        description="; ".join(["created by mcp-unifi", *notes]),
    )


def policy_preview(kind: str, **fields: Any) -> dict[str, Any]:
    """What a dry run shows on a zone-based site, before any zone is resolved."""
    return {"kind": kind, "api": "integration/v1", **fields}
