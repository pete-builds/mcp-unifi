"""Build Integration API firewall policy bodies (ADR 0009).

Pure functions, no I/O. Every shape here comes from the published UniFi Network
10.6.106 reference for ``/v1/sites/{siteId}/firewall/policies`` (scraped
2026-10-12 into KallistoX/mcp-unifi-applications, read 2026-10-18). None of it
has been sent to a zone-based console yet: the site this server runs against
had not migrated when it was written. ADR 0008 found that same reference wrong
about which network and WLAN fields are required, so treat these bodies as the
documented shape, not a verified one, until a live write test says otherwise.

Each policy endpoint (``source`` or ``destination``) is a zone plus an optional
traffic filter. The filter is a discriminated union on ``type``; this module
builds the three a homelab needs:

- ``NETWORK``: match by network, with an optional port filter.
- ``IP_ADDRESS``: match by address, subnet or range, with an optional port filter.
- ``PORT``: match by port only.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence
from typing import Any

#: ``action.type`` values the console accepts.
ACTIONS: frozenset[str] = frozenset({"ALLOW", "BLOCK", "REJECT"})

#: ``ipProtocolScope.ipVersion`` values the console accepts.
IP_VERSIONS: frozenset[str] = frozenset({"IPV4", "IPV6", "IPV4_AND_IPV6"})

#: Protocol names this module maps onto ``ipProtocolScope.protocolFilter``.
PROTOCOLS: frozenset[str] = frozenset({"all", "tcp", "udp", "tcp_udp", "icmp", "icmpv6"})

#: Keys a PUT body may carry. ``id``, ``index`` and ``metadata`` are read-only.
WRITABLE_KEYS: frozenset[str] = frozenset(
    {
        "action",
        "connectionStateFilter",
        "description",
        "destination",
        "enabled",
        "ipProtocolScope",
        "ipsecFilter",
        "loggingEnabled",
        "name",
        "schedule",
        "source",
    }
)

#: ``metadata.origin`` of a policy an operator created. Anything else is
#: controller-managed (the predefined and derived return-traffic policies).
USER_DEFINED = "USER_DEFINED"


class PolicyBodyError(ValueError):
    """The requested policy cannot be expressed as an Integration API body."""


# ---------------------------------------------------------------------------
# Matchers
# ---------------------------------------------------------------------------


def port_items(spec: str) -> list[dict[str, Any]]:
    """Turn ``"80,443,8000-8100"`` into port-matching items.

    Raises :class:`PolicyBodyError` on anything that is not a port or a
    ``start-stop`` range within 1-65535.
    """
    items: list[dict[str, Any]] = []
    for raw in spec.split(","):
        part = raw.strip()
        if not part:
            continue
        try:
            if "-" in part:
                start_s, stop_s = part.split("-", 1)
                start, stop = int(start_s), int(stop_s)
                _check_port(start)
                _check_port(stop)
                if start > stop:
                    raise PolicyBodyError(f"port range {part!r} runs backwards")
                items.append({"type": "PORT_NUMBER_RANGE", "start": start, "stop": stop})
            else:
                port = int(part)
                _check_port(port)
                items.append({"type": "PORT_NUMBER", "value": port})
        except ValueError as exc:
            if isinstance(exc, PolicyBodyError):
                raise
            raise PolicyBodyError(f"not a port or port range: {part!r}") from exc
    return items


def _check_port(port: int) -> None:
    if not 1 <= port <= 65535:
        raise PolicyBodyError(f"port {port} out of range (1-65535)")


def address_items(addresses: Iterable[str]) -> list[dict[str, Any]]:
    """Turn addresses, subnets and ``a-b`` ranges into IP-matching items."""
    items: list[dict[str, Any]] = []
    for raw in addresses:
        value = raw.strip()
        if not value:
            continue
        try:
            if "-" in value:
                start_s, stop_s = (s.strip() for s in value.split("-", 1))
                start, stop = ipaddress.ip_address(start_s), ipaddress.ip_address(stop_s)
                if start.version != stop.version or int(start) > int(stop):
                    raise PolicyBodyError(f"address range {value!r} is not a valid range")
                items.append({"type": "IP_ADDRESS_RANGE", "start": start_s, "stop": stop_s})
            elif "/" in value:
                network = ipaddress.ip_network(value, strict=False)
                items.append({"type": "SUBNET", "value": str(network)})
            else:
                ipaddress.ip_address(value)
                items.append({"type": "IP_ADDRESS", "value": value})
        except ValueError as exc:
            if isinstance(exc, PolicyBodyError):
                raise
            raise PolicyBodyError(f"not an address, subnet or range: {value!r}") from exc
    return items


def endpoint(
    zone_id: str,
    *,
    network_ids: Sequence[str] = (),
    addresses: Sequence[str] = (),
    ports: str = "",
) -> dict[str, Any]:
    """Build one ``source`` or ``destination`` object.

    ``network_ids`` are Integration API network ids, not private ``_id``
    values. A side matches by networks or by addresses, never both: the
    console's traffic filter holds exactly one of them.
    """
    if network_ids and addresses:
        raise PolicyBodyError("match by networks or by addresses on one side, not both")
    port_filter = (
        {"type": "PORTS", "matchOpposite": False, "items": port_items(ports)} if ports else None
    )
    if port_filter is not None and not port_filter["items"]:
        port_filter = None
    out: dict[str, Any] = {"zoneId": zone_id}
    traffic: dict[str, Any] | None = None
    if network_ids:
        traffic = {
            "type": "NETWORK",
            "networkFilter": {"matchOpposite": False, "networkIds": list(network_ids)},
        }
    elif addresses:
        items = address_items(addresses)
        if items:
            traffic = {
                "type": "IP_ADDRESS",
                "ipAddressFilter": {"type": "IP_ADDRESSES", "matchOpposite": False, "items": items},
            }
    if traffic is None and port_filter is not None:
        traffic = {"type": "PORT"}
    if traffic is not None:
        if port_filter is not None:
            traffic["portFilter"] = port_filter
        out["trafficFilter"] = traffic
    return out


def protocol_scope(protocol: str, ip_version: str) -> dict[str, Any]:
    """Build ``ipProtocolScope`` for a protocol name and IP version."""
    proto = protocol.strip().lower()
    version = ip_version.strip().upper()
    if proto not in PROTOCOLS:
        raise PolicyBodyError(f"protocol {protocol!r} not one of {sorted(PROTOCOLS)}")
    if version not in IP_VERSIONS:
        raise PolicyBodyError(f"ip_version {ip_version!r} not one of {sorted(IP_VERSIONS)}")
    scope: dict[str, Any] = {"ipVersion": version}
    if proto == "all":
        return scope
    if proto == "tcp_udp":
        scope["protocolFilter"] = {"type": "PRESET", "preset": {"name": "TCP_UDP"}}
        return scope
    if proto == "icmp" and version != "IPV4":
        raise PolicyBodyError("icmp matches IPv4 only; use icmpv6 with ip_version IPV6")
    if proto == "icmpv6" and version != "IPV6":
        raise PolicyBodyError("icmpv6 matches IPv6 only; set ip_version to IPV6")
    scope["protocolFilter"] = {
        "type": "NAMED_PROTOCOL",
        "matchOpposite": False,
        "protocol": {"name": proto.upper()},
    }
    return scope


def action_body(action: str, *, allow_return_traffic: bool = True) -> dict[str, Any]:
    """Build ``action``. ``allowReturnTraffic`` exists only on ALLOW."""
    kind = action.strip().upper()
    if kind not in ACTIONS:
        raise PolicyBodyError(f"action {action!r} not one of {sorted(ACTIONS)}")
    out: dict[str, Any] = {"type": kind}
    if kind == "ALLOW":
        out["allowReturnTraffic"] = allow_return_traffic
    return out


# ---------------------------------------------------------------------------
# Whole bodies
# ---------------------------------------------------------------------------


def create_body(
    *,
    name: str,
    action: str,
    source: dict[str, Any],
    destination: dict[str, Any],
    protocol: str = "all",
    ip_version: str = "IPV4",
    allow_return_traffic: bool = True,
    enabled: bool = True,
    logging: bool = False,
    description: str = "",
    connection_states: Sequence[str] = (),
) -> dict[str, Any]:
    """Build a POST body. ``source``/``destination`` come from :func:`endpoint`."""
    if not name.strip():
        raise PolicyBodyError("name must not be empty")
    has_ports = any(
        isinstance(side.get("trafficFilter"), dict) and "portFilter" in side["trafficFilter"]
        for side in (source, destination)
    )
    if has_ports and protocol.strip().lower() not in {"tcp", "udp", "tcp_udp"}:
        raise PolicyBodyError("a port match needs protocol tcp, udp or tcp_udp")
    body: dict[str, Any] = {
        "name": name,
        "enabled": enabled,
        "loggingEnabled": logging,
        "action": action_body(action, allow_return_traffic=allow_return_traffic),
        "source": source,
        "destination": destination,
        "ipProtocolScope": protocol_scope(protocol, ip_version),
    }
    if description:
        body["description"] = description
    states = [s.strip().upper() for s in connection_states if s.strip()]
    if states:
        body["connectionStateFilter"] = states
    return body


def put_body(current: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    """Merge top-level ``changes`` onto a GET readback to form a PUT body.

    The PUT replaces the whole policy, so the body starts from what the console
    returned, minus its read-only keys. Raises on a key the PUT does not take.
    """
    unknown = sorted(set(changes) - WRITABLE_KEYS)
    if unknown:
        raise PolicyBodyError(f"not a writable policy field: {', '.join(unknown)}")
    body = {k: v for k, v in current.items() if k in WRITABLE_KEYS}
    body.update(changes)
    return body


# ---------------------------------------------------------------------------
# Lookups over Integration API records
# ---------------------------------------------------------------------------


def find_by_id_or_name(records: Iterable[dict[str, Any]], ref: str) -> list[dict[str, Any]]:
    """Records whose ``id`` equals ``ref``, else whose name matches it.

    Name matching ignores case. More than one result means the name is
    ambiguous and the caller should ask for the id.
    """
    pool = [r for r in records if isinstance(r, dict)]
    by_id = [r for r in pool if r.get("id") == ref]
    if by_id:
        return by_id
    wanted = ref.strip().casefold()
    return [r for r in pool if str(r.get("name", "")).casefold() == wanted]


def zone_of_network(zones: Iterable[dict[str, Any]], network_id: str) -> dict[str, Any] | None:
    """The zone whose ``networkIds`` holds the Integration API ``network_id``."""
    for zone in zones:
        if isinstance(zone, dict) and network_id in (zone.get("networkIds") or []):
            return zone
    return None


def is_user_defined(record: dict[str, Any]) -> bool:
    """True when an operator created this policy, not the controller."""
    metadata = record.get("metadata")
    return isinstance(metadata, dict) and metadata.get("origin") == USER_DEFINED
