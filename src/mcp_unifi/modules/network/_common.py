"""Shared helpers for the network module's per-resource files."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from mcp_unifi.config import Settings
from mcp_unifi.redaction import redact

if TYPE_CHECKING:
    from mcp_unifi.backends import Backend
    from mcp_unifi.models import UniFiRecord


def dump_json(data: object) -> str:
    """Serialise a payload to indented JSON **without** redacting it.

    Not for tool responses. The one legitimate caller is
    :func:`~mcp_unifi.modules.network._pending.format_preview_envelope`, which
    has already run :func:`redact` over everything except the preview
    ``token`` the caller must hand back to ``confirm_destructive_action``.
    Every tool response goes through :func:`format_json`.
    """
    result: str = json.dumps(data, indent=2, default=str)
    return result


def format_json(data: object) -> str:
    """Serialise a tool response with sensitive keys redacted.

    This is the single serialiser every module's tools return through, so
    redaction is enforced here rather than left to each tool. Before this,
    ``redact`` ran only where a module remembered to call it, and the
    invariant "if it returns a controller record, it calls redact" was
    violated by 24 of the 84 Network tools a stub-mode sweep could call
    (``list_firewall_rules``, ``list_port_forwards``, ``list_routes``,
    ``audit_open_ports`` and the rest): none of those records carries a
    secret on today's firmware, which is exactly how the gap survived, and
    issue #124 showed a newer firmware adding secret-shaped fields to a
    record type that had none. Redacting at the serialiser means a record
    that grows a secret field is covered the day it appears, and a new tool
    is covered before its author thinks about it.

    The per-tool ``redact`` calls that already exist are harmless (the walk
    is idempotent) and stay as documentation of which records are known to
    carry secrets.
    """
    return dump_json(redact(data))


def make_err(settings: Settings) -> Callable[[str], str]:
    """Return an ``err(msg)`` helper bound to the current settings.

    Tool error envelopes always include ``stub_mode`` so callers can tell
    which controller surface they're talking to. Keeping the helper inside the
    module avoids each tool re-importing the formatter.
    """

    def err(msg: str) -> str:
        return format_json({"error": msg, "stub_mode": settings.stub_mode})

    return err


def subnet_to_dhcp(
    subnet: str, dhcp_start_offset: int, dhcp_stop_offset: int
) -> tuple[str, str, str]:
    """Compute (gateway, dhcp_start, dhcp_stop) from a /24 subnet string.

    Only handles /24s — that is what create_iot_network templates produce.
    Callers can pass explicit dhcp_start/dhcp_stop to create_vlan instead.
    """
    base = subnet.split("/")[0].rsplit(".", 1)[0]
    return (
        f"{base}.1",
        f"{base}.{dhcp_start_offset}",
        f"{base}.{dhcp_stop_offset}",
    )


def subnet_to_network_form(subnet: str) -> str:
    """Return the network-address form of a subnet (``10.0.50.0/24``).

    Inverse of :func:`normalize_ip_subnet`. Firewall src/dst CIDR fields read
    cleaner in network form than gateway form (even though UniFi accepts
    either since CIDR is bit-masked). /24 only; other masks pass through
    unchanged.
    """
    if "/" not in subnet:
        return subnet
    host, _, mask = subnet.partition("/")
    if mask != "24":
        return subnet
    octets = host.split(".")
    if len(octets) != 4:
        return subnet
    if octets[3] != "0":
        octets[3] = "0"
        return f"{'.'.join(octets)}/{mask}"
    return subnet


def normalize_ip_subnet(subnet: str) -> str:
    """Normalize a subnet string to UniFi's ``<gateway-ip>/<mask>`` form.

    UniFi stores the gateway IP (the first usable host, ``.1`` for a /24)
    inside ``ip_subnet`` — not the network address. Callers who pass the
    network form (``10.0.50.0/24``) get auto-promoted to gateway form
    (``10.0.50.1/24``). Callers who already pass gateway form are returned
    unchanged. Anything that doesn't parse as ``host/mask`` is returned as-is
    and left for the controller to reject.

    Only /24-shaped strings are normalized for now; that matches the
    network-segmentation rollout (the only path that hits this helper) and
    avoids accidentally rewriting subnets the caller already crafted.
    """
    if "/" not in subnet:
        return subnet
    host, _, mask = subnet.partition("/")
    if mask != "24":
        return subnet
    octets = host.split(".")
    if len(octets) != 4:
        return subnet
    # ``0`` → network address, promote the last octet to ``1`` (gateway).
    if octets[3] == "0":
        octets[3] = "1"
        return f"{'.'.join(octets)}/{mask}"
    return subnet


async def resolve_default_ap_group(backend: Backend) -> list[str]:
    """Return ``[default_group._id]`` so ``create_wlan`` can default cleanly.

    UniFi controllers reject ``POST /rest/wlanconf`` with
    ``api.err.ApGroupMissing`` when ``ap_group_ids`` is absent. Every
    controller ships with a "default" AP group; this helper picks it via the
    ``attr_hidden_id == "default"`` marker, falling back to the first group
    if no marker is set. Returns an empty list when the controller returns
    no groups at all so the tool can surface a clear error instead of
    silently sending an empty list to UniFi.
    """
    groups: list[UniFiRecord] = await backend.list_ap_groups()
    if not groups:
        return []
    for group in groups:
        if isinstance(group, dict) and group.get("attr_hidden_id") == "default":
            gid = group.get("_id")
            if isinstance(gid, str):
                return [gid]
    # No "default"-marked group; fall back to the first group with an _id.
    for group in groups:
        if isinstance(group, dict):
            gid = group.get("_id")
            if isinstance(gid, str):
                return [gid]
    return []


# ---------------------------------------------------------------------------
# Zone-Based Firewall helpers (shared by audit_open_ports and drift)
# ---------------------------------------------------------------------------

#: Lowercased ``zone_key`` values the controller uses for the internet-facing
#: zone. UniFi names that zone "External" in the UI; ``wan`` is the key seen
#: in captured records.
_WAN_ZONE_KEYS: frozenset[str] = frozenset({"wan", "external"})

#: Lowercased zone names that front the public internet, for controllers
#: whose WAN zone carries no ``zone_key`` or has been renamed. "External" is
#: the controller's own default name (captured 2026-09-07 readback); "WAN"
#: and "Internet" cover renames.
_WAN_ZONE_NAMES: frozenset[str] = frozenset({"wan", "external", "internet"})


def zone_names_by_id(zones: list[Any]) -> dict[str, str]:
    """Map ``zone._id`` to a display name (``name``, else ``zone_key``)."""
    out: dict[str, str] = {}
    for zone in zones:
        if not isinstance(zone, dict) or not zone.get("_id"):
            continue
        out[str(zone["_id"])] = str(zone.get("name") or zone.get("zone_key") or "")
    return out


def wan_zone_ids(zones: list[Any]) -> set[str]:
    """Ids of every Zone-Based Firewall zone that faces the internet.

    ``zone_key`` is the controller's own marker and is checked first. The
    name fallback covers a record with no key and the default "External"
    label the UI shows. An empty result on a site that has policies means
    "could not classify", and the callers say so rather than reporting a
    clean WAN.
    """
    out: set[str] = set()
    for zone in zones:
        if not isinstance(zone, dict) or not zone.get("_id"):
            continue
        key = str(zone.get("zone_key") or "").lower()
        name = str(zone.get("name") or "").lower()
        if key in _WAN_ZONE_KEYS or name in _WAN_ZONE_NAMES:
            out.add(str(zone["_id"]))
    return out
