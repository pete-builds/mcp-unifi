"""Shared helpers for the network module's per-resource files."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import TYPE_CHECKING

from mcp_unifi.config import Settings

if TYPE_CHECKING:
    from mcp_unifi.backends import Backend
    from mcp_unifi.models import UniFiRecord


def format_json(data: object) -> str:
    """Serialise a payload to the indented JSON the tools return."""
    result: str = json.dumps(data, indent=2, default=str)
    return result


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
