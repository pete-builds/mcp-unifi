"""Shared helpers for the network module's per-resource files."""

from __future__ import annotations

import json
from collections.abc import Callable

from mcp_unifi.config import Settings


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
