"""Network module — VLANs, WLANs, firewall, ports, clients, observability.

The dispatcher imports this package and calls :func:`register`. Each
per-resource file in this package defines a ``register(mcp, settings, registry)``
function that wires its own ``@mcp.tool()`` definitions onto the FastMCP
instance.

Tool surface is byte-identical to v0.4.x except for the new
``controller: str = "default"`` parameter on every tool. That parameter
addresses one of ``settings.controllers`` and is the only multi-site entry
point a caller needs.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mcp_unifi.modules.network import (
    backup,
    clients,
    composites,
    confirm,
    content_filtering,
    devices,
    dhcp,
    drift,
    dynamic_dns,
    firewall,
    honeypot,
    ipv6,
    observability,
    port_forwards,
    port_profiles,
    routing,
    stats,
    teleport,
    threat_management,
    traffic,
    vlans,
    wlans,
)

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    """Register every Network tool on ``mcp``.

    Order matters only for clarity (it shows up in tool-list output): VLAN
    primitives first, then WLANs, firewall, port profiles, switch / client
    ops, leases, port forwards, observability, then composites that compose
    the primitives.
    """
    vlans.register(mcp, settings, registry)
    ipv6.register(mcp, settings, registry)
    wlans.register(mcp, settings, registry)
    firewall.register(mcp, settings, registry)
    routing.register(mcp, settings, registry)
    traffic.register(mcp, settings, registry)
    content_filtering.register(mcp, settings, registry)
    dynamic_dns.register(mcp, settings, registry)
    port_profiles.register(mcp, settings, registry)
    devices.register(mcp, settings, registry)
    clients.register(mcp, settings, registry)
    dhcp.register(mcp, settings, registry)
    port_forwards.register(mcp, settings, registry)
    observability.register(mcp, settings, registry)
    stats.register(mcp, settings, registry)
    threat_management.register(mcp, settings, registry)
    honeypot.register(mcp, settings, registry)
    teleport.register(mcp, settings, registry)
    composites.register(mcp, settings, registry)
    drift.register(mcp, settings, registry)
    backup.register(mcp, settings, registry)
    # ``confirm_destructive_action`` is registered last so it shows up after
    # the destructive tools it pairs with in tool-list output.
    confirm.register(mcp, settings, registry)


__all__ = ["register"]
