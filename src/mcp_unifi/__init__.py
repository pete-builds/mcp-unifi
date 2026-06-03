"""mcp-unifi — MCP server for self-hosted UniFi gateways.

Forty-one tools covering devices, networks/VLANs, WLANs (full CRUD), firewall
rules (full CRUD), switch port profiles (full CRUD), connected clients
(block / unblock / reconnect / quarantine), per-port state (PoE + enable +
profile), static DHCP leases, port forwarding (full CRUD), site health, WAN
status, events, alarms, speed tests, DPI top talkers, and four composite
operations: ``create_iot_network``, ``provision_homelab_service``,
``quarantine_client``, ``create_guest_network``, plus the read-only
``audit_open_ports`` review.

Stub mode (``STUB_MODE=true``, default) returns realistic in-memory mock data
so the server is useful before any UniFi hardware is on the network. Flip
``STUB_MODE=false`` and supply ``UNIFI_HOST`` plus ``UNIFI_API_KEY`` to talk to
a real UCG-Fiber, UDM Pro, or other UniFi OS gateway.
"""

from __future__ import annotations

__version__ = "0.11.0"
