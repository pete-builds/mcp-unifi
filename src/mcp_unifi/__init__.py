"""mcp-unifi — MCP server for self-hosted UniFi gateways.

Eleven tools covering devices, networks/VLANs, WLANs, firewall rules, switch
port profiles, and a one-shot ``create_iot_network`` composite that provisions
an isolated IoT subnet in a single call.

Stub mode (``STUB_MODE=true``, default) returns realistic in-memory mock data
so the server is useful before any UniFi hardware is on the network. Flip
``STUB_MODE=false`` and supply ``UNIFI_HOST`` plus ``UNIFI_API_KEY`` to talk to
a real UCG-Fiber, UDM Pro, or other UniFi OS gateway.
"""

from __future__ import annotations

__version__ = "0.1.0"
