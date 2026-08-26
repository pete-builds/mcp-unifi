"""Stats & insights tools: system info, gateway/device/client stats, sessions,
anomalies. Wave C — every tool here is READ-ONLY (no writes, no dry_run).

Endpoints were probed read-only against a live UCG-Fiber (UniFi Network
10.4.57, 2026-06-12) before these tools were built. Endpoints with no live
surface on this firmware were deferred rather than shipped as phantom tools:

* IPS/IDS threat events — ``/stat/ips/event`` (404), ``/stat/ips/events`` (404),
  ``/rest/ips`` (400), ``/stat/threat`` (404). No working route → no tool.
* DPI app/category traffic — ``/stat/dpi``, ``/stat/sitedpi``, ``/stat/stadpi``
  all return empty (DPI not populated on this gateway) and the reference dicts
  ``/stat/dpiapp`` / ``/stat/dpigroup`` 404. The existing ``list_top_talkers``
  already wraps the by-station ``/stat/sitedpi`` view, so a ``get_top_clients``
  would duplicate it. No DPI tools built.
* Per-subsystem health — already covered by ``get_site_health`` (it passes the
  full ``/stat/health`` record through), so a separate ``get_network_health``
  is omitted to avoid duplication.

``get_gateway_stats`` and ``get_device_stats`` are device-record readers: both
start from a ``/stat/device`` record and flatten it through
:mod:`mcp_unifi.clients.stats_shape`. That shaping is an allowlist, so it
keeps ``x_authkey`` and ``x_vwirekey`` out today; both tools redact anyway,
because an allowlist that grows later is a leak that ships quietly. See
:mod:`mcp_unifi.redaction`.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from mcp_unifi.annotations import READ_ONLY
from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.dispatcher import resolve_backend
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules.network._common import format_json, make_err
from mcp_unifi.redaction import redact

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.network.stats")


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_system_info", mutates=False)
    async def get_system_info(controller: str = "default") -> str:
        """Report controller/system info: version, uptime, device type.

        Side effects: None (read-only).

        Returns a single record with ``version``, ``build``,
        ``previous_version``, ``hostname``, ``name``, ``uptime`` (seconds),
        ``timezone``, ``ubnt_device_type``, ``udm_version``,
        ``console_display_version``, and ``update_available``. Use it to check
        the firmware level and whether an update is pending.

        Example: get_system_info(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.get_system_info())
        except UniFiError as exc:
            logger.exception("get_system_info failed")
            return err(str(exc))

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_gateway_stats", mutates=False)
    async def get_gateway_stats(controller: str = "default") -> str:
        """Report gateway resource stats: CPU, memory, temperature, throughput.

        Side effects: None (read-only).

        Returns a single record for the gateway (UCG/UDM) with ``cpu_pct``,
        ``mem_pct``, ``temperatures`` (a list of ``{name, type, value}`` in
        degrees C), ``uptime`` (seconds), ``tx_bytes``/``rx_bytes``,
        ``num_sta``, ``last_wan_ip``, and ``speedtest_status``. Returns ``{}``
        if no gateway device is adopted on this controller.

        Example: get_gateway_stats(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            return format_json(redact(await backend.get_gateway_stats()))
        except UniFiError as exc:
            logger.exception("get_gateway_stats failed")
            return err(str(exc))

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_device_stats", mutates=False)
    async def get_device_stats(mac: str, controller: str = "default") -> str:
        """Report per-device stats for one UniFi device by MAC.

        Side effects: None (read-only).

        Returns a record with ``name``, ``model``, ``type``, ``state``,
        ``uptime`` (seconds), ``cpu_pct``, ``mem_pct``, ``satisfaction``,
        ``num_sta``, ``tx_bytes``/``rx_bytes``, and (for access points)
        ``tx_retries``/``tx_packets``/``rx_packets``. Returns a NOT_FOUND
        error envelope if no adopted device matches ``mac``.

        Example: get_device_stats(mac="f4:e2:c6:00:00:02")

        Args:
            mac: MAC address of the device (gateway, AP, or switch).
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            record = await backend.get_device_stats(mac)
            if record is None:
                return err(f"device {mac} not found")
            return format_json(redact(record))
        except UniFiError as exc:
            logger.exception("get_device_stats failed")
            return err(str(exc))

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_client_stats", mutates=False)
    async def get_client_stats(mac: str, controller: str = "default") -> str:
        """Report per-client traffic, signal, and uptime for one client by MAC.

        Side effects: None (read-only).

        Returns a record with ``hostname``, ``name``, ``ip``, ``is_wired``,
        ``network``, ``essid``, ``uptime``, ``first_seen``/``last_seen``,
        ``signal``/``rssi``/``satisfaction`` (wireless), ``tx_rate``/``rx_rate``,
        ``tx_bytes``/``rx_bytes``, ``tx_retries``, ``anomalies``, and the wired
        ``wired_rate_mbps``/``wired_tx_bytes``/``wired_rx_bytes`` fields when
        present. Returns a NOT_FOUND error envelope if the client is not
        currently connected.

        Example: get_client_stats(mac="aa:bb:cc:00:00:01")

        Args:
            mac: MAC address of the connected client.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            record = await backend.get_client_stats(mac)
            if record is None:
                return err(f"client {mac} not found or not currently connected")
            return format_json(record)
        except UniFiError as exc:
            logger.exception("get_client_stats failed")
            return err(str(exc))

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_client_sessions", mutates=False)
    async def get_client_sessions(
        mac: str = "",
        hours: int = 24,
        limit: int = 50,
        controller: str = "default",
    ) -> str:
        """List recent client connection sessions over a time window.

        Side effects: None (read-only).

        Returns one record per association, newest first, with ``mac``,
        ``hostname``, ``name``, ``ip``, ``assoc_time`` (epoch seconds),
        ``duration`` (seconds), ``rx_bytes``/``tx_bytes``, ``is_wired``,
        ``is_guest``, ``ap_mac``, and ``satisfaction``. Pass ``mac`` to scope
        to one client; omit it for every client's sessions in the window.

        Example: get_client_sessions(mac="aa:bb:cc:00:00:01", hours=48, limit=20)

        Args:
            mac: MAC address to filter to one client. Empty (default) returns
                sessions for all clients.
            hours: Look-back window in hours (default 24, max 720 = 30 days).
            limit: Max number of sessions to return (default 50, max 1000).
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        if not 1 <= hours <= 720:
            return err("hours must be between 1 and 720")
        if not 1 <= limit <= 1000:
            return err("limit must be between 1 and 1000")
        end = int(time.time())
        start = end - hours * 3600
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.get_client_sessions(mac, start, end, limit))
        except UniFiError as exc:
            logger.exception("get_client_sessions failed")
            return err(str(exc))

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_anomalies", mutates=False)
    async def get_anomalies(controller: str = "default") -> str:
        """List client-impacting anomalies the controller has detected.

        Side effects: None (read-only).

        Returns one record per anomaly with ``anomaly`` (an enum string such
        as ``USER_HIGH_TCP_LATENCY`` or ``USER_DNS_LATENCY``), ``mac`` (the
        affected client), and ``timestamps`` (a list of epoch-ms occurrence
        times). Returns an empty list on a clean network.

        Example: get_anomalies(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.get_anomalies())
        except UniFiError as exc:
            logger.exception("get_anomalies failed")
            return err(str(exc))
