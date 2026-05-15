"""Observability tools: site health, WAN, events, alarms, speedtest, top talkers."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules.network._common import format_json, make_err

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.network.observability")


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool()
    @audited("get_site_health")
    async def get_site_health(controller: str = "default") -> str:
        """Per-subsystem health (wan, lan, wlan, www, vpn).

        Returns:
            JSON list with one record per subsystem: ``subsystem``, ``status``,
            and subsystem-specific metrics (e.g. WAN throughput, LAN client
            counts).
        """
        try:
            backend = registry.get(controller)
            return format_json(await backend.get_site_health())
        except UniFiError as exc:
            logger.exception("get_site_health failed")
            return err(str(exc))

    @mcp.tool()
    @audited("get_wan_status")
    async def get_wan_status(controller: str = "default") -> str:
        """Current WAN status: link state, ISP, public IP, throughput, latency.

        Convenience wrapper around ``get_site_health`` that returns just the
        WAN subsystem record.

        Returns:
            JSON object for the WAN subsystem, or ``{"subsystem": "wan",
            "status": "unknown"}`` if not reported.
        """
        try:
            backend = registry.get(controller)
            return format_json(await backend.get_wan_status())
        except UniFiError as exc:
            logger.exception("get_wan_status failed")
            return err(str(exc))

    @mcp.tool()
    @audited("list_events")
    async def list_events(limit: int = 50, controller: str = "default") -> str:
        """List recent controller events (connections, disconnections, etc.).

        Args:
            limit: Max number of events to return (default 50, max 1000).

        Returns:
            JSON list of event records.
        """
        if not 1 <= limit <= 1000:
            return err("limit must be between 1 and 1000")
        try:
            backend = registry.get(controller)
            return format_json(await backend.list_events(limit))
        except UniFiError as exc:
            logger.exception("list_events failed")
            return err(str(exc))

    @mcp.tool()
    @audited("list_alarms")
    async def list_alarms(
        limit: int = 50,
        archived: bool = False,
        controller: str = "default",
    ) -> str:
        """List controller alarms.

        Args:
            limit: Max number of alarms to return (default 50, max 1000).
            archived: ``True`` to list dismissed/archived alarms; ``False``
                (default) for active alarms only.

        Returns:
            JSON list of alarm records.
        """
        if not 1 <= limit <= 1000:
            return err("limit must be between 1 and 1000")
        try:
            backend = registry.get(controller)
            return format_json(await backend.list_alarms(limit, archived))
        except UniFiError as exc:
            logger.exception("list_alarms failed")
            return err(str(exc))

    @mcp.tool()
    @audited("trigger_speedtest")
    async def trigger_speedtest(controller: str = "default") -> str:
        """Kick off a UniFi speed test on the WAN link.

        The test runs server-side; this returns when the controller acks the
        command. Use ``get_speedtest_results`` to read the results once the
        test finishes (typically 30-60 seconds).

        Returns:
            JSON of the controller's response.
        """
        try:
            backend = registry.get(controller)
            return format_json(await backend.trigger_speedtest())
        except UniFiError as exc:
            logger.exception("trigger_speedtest failed")
            return err(str(exc))

    @mcp.tool()
    @audited("get_speedtest_results")
    async def get_speedtest_results(limit: int = 10, controller: str = "default") -> str:
        """Return recent speed-test results, newest first.

        Args:
            limit: Max number of results to return (default 10).

        Returns:
            JSON list of speed-test records: ``time``, ``xput_up``,
            ``xput_download``, ``latency``, ``server``.
        """
        if not 1 <= limit <= 1000:
            return err("limit must be between 1 and 1000")
        try:
            backend = registry.get(controller)
            return format_json(await backend.get_speedtest_results(limit))
        except UniFiError as exc:
            logger.exception("get_speedtest_results failed")
            return err(str(exc))

    @mcp.tool()
    @audited("list_top_talkers")
    async def list_top_talkers(limit: int = 10, controller: str = "default") -> str:
        """Top clients by total bytes (DPI by-station report).

        Returns:
            JSON list ranked by ``total_bytes`` descending: ``mac``,
            ``hostname``, ``ip``, ``tx_bytes``, ``rx_bytes``, ``total_bytes``.
        """
        if not 1 <= limit <= 1000:
            return err("limit must be between 1 and 1000")
        try:
            backend = registry.get(controller)
            return format_json(await backend.top_talkers(limit))
        except UniFiError as exc:
            logger.exception("list_top_talkers failed")
            return err(str(exc))
