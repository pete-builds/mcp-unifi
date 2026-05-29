"""Observability tools: site health, WAN, events, alarms, speedtest, top talkers."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.dispatcher import resolve_backend
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
        """Report per-subsystem health (wan, lan, wlan, www, vpn).

        Side effects: None (read-only).

        Returns one record per subsystem with ``subsystem``, ``status``, and
        subsystem-specific metrics (e.g. WAN throughput, LAN client counts).

        Example: get_site_health(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.get_site_health())
        except UniFiError as exc:
            logger.exception("get_site_health failed")
            return err(str(exc))

    @mcp.tool()
    @audited("get_wan_status")
    async def get_wan_status(controller: str = "default") -> str:
        """Report current WAN status: link, ISP, public IP, throughput, latency.

        Side effects: None (read-only).

        Convenience wrapper around ``get_site_health`` that returns just the
        WAN subsystem record. Returns ``{"subsystem": "wan", "status":
        "unknown"}`` if the controller does not report WAN.

        Example: get_wan_status(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.get_wan_status())
        except UniFiError as exc:
            logger.exception("get_wan_status failed")
            return err(str(exc))

    @mcp.tool()
    @audited("list_events")
    async def list_events(limit: int = 50, controller: str = "default") -> str:
        """List recent controller events (connections, disconnections, etc.).

        Side effects: None (read-only).

        Returns the most recent ``limit`` event records, newest first.

        Example: list_events(limit=100)

        Args:
            limit: Max number of events to return (default 50, max 1000).
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        if not 1 <= limit <= 1000:
            return err("limit must be between 1 and 1000")
        try:
            backend = resolve_backend(registry, controller)
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
        """List controller alarms, active or archived.

        Side effects: None (read-only).

        Returns the most recent ``limit`` alarm records.

        Example: list_alarms(limit=20, archived=False)

        Args:
            limit: Max number of alarms to return (default 50, max 1000).
            archived: ``True`` lists dismissed/archived alarms; ``False``
                (default) lists active alarms only.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        if not 1 <= limit <= 1000:
            return err("limit must be between 1 and 1000")
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.list_alarms(limit, archived))
        except UniFiError as exc:
            logger.exception("list_alarms failed")
            return err(str(exc))

    @mcp.tool()
    @audited("trigger_speedtest")
    async def trigger_speedtest(controller: str = "default") -> str:
        """Kick off a UniFi speed test on the WAN link.

        Side effects: None on the controller's persistent state. Issues a
        one-shot WAN measurement that consumes WAN bandwidth for ~30-60
        seconds while the test runs server-side. Use
        ``get_speedtest_results`` to read the result once it finishes.

        Example: trigger_speedtest(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.trigger_speedtest())
        except UniFiError as exc:
            logger.exception("trigger_speedtest failed")
            return err(str(exc))

    @mcp.tool()
    @audited("get_speedtest_results")
    async def get_speedtest_results(limit: int = 10, controller: str = "default") -> str:
        """List recent speed-test results, newest first.

        Side effects: None (read-only).

        Returns one record per test with ``time``, ``xput_up``,
        ``xput_download``, ``latency``, and ``server``.

        Example: get_speedtest_results(limit=10)

        Args:
            limit: Max number of results to return (default 10, max 1000).
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        if not 1 <= limit <= 1000:
            return err("limit must be between 1 and 1000")
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.get_speedtest_results(limit))
        except UniFiError as exc:
            logger.exception("get_speedtest_results failed")
            return err(str(exc))

    @mcp.tool()
    @audited("list_top_talkers")
    async def list_top_talkers(limit: int = 10, controller: str = "default") -> str:
        """List top clients by total bytes (DPI by-station report).

        Side effects: None (read-only).

        Returns one record per client ranked by ``total_bytes`` descending,
        with ``mac``, ``hostname``, ``ip``, ``tx_bytes``, ``rx_bytes``, and
        ``total_bytes``.

        Example: list_top_talkers(limit=10)

        Args:
            limit: Max number of clients to return (default 10, max 1000).
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        if not 1 <= limit <= 1000:
            return err("limit must be between 1 and 1000")
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.top_talkers(limit))
        except UniFiError as exc:
            logger.exception("list_top_talkers failed")
            return err(str(exc))
