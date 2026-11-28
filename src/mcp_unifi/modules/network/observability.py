"""Observability tools: site health, WAN, events, alarms, IPS detections, speedtest, top talkers."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from mcp_unifi.annotations import ACTION, READ_ONLY
from mcp_unifi.clients.system_log import client_matcher
from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.dispatcher import resolve_backend
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules.network._common import format_json, make_err

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.network.observability")

#: Longest look-back the log tools accept, in hours (30 days).
MAX_LOG_HOURS = 720


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_site_health", mutates=False)
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

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_wan_status", mutates=False)
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

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_events", mutates=False)
    async def list_events(limit: int = 50, hours: int = 24, controller: str = "default") -> str:
        """List the controller's event log (connections, WAN changes, updates, admin activity).

        Side effects: None (read-only).

        Reads the v2 system log (``POST .../v2/api/site/<site>/system-log/all``)
        in place of the legacy ``/stat/event`` route, which newer
        consoles no longer serve. Only when the v2 route is absent (an older
        controller) does it fall back to ``/stat/event``. If the log cannot be
        read, the call returns an error naming the exact path and HTTP status, never an empty
        list, so an empty ``events`` list really means nothing was logged in
        the window.

        Returns an envelope: ``source`` (the route that answered), ``window``,
        ``window_fully_read`` (false, with a ``note``, when the window was not
        read to the end), ``total`` (entries the controller holds for the
        window), ``returned``, ``more_available``, and ``events``, newest
        first. Each
        event keeps the controller's fields (``timestamp`` in ms, ``category``,
        ``key``, ``severity``, ``parameters``) plus ``time`` (UTC) and a
        rendered ``message``. Stub mode returns sample events with
        ``source`` saying so.

        Example: list_events(limit=100, hours=48)

        Args:
            limit: Max number of events to return (default 50, max 1000).
            hours: How far back to read, in hours (default 24, max 720).
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        if not 1 <= limit <= 1000:
            return err("limit must be between 1 and 1000")
        if not 1 <= hours <= MAX_LOG_HOURS:
            return err(f"hours must be between 1 and {MAX_LOG_HOURS}")
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.list_events(limit, hours))
        except UniFiError as exc:
            logger.exception("list_events failed")
            return err(str(exc))

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_alarms", mutates=False)
    async def list_alarms(
        limit: int = 50,
        archived: bool = False,
        hours: int = 24,
        controller: str = "default",
    ) -> str:
        """List controller alarms: the critical system log, or archived legacy alarms.

        Side effects: None (read-only).

        Active alarms (``archived=False``) come from the v2 critical system log
        (``POST .../v2/api/site/<site>/system-log/critical``) in place of the
        legacy ``/list/alarm`` route, which newer consoles no
        longer serve; the
        legacy route is tried only when the v2 one is absent. The v2 log has no
        archived state, so ``archived=True`` reads the legacy route alone and
        returns an error where that route is gone. Any failure is an error
        naming the exact path and HTTP status, never an empty list.

        Returns an envelope: ``source``, ``window``, ``window_fully_read``,
        ``total``, ``returned``, ``more_available``, and ``alarms``, newest
        first. Stub mode returns
        sample alarms with ``source`` saying so.

        Example: list_alarms(limit=20, hours=72)

        Args:
            limit: Max number of alarms to return (default 50, max 1000).
            archived: ``True`` lists dismissed/archived alarms (legacy
                controllers only); ``False`` (default) lists the critical log.
            hours: How far back to read the critical log, in hours (default
                24, max 720). Not used for archived alarms.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        if not 1 <= limit <= 1000:
            return err("limit must be between 1 and 1000")
        if not 1 <= hours <= MAX_LOG_HOURS:
            return err(f"hours must be between 1 and {MAX_LOG_HOURS}")
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.list_alarms(limit, archived, hours))
        except UniFiError as exc:
            logger.exception("list_alarms failed")
            return err(str(exc))

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_threat_detections", mutates=False)
    async def list_threat_detections(
        hours: int = 24,
        client: str = "",
        limit: int = 100,
        controller: str = "default",
    ) -> str:
        """List what Threat Management (IDS/IPS) detected or blocked, newest first.

        Side effects: None (read-only).

        Reads two v2 sources and merges them: intrusion-prevention matches from
        ``POST .../v2/api/site/<site>/traffic-flows`` (ports, protocol,
        signature, action) and ``POST .../system-log/threat-alert`` (the
        console's alerts, including honeypot hits; no ports or signature).
        Each detection has ``time``, ``action`` (``blocked``, ``alerted`` or
        ``unknown``), ``src_ip``, ``src_port``, ``dst_ip``, ``dst_port``,
        ``protocol``, ``signature``, ``category``, ``severity``,
        ``client_name`` when the controller knows it, and ``source``.

        If both sources fail the call returns an error naming each path and
        HTTP status. If one fails, or the window holds more rows than one call
        reads, the envelope opens with ``warning`` and ``complete: false``,
        because a partial list is not proof nothing was blocked. ``sources`` reports what each route returned. Use
        ``get_threat_management`` for the IPS settings themselves.

        Example: list_threat_detections(hours=24, client="192.0.2.20")

        Args:
            hours: How far back to read, in hours (default 24, max 720).
            client: Keep only detections with this IP or MAC at either end.
                A honeypot hit that names the device by MAC alone matches
                only a MAC. Empty (default) returns every detection.
            limit: Max number of detections to return (default 100, max 1000).
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        if not 1 <= limit <= 1000:
            return err("limit must be between 1 and 1000")
        if not 1 <= hours <= MAX_LOG_HOURS:
            return err(f"hours must be between 1 and {MAX_LOG_HOURS}")
        if client and client_matcher(client) is None:
            return err(f"client must be an IP address or a MAC address, got {client!r}")
        try:
            backend = resolve_backend(registry, controller)
            return format_json(await backend.list_threat_detections(hours, limit, client))
        except UniFiError as exc:
            logger.exception("list_threat_detections failed")
            return err(str(exc))

    @mcp.tool(annotations=ACTION)
    # Classified mutating even though it changes no configuration: it issues a
    # POST that makes the gateway saturate the WAN for ~30-60s and appends a
    # result row. "Read-only" has to mean the server cannot make the gateway do
    # work on command, not merely that it cannot edit config — an agent that can
    # trigger speed tests in a loop is a denial-of-service on the uplink.
    # ``get_speedtest_results`` (read) still returns previously-run tests.
    @audited("trigger_speedtest", mutates=True)
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

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_speedtest_results", mutates=False)
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

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_top_talkers", mutates=False)
    async def list_top_talkers(limit: int = 10, controller: str = "default") -> str:
        """List the connected clients that have moved the most data.

        Side effects: None (read-only).

        Ranks the clients connected right now by bytes sent plus received
        since each one connected, so it is not a per-day or per-month total
        and a client that has left is not listed. Returns one record per
        client, highest ``total_bytes`` first, with ``mac``, ``hostname``,
        ``ip``, ``tx_bytes``, ``rx_bytes``, and ``total_bytes``.

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
