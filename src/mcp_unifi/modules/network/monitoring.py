"""Bounded, read-only controller/site/device monitoring contracts.

The legacy Network tools remain available for compatibility.  These tools are
an intentionally small monitoring surface: every list is paginated, device
records are allowlisted, and failures carry a stable category instead of raw
controller response text.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from mcp_unifi.annotations import READ_ONLY
from mcp_unifi.clients.errors import UniFiUnsupportedError
from mcp_unifi.dispatcher import resolve_backend
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules.network._common import format_json
from mcp_unifi.redaction import redact

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import ControllerConfig, Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.network.monitoring")
MAX_LIMIT = 100


def _error(settings: Settings, code: str, message: str) -> str:
    return format_json(
        {"error": message, "error_code": code, "stub_mode": settings.stub_mode}
    )


def _error_code(exc: Exception) -> str:
    text = str(exc).lower()
    if isinstance(exc, UniFiUnsupportedError):
        return "unsupported"
    if isinstance(exc, KeyError) or "unknown controller" in text:
        return "invalid_target"
    if "401" in text or "403" in text or "authorization" in text:
        return "authorization"
    if "timeout" in text or "timed out" in text:
        return "timeout"
    return "controller_failure"


def _page(items: list[dict[str, Any]], page: int, limit: int) -> dict[str, Any]:
    start = (page - 1) * limit
    selected = items[start : start + limit]
    return {
        "items": selected,
        "page": page,
        "limit": limit,
        "total": len(items),
        "has_more": start + limit < len(items),
    }


def _controller(settings: Settings, name: str) -> ControllerConfig | None:
    return next((item for item in settings.controllers if item.name == name), None)


def _status(record: dict[str, Any]) -> str:
    value = record.get("state")
    if value in (1, "1", "online", "connected", "up"):
        return "online"
    return "offline"


def _device_summary(record: dict[str, Any]) -> dict[str, Any]:
    stats = record.get("system-stats") or record.get("sys_stats") or {}
    if not isinstance(stats, dict):
        stats = {}

    def number(value: Any) -> float | int | None:
        if value is None:
            return None
        try:
            converted = float(value)
            return int(converted) if converted.is_integer() else converted
        except (TypeError, ValueError):
            return None

    result: dict[str, Any] = {
        "id": record.get("_id"),
        "mac": record.get("mac"),
        "name": record.get("name"),
        "type": record.get("type"),
        "model": record.get("model"),
        "firmware": record.get("version"),
        "ip": record.get("ip"),
        "status": _status(record),
        "adopted": record.get("adopted"),
        "uptime": record.get("uptime"),
        "cpu_pct": number(stats.get("cpu")),
        "memory_pct": number(stats.get("mem")),
    }
    return {key: value for key, value in result.items() if value is not None}


def _client_summary(record: dict[str, Any]) -> dict[str, Any]:
    """Project connected-client records without exposing arbitrary fields."""
    allowed = (
        "_id", "mac", "hostname", "name", "ip", "is_wired", "blocked", "network",
        "essid", "ap_mac", "sw_mac", "sw_port", "channel", "radio", "signal", "rssi",
        "satisfaction", "tx_rate", "rx_rate", "tx_bytes", "rx_bytes", "uptime", "last_seen",
    )
    return {key: record[key] for key in allowed if key in record and record[key] is not None}


def _network_summary(record: dict[str, Any]) -> dict[str, Any]:
    allowed = (
        "_id", "name", "purpose", "vlan_enabled", "vlan", "ip_subnet", "dhcpd_enabled",
        "site_id", "enabled", "wan_networkgroup", "ipv6_interface_type",
    )
    return {key: record[key] for key in allowed if key in record and record[key] is not None}


def _wlan_summary(record: dict[str, Any]) -> dict[str, Any]:
    allowed = (
        "_id", "name", "enabled", "security", "wpa_mode", "networkconf_id", "is_guest",
        "hide_ssid", "wlan_band",
    )
    return {key: record[key] for key in allowed if key in record and record[key] is not None}


def _radio_summary(record: dict[str, Any]) -> dict[str, Any]:
    allowed = ("radio", "channel", "ht", "tx_power", "num_sta", "utilization", "satisfaction")
    return {key: record[key] for key in allowed if key in record and record[key] is not None}


def _port_summary(
    device: dict[str, Any], port: dict[str, Any], client: dict[str, Any] | None = None
) -> dict[str, Any]:
    allowed = ("port_idx", "name", "enable", "poe_mode", "portconf_id", "speed", "media", "up")
    result: dict[str, Any] = {
        "device_id": device.get("_id"),
        "device_mac": device.get("mac"),
        "device_name": device.get("name"),
        **{key: port[key] for key in allowed if key in port and port[key] is not None},
    }
    if client is not None:
        result["client_mac"] = client.get("mac")
        result["client_name"] = client.get("name") or client.get("hostname")
    return {key: value for key, value in result.items() if value is not None}


def _wan_summary(record: dict[str, Any]) -> dict[str, Any]:
    allowed = (
        "subsystem", "status", "gw_name", "gw_mac", "wan_ip", "isp_name",
        "speedtest_status", "uptime", "latency", "xput_up", "xput_down",
    )
    return {key: record[key] for key in allowed if key in record and record[key] is not None}


def _event_summary(record: dict[str, Any]) -> dict[str, Any]:
    allowed = ("_id", "time", "datetime", "key", "msg", "subsystem", "site_id")
    return {key: record[key] for key in allowed if key in record and record[key] is not None}


def _alarm_summary(record: dict[str, Any]) -> dict[str, Any]:
    allowed = (
        "_id", "time", "datetime", "key", "msg", "subsystem", "archived",
        "user", "sta", "ap", "ssid", "site_id",
    )
    return {key: record[key] for key in allowed if key in record and record[key] is not None}


def _threat_summary(record: dict[str, Any]) -> dict[str, Any]:
    allowed = ("anomaly", "mac", "timestamps", "site_id")
    return {key: record[key] for key in allowed if key in record and record[key] is not None}


def _firewall_summary(record: dict[str, Any]) -> dict[str, Any]:
    allowed = (
        "_id", "name", "ruleset", "rule_index", "action", "enabled", "protocol",
        "predefined", "index", "ip_version", "connection_state_type", "source",
        "destination", "logging", "description", "zone_key", "default_zone",
        "attr_no_edit", "network_ids",
    )
    return {key: record[key] for key in allowed if key in record and record[key] is not None}


def _valid_page(settings: Settings, page: int, limit: int) -> str | None:
    if page < 1 or not 1 <= limit <= MAX_LIMIT:
        return _error(settings, "invalid_input", "page must be >= 1 and limit must be between 1 and 100")
    return None


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    @mcp.tool(annotations=READ_ONLY)
    @audited("get_controller_info", mutates=False)
    async def get_controller_info(controller: str = "default") -> str:
        """Return bounded controller identity, version and uptime information.

        The controller host is configuration metadata, never a credential. API
        output is allowlisted; unavailable fields are omitted rather than guessed.
        Example: get_controller_info(controller="default")
        """
        try:
            resolved = registry.resolve_name(controller)
            config = _controller(settings, resolved)
            if config is None:
                return _error(settings, "invalid_target", "Controller configuration is unavailable.")
            backend = resolve_backend(registry, controller)
            info = await backend.get_system_info()
            result: dict[str, Any] = {
                "controller": config.name,
                "site": config.site,
                "host": config.host,
                "port": config.port,
                **{
                    key: info[key]
                    for key in ("version", "build", "uptime")
                    if key in info
                },
                "stub_mode": settings.stub_mode,
            }
            return format_json(redact(result))
        except Exception as exc:
            logger.warning("get_controller_info failed: %s", type(exc).__name__)
            return _error(settings, _error_code(exc), "Controller information is unavailable.")

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_sites", mutates=False)
    async def list_sites(
        page: int = 1, limit: int = 50, name_filter: str = ""
    ) -> str:
        """List configured sites with explicit pagination and name filtering.

        This inventory is local configuration metadata; it does not expose API
        keys or imply that a site is reachable. Example: list_sites(limit=20)
        """
        if page < 1 or not 1 <= limit <= MAX_LIMIT:
            return _error(settings, "invalid_input", "page must be >= 1 and limit must be between 1 and 100")
        needle = name_filter.strip().lower()
        items = [
            {"id": config.site, "name": config.site, "controller": config.name}
            for config in settings.controllers
            if not needle or needle in config.site.lower() or needle in config.name.lower()
        ]
        return format_json(_page(items, page, limit))

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_site_health_bounded", mutates=False)
    async def get_site_health_bounded(
        controller: str = "default",
        page: int = 1,
        limit: int = 50,
        subsystem: str = "",
    ) -> str:
        """Return bounded per-subsystem site health with an optional filter.

        A missing subsystem record is not fabricated; an empty ``items`` list
        means the controller reported no matching subsystem. Example:
        get_site_health_bounded(subsystem="wan")
        """
        if page < 1 or not 1 <= limit <= MAX_LIMIT:
            return _error(settings, "invalid_input", "page must be >= 1 and limit must be between 1 and 100")
        try:
            records = await resolve_backend(registry, controller).get_site_health()
            items = [record for record in records if isinstance(record, dict)]
            if subsystem:
                items = [item for item in items if item.get("subsystem") == subsystem.lower()]
            return format_json(_page(items, page, limit))
        except Exception as exc:
            logger.warning("get_site_health_bounded failed: %s", type(exc).__name__)
            return _error(settings, _error_code(exc), "Site health is unavailable.")

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_devices_bounded", mutates=False)
    async def list_devices_bounded(
        controller: str = "default",
        page: int = 1,
        limit: int = 50,
        device_type: str = "",
        status: str = "",
    ) -> str:
        """List bounded device health summaries with type/status filters.

        ``device_type`` accepts controller values such as ``ugw``, ``usw`` and
        ``uap``. ``status`` accepts ``online`` or ``offline``. Example:
        list_devices_bounded(device_type="uap", limit=25)
        """
        if page < 1 or not 1 <= limit <= MAX_LIMIT:
            return _error(settings, "invalid_input", "page must be >= 1 and limit must be between 1 and 100")
        if status and status.lower() not in {"online", "offline"}:
            return _error(settings, "invalid_input", "status must be online or offline")
        try:
            records = await resolve_backend(registry, controller).list_devices()
            summaries = [_device_summary(record) for record in records if isinstance(record, dict)]
            if device_type:
                summaries = [item for item in summaries if item.get("type") == device_type.lower()]
            if status:
                summaries = [item for item in summaries if item.get("status") == status.lower()]
            return format_json(_page(summaries, page, limit))
        except Exception as exc:
            logger.warning("list_devices_bounded failed: %s", type(exc).__name__)
            return _error(settings, _error_code(exc), "Device inventory is unavailable.")

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_device_details", mutates=False)
    async def get_device_details(
        controller: str = "default", device_id: str = "", mac: str = ""
    ) -> str:
        """Return one bounded device summary using exactly one selector.

        ``device_id`` and ``mac`` are mutually exclusive. Missing or duplicate
        selection is rejected so a read cannot silently target the wrong device.
        Example: get_device_details(mac="f4:e2:c6:00:00:02")
        """
        if bool(device_id) == bool(mac):
            return _error(settings, "ambiguous_target", "Provide exactly one of device_id or mac")
        try:
            records = await resolve_backend(registry, controller).list_devices()
            matches = [
                record
                for record in records
                if isinstance(record, dict)
                and ((device_id and record.get("_id") == device_id) or (mac and str(record.get("mac", "")).lower() == mac.lower()))
            ]
            if not matches:
                return _error(settings, "not_found", "Device was not found")
            if len(matches) > 1:
                return _error(settings, "ambiguous_target", "Device selector matched multiple devices")
            return format_json(_device_summary(matches[0]))
        except Exception as exc:
            logger.warning("get_device_details failed: %s", type(exc).__name__)
            return _error(settings, _error_code(exc), "Device details are unavailable.")

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_clients_bounded", mutates=False)
    async def list_clients_bounded(
        controller: str = "default", page: int = 1, limit: int = 50,
        network: str = "", wired: bool | None = None,
    ) -> str:
        """List bounded connected-client identity and link facts.

        Credential-like and arbitrary controller fields are omitted. Example:
        list_clients_bounded(wired=False, limit=25)
        """
        invalid = _valid_page(settings, page, limit)
        if invalid:
            return invalid
        try:
            records = await resolve_backend(registry, controller).list_clients()
            items = [_client_summary(record) for record in records if isinstance(record, dict)]
            if network:
                items = [item for item in items if str(item.get("network", "")).lower() == network.lower()]
            if wired is not None:
                items = [item for item in items if item.get("is_wired") is wired]
            return format_json(_page(items, page, limit))
        except Exception as exc:
            logger.warning("list_clients_bounded failed: %s", type(exc).__name__)
            return _error(settings, _error_code(exc), "Connected clients are unavailable.")

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_networks_bounded", mutates=False)
    async def list_networks_bounded(
        controller: str = "default", page: int = 1, limit: int = 50,
        purpose: str = "", vlan: int | None = None,
    ) -> str:
        """List bounded network/VLAN associations without secrets.

        Example: list_networks_bounded(purpose="corporate", limit=25)
        """
        invalid = _valid_page(settings, page, limit)
        if invalid:
            return invalid
        try:
            records = await resolve_backend(registry, controller).list_networks()
            items = [_network_summary(record) for record in records if isinstance(record, dict)]
            if purpose:
                items = [item for item in items if str(item.get("purpose", "")).lower() == purpose.lower()]
            if vlan is not None:
                items = [item for item in items if item.get("vlan") == vlan]
            return format_json(_page(items, page, limit))
        except Exception as exc:
            logger.warning("list_networks_bounded failed: %s", type(exc).__name__)
            return _error(settings, _error_code(exc), "Network configuration is unavailable.")

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_wlans_bounded", mutates=False)
    async def list_wlans_bounded(
        controller: str = "default", page: int = 1, limit: int = 50,
        enabled: bool | None = None,
    ) -> str:
        """List bounded WLAN configuration and radio statistics.

        PSKs and nested credential fields are intentionally absent. Example:
        list_wlans_bounded(enabled=True)
        """
        invalid = _valid_page(settings, page, limit)
        if invalid:
            return invalid
        try:
            backend = resolve_backend(registry, controller)
            wlans = await backend.list_wlans()
            devices = await backend.list_devices()
            radios: list[dict[str, Any]] = []
            for device in devices:
                for radio in device.get("radio_table", []):
                    if isinstance(radio, dict):
                        radios.append({"device_id": device.get("_id"), "device_mac": device.get("mac"), **_radio_summary(radio)})
            items = [{**_wlan_summary(record), "radios": radios} for record in wlans]
            if enabled is not None:
                items = [item for item in items if item.get("enabled") is enabled]
            return format_json(_page(items, page, limit))
        except Exception as exc:
            logger.warning("list_wlans_bounded failed: %s", type(exc).__name__)
            return _error(settings, _error_code(exc), "WLAN configuration is unavailable.")

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_switch_ports_bounded", mutates=False)
    async def list_switch_ports_bounded(
        controller: str = "default", page: int = 1, limit: int = 50,
        device_mac: str = "", port_idx: int | None = None,
    ) -> str:
        """List bounded switch link, PoE, profile and client-association facts.

        This is read-only; port state and PoE mutations are not exposed. Example:
        list_switch_ports_bounded(device_mac="f4:e2:c6:00:00:03", limit=24)
        """
        invalid = _valid_page(settings, page, limit)
        if invalid:
            return invalid
        if port_idx is not None and port_idx < 1:
            return _error(settings, "invalid_input", "port_idx must be >= 1")
        try:
            backend = resolve_backend(registry, controller)
            devices = await backend.list_devices()
            clients = await backend.list_clients()
            items: list[dict[str, Any]] = []
            for device in devices:
                if not isinstance(device, dict) or device.get("type") != "usw":
                    continue
                if device_mac and str(device.get("mac", "")).lower() != device_mac.lower():
                    continue
                for port in device.get("port_table", []):
                    if isinstance(port, dict) and (port_idx is None or port.get("port_idx") == port_idx):
                        client = next(
                            (
                                candidate
                                for candidate in clients
                                if candidate.get("sw_mac") == device.get("mac")
                                and candidate.get("sw_port") == port.get("port_idx")
                            ),
                            None,
                        )
                        items.append(_port_summary(device, port, client))
            return format_json(_page(items, page, limit))
        except Exception as exc:
            logger.warning("list_switch_ports_bounded failed: %s", type(exc).__name__)
            return _error(settings, _error_code(exc), "Switch port inventory is unavailable.")

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_wan_status_bounded", mutates=False)
    async def get_wan_status_bounded(controller: str = "default") -> str:
        """Return an allowlisted current WAN status and traffic summary."""
        try:
            record = await resolve_backend(registry, controller).get_wan_status()
            return format_json(_wan_summary(record))
        except Exception as exc:
            logger.warning("get_wan_status_bounded failed: %s", type(exc).__name__)
            return _error(settings, _error_code(exc), "WAN status is unavailable.")

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_wan_traffic_bounded", mutates=False)
    async def get_wan_traffic_bounded(controller: str = "default") -> str:
        """Return bounded WAN throughput and latency facts without mutation."""
        try:
            record = await resolve_backend(registry, controller).get_wan_status()
            allowed = ("subsystem", "status", "wan_ip", "latency", "xput_up", "xput_down")
            traffic = {key: record[key] for key in allowed if key in record and record[key] is not None}
            return format_json(traffic)
        except Exception as exc:
            logger.warning("get_wan_traffic_bounded failed: %s", type(exc).__name__)
            return _error(settings, _error_code(exc), "WAN traffic is unavailable.")

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_events_bounded", mutates=False)
    async def list_events_bounded(
        controller: str = "default", page: int = 1, limit: int = 50
    ) -> str:
        """Return a bounded, redacted controller event window.

        Some Network firmware does not expose event logs through the local
        API-key surface; that condition is returned as ``unsupported``.
        """
        invalid = _valid_page(settings, page, limit)
        if invalid:
            return invalid
        try:
            records = await resolve_backend(registry, controller).list_events(limit=MAX_LIMIT)
            items = [_event_summary(record) for record in records if isinstance(record, dict)]
            return format_json(_page(items, page, limit))
        except Exception as exc:
            logger.warning("list_events_bounded failed: %s", type(exc).__name__)
            return _error(settings, _error_code(exc), "Controller events are unavailable.")

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_alarms_bounded", mutates=False)
    async def list_alarms_bounded(
        controller: str = "default", page: int = 1, limit: int = 50, archived: bool = False
    ) -> str:
        """Return a bounded, redacted active or archived alarm window."""
        invalid = _valid_page(settings, page, limit)
        if invalid:
            return invalid
        try:
            records = await resolve_backend(registry, controller).list_alarms(page * limit, archived)
            items = [_alarm_summary(record) for record in records if isinstance(record, dict)]
            return format_json(_page(items, page, limit))
        except Exception as exc:
            logger.warning("list_alarms_bounded failed: %s", type(exc).__name__)
            return _error(settings, _error_code(exc), "Controller alarms are unavailable.")

    @mcp.tool(annotations=READ_ONLY)
    @audited("list_threat_signals_bounded", mutates=False)
    async def list_threat_signals_bounded(
        controller: str = "default", page: int = 1, limit: int = 50
    ) -> str:
        """Return bounded client-impacting threat/anomaly signals."""
        invalid = _valid_page(settings, page, limit)
        if invalid:
            return invalid
        try:
            records = await resolve_backend(registry, controller).get_anomalies()
            items = [_threat_summary(record) for record in records if isinstance(record, dict)]
            return format_json(_page(items, page, limit))
        except Exception as exc:
            logger.warning("list_threat_signals_bounded failed: %s", type(exc).__name__)
            return _error(settings, _error_code(exc), "Threat signals are unavailable.")

    @mcp.tool(annotations=READ_ONLY)
    @audited("inspect_firewall_bounded", mutates=False)
    async def inspect_firewall_bounded(
        controller: str = "default", page: int = 1, limit: int = 50
    ) -> str:
        """Inspect legacy rules and zone-based policies without mutation.

        The two sources remain labelled separately; an empty legacy list never
        implies that zone-based policy is absent, and vice versa.
        """
        invalid = _valid_page(settings, page, limit)
        if invalid:
            return invalid
        try:
            backend = resolve_backend(registry, controller)
            legacy = await backend.list_firewall_rules()
            policies = await backend.list_firewall_policies()
            zones = await backend.list_firewall_zones()
            return format_json({
                "legacy": _page(
                    [_firewall_summary(record) for record in legacy if isinstance(record, dict)],
                    page, limit,
                ),
                "zone_based": {
                    "policies": _page(
                        [_firewall_summary(record) for record in policies if isinstance(record, dict)],
                        page, limit,
                    ),
                    "zones": [_firewall_summary(record) for record in zones if isinstance(record, dict)],
                },
            })
        except Exception as exc:
            logger.warning("inspect_firewall_bounded failed: %s", type(exc).__name__)
            return _error(settings, _error_code(exc), "Firewall inspection is unavailable.")

    @mcp.tool(annotations=READ_ONLY)
    @audited("get_firmware_info", mutates=False)
    async def get_firmware_info(controller: str = "default") -> str:
        """Return controller firmware version and update availability facts.

        This reports Network/controller information available to the API key; it
        never initiates, schedules, downloads, or applies a firmware update.
        """
        try:
            record = await resolve_backend(registry, controller).get_system_info()
            allowed = (
                "version", "build", "previous_version", "uptime", "update_available",
                "update_downloaded", "console_display_version", "udm_version",
            )
            result = {key: record[key] for key in allowed if key in record and record[key] is not None}
            result["stub_mode"] = settings.stub_mode
            return format_json(result)
        except Exception as exc:
            logger.warning("get_firmware_info failed: %s", type(exc).__name__)
            return _error(settings, _error_code(exc), "Firmware information is unavailable.")
