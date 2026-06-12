"""Shared shaping helpers for the read-only stats & insights surface (Wave C).

Both :class:`mcp_unifi.backends.RealBackend` and
:class:`mcp_unifi.backends.StubBackend` route their stats methods through these
pure functions so the two backends return byte-identical shapes. Tools never
branch on stub vs real, and the LLM-facing payload stays small and stable
regardless of how noisy the underlying controller record is.

The field selections were driven by a live read-only probe of a UCG-Fiber on
UniFi Network 10.4.57 (2026-06-12); see the per-function docstrings in
:mod:`mcp_unifi.clients.unifi` for the raw envelopes.
"""

from __future__ import annotations

from typing import Any

from mcp_unifi.models import UniFiRecord


def _to_float(value: Any) -> float | None:
    """Coerce a controller stat (often a numeric string) to float, or None."""
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def shape_system_info(raw: Any) -> UniFiRecord:
    """Trim a ``/stat/sysinfo`` record to the fields callers actually use."""
    if not isinstance(raw, dict):
        return {}
    keys = (
        "version",
        "build",
        "previous_version",
        "hostname",
        "name",
        "uptime",
        "timezone",
        "ubnt_device_type",
        "udm_version",
        "console_display_version",
        "update_available",
        "update_downloaded",
        "is_cloud_console",
    )
    return {k: raw[k] for k in keys if k in raw}


def shape_gateway_stats(raw: Any) -> UniFiRecord:
    """Flatten a gateway (ugw/udm) device record into a compact stats view.

    Pulls ``system-stats`` (cpu/mem/uptime), ``temperatures``, throughput
    counters, and WAN summary fields out of the noisy raw record.
    """
    if not isinstance(raw, dict):
        return {}
    sys_stats = raw.get("system-stats") or raw.get("sys_stats") or {}
    if not isinstance(sys_stats, dict):
        sys_stats = {}
    out: UniFiRecord = {
        "mac": raw.get("mac"),
        "name": raw.get("name"),
        "model": raw.get("model"),
        "type": raw.get("type"),
        "version": raw.get("version"),
        "uptime": raw.get("uptime"),
        "cpu_pct": _to_float(sys_stats.get("cpu")),
        "mem_pct": _to_float(sys_stats.get("mem")),
        "tx_bytes": raw.get("tx_bytes"),
        "rx_bytes": raw.get("rx_bytes"),
        "num_sta": raw.get("num_sta"),
        "last_wan_ip": raw.get("last_wan_ip"),
        "speedtest_status": raw.get("speedtest-status") or raw.get("speedtest_status"),
    }
    temps = raw.get("temperatures")
    if isinstance(temps, list):
        out["temperatures"] = [
            {"name": t.get("name"), "type": t.get("type"), "value": _to_float(t.get("value"))}
            for t in temps
            if isinstance(t, dict)
        ]
    # Drop keys the controller didn't populate so the payload stays clean.
    return {k: v for k, v in out.items() if v is not None}


def shape_device_stats(raw: Any) -> UniFiRecord:
    """Flatten a per-device ``/stat/device`` record into a compact stats view."""
    if not isinstance(raw, dict):
        return {}
    sys_stats = raw.get("system-stats") or raw.get("sys_stats") or {}
    if not isinstance(sys_stats, dict):
        sys_stats = {}
    out: UniFiRecord = {
        "mac": raw.get("mac"),
        "name": raw.get("name"),
        "model": raw.get("model"),
        "type": raw.get("type"),
        "version": raw.get("version"),
        "state": raw.get("state"),
        "uptime": raw.get("uptime"),
        "cpu_pct": _to_float(sys_stats.get("cpu")),
        "mem_pct": _to_float(sys_stats.get("mem")),
        "satisfaction": raw.get("satisfaction"),
        "num_sta": raw.get("num_sta"),
        "tx_bytes": raw.get("tx_bytes"),
        "rx_bytes": raw.get("rx_bytes"),
    }
    # The wireless tx/rx retry rollup lives under ``stat.ap`` on APs.
    stat = raw.get("stat")
    if isinstance(stat, dict):
        ap_stat = stat.get("ap")
        if isinstance(ap_stat, dict):
            out["tx_retries"] = ap_stat.get("tx_retries")
            out["tx_packets"] = ap_stat.get("tx_packets")
            out["rx_packets"] = ap_stat.get("rx_packets")
    return {k: v for k, v in out.items() if v is not None}


def shape_client_stats(raw: Any) -> UniFiRecord:
    """Flatten a ``/stat/sta`` client record into a compact stats view.

    Returns both wireless (signal/rssi/rate) and wired (wired-* throughput)
    fields when present; absent fields are dropped from the payload.
    """
    if not isinstance(raw, dict):
        return {}
    out: UniFiRecord = {
        "mac": raw.get("mac"),
        "hostname": raw.get("hostname"),
        "name": raw.get("name"),
        "ip": raw.get("ip"),
        "is_wired": raw.get("is_wired"),
        "network": raw.get("network"),
        "essid": raw.get("essid"),
        "uptime": raw.get("uptime"),
        "first_seen": raw.get("first_seen"),
        "last_seen": raw.get("last_seen"),
        "signal": raw.get("signal"),
        "rssi": raw.get("rssi"),
        "satisfaction": raw.get("satisfaction"),
        "satisfaction_avg": raw.get("satisfaction_avg"),
        "tx_rate": raw.get("tx_rate"),
        "rx_rate": raw.get("rx_rate"),
        "tx_bytes": raw.get("tx_bytes"),
        "rx_bytes": raw.get("rx_bytes"),
        "tx_retries": raw.get("tx_retries"),
        "anomalies": raw.get("anomalies"),
        "wired_rate_mbps": raw.get("wired_rate_mbps"),
        "wired_tx_bytes": raw.get("wired-tx_bytes"),
        "wired_rx_bytes": raw.get("wired-rx_bytes"),
    }
    return {k: v for k, v in out.items() if v is not None}


def shape_session(raw: Any) -> UniFiRecord:
    """Trim a ``/stat/session`` record to the fields callers actually use."""
    if not isinstance(raw, dict):
        return {}
    keys = (
        "mac",
        "hostname",
        "name",
        "ip",
        "assoc_time",
        "duration",
        "rx_bytes",
        "tx_bytes",
        "is_wired",
        "is_guest",
        "ap_mac",
        "satisfaction",
        "satisfaction_avg",
        "roaming_sessions",
    )
    return {k: raw[k] for k in keys if k in raw}
