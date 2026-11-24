"""Request bodies and response shaping for the v2 system log and IPS reads.

WHY THIS EXISTS
---------------
UniFi Network 10.x removed the legacy log readers this server used:
``/stat/event`` answers 404, ``/list/alarm`` answers 400
``api.err.InvalidObject`` and ``/stat/ips/event`` answers 404. Their
replacement is the v2 system log, a paged ``POST`` under
``/proxy/network/v2/api/site/<site>/system-log/<class>``. Sources, read
2026-11-24:

* Art-of-WiFi ``UniFi-API-client`` ``src/Client.php`` at commit
  ``e1f7f63b`` (v2.4.0): ``get_system_log()`` (lines 3989-4053) builds the
  body ``{pageNumber, pageSize, timestampFrom, timestampTo}``, adds
  ``threatTypes: ["HONEYPOT", "THREAT"]`` for the ``threat-alert`` class, and
  documents that ``all`` replaces ``list_events()``, ``critical`` replaces
  ``list_alarms()`` and ``threat-alert`` replaces ``stat_ips_events()``. Its
  ``list_events()`` (3505-3528), ``list_alarms()`` (3530-3544) and
  ``stat_ips_events()`` (1193-1214) record the 404 / 400 the legacy routes
  now answer.
* unpoller ``unifi`` ``system_log.go`` at commit ``132b9d92``: the entry
  fields (``id``, ``timestamp`` in ms, ``category``, ``subcategory``,
  ``event``, ``key``, ``severity``, ``status``, ``type``, ``title_raw``,
  ``message_raw``, ``parameters``) and the page envelope (``data``,
  ``page_number``, ``total_element_count``, ``total_page_count``).
  ``endpoints_data/ENDPOINTS.md`` there lists ``stat/event`` and
  ``stat/ips/event`` as removed on Network 10.x and the system-log routes as
  their replacement.

IPS detections come from two v2 reads, because neither carries everything:

* ``POST /traffic-flows`` filtered to ``policy_type: ["INTRUSION_PREVENTION"]``
  carries ports, protocol, the signature and the ``blocked`` / ``allowed``
  action. The body and row shape follow kcorr ``unifi-security-console``
  ``server/unifi/threats.ts`` (commit ``73515f5b``, ``fetchThreats`` and
  ``parseTrafficFlow``). That is one project's reading of the controller, not
  a vendor document, so it is the least certain shape in this module.
* ``POST /system-log/threat-alert`` carries the alert as the console shows it
  (``THREAT_BLOCKED`` / ``THREAT_DETECTED`` keys, ``SRC_IP`` / ``DST_IP``
  parameters) but no ports and no signature, and catches honeypot hits.

THE RULE
--------
Nothing here turns a failure into an empty list. A page that is not the
documented shape raises :class:`UniFiError`; an empty ``data`` list on a
well-formed page is a real "nothing in this window".
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from typing import Any

from mcp_unifi.clients.errors import UniFiError
from mcp_unifi.clients.mac import is_mac, normalize_mac

#: Page size for the system log. Art-of-WiFi's default; a third-party fake
#: console caps ``threat-alert`` pages at 100, so asking for more buys nothing.
SYSTEM_LOG_PAGE_SIZE = 100

#: Page size for ``traffic-flows`` (kcorr uses 1000; 500 keeps one page small).
TRAFFIC_FLOW_PAGE_SIZE = 500

#: Most rows read from one source for one call. A window holding more is
#: reported as ``more_available`` so the caller narrows it, never truncated
#: silently.
MAX_SCAN_ROWS = 2000

#: Two reports of one detection (a flow and an alert) land within this many
#: milliseconds of each other.
_SAME_DETECTION_MS = 120_000

#: Empty filter set the ``traffic-flows`` body carries alongside
#: ``policy_type`` (copied from kcorr ``EMPTY_FLOW_FILTERS``). An empty list
#: means "no filter" on that field.
_EMPTY_FLOW_FILTERS: dict[str, Any] = {
    "risk": [],
    "action": [],
    "direction": [],
    "protocol": [],
    "policy": [],
    "service": [],
    "source_host": [],
    "source_mac": [],
    "source_ip": [],
    "source_port": [],
    "source_network_id": [],
    "source_domain": [],
    "source_zone_id": [],
    "source_region": [],
    "destination_host": [],
    "destination_mac": [],
    "destination_ip": [],
    "destination_port": [],
    "destination_network_id": [],
    "destination_domain": [],
    "destination_zone_id": [],
    "destination_region": [],
    "in_network_id": [],
    "out_network_id": [],
    "next_ai_query": [],
    "except_for": [],
    "search_text": "",
}

_PLACEHOLDER = re.compile(r"\{(\w+)\}")


# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------


def system_log_body(log_class: str, start_ms: int, end_ms: int, page: int) -> dict[str, Any]:
    """The ``POST /system-log/<class>`` body, as Art-of-WiFi builds it."""
    body: dict[str, Any] = {
        "pageNumber": page,
        "pageSize": SYSTEM_LOG_PAGE_SIZE,
        "timestampFrom": start_ms,
        "timestampTo": end_ms,
    }
    if log_class == "threat-alert":
        body["threatTypes"] = ["HONEYPOT", "THREAT"]
    return body


def ips_flow_body(start_ms: int, end_ms: int, page: int) -> dict[str, Any]:
    """The ``POST /traffic-flows`` body filtered to intrusion prevention."""
    return {
        **_EMPTY_FLOW_FILTERS,
        "timestampFrom": start_ms,
        "timestampTo": end_ms,
        "pageNumber": page,
        "pageSize": TRAFFIC_FLOW_PAGE_SIZE,
        "skip_count": False,
        "policy_type": ["INTRUSION_PREVENTION"],
    }


# ---------------------------------------------------------------------------
# Page parsing
# ---------------------------------------------------------------------------


def parse_page(body: Any, label: str) -> tuple[list[dict[str, Any]], int | None, bool]:
    """Return ``(rows, total, has_more)`` from one v2 page, or raise.

    Accepts the documented envelope (``{"data": [...], "total_page_count":
    N, ...}``) and a bare list (unpoller's endpoint catalogue describes
    ``system-log/critical`` as an array). Anything else raises
    :class:`UniFiError` naming ``label``: an unrecognised body is a failure
    to read the log, never an empty log.
    """
    if isinstance(body, list):
        return [r for r in body if isinstance(r, dict)], len(body), False
    if not isinstance(body, dict) or not isinstance(body.get("data"), list):
        kind = type(body).__name__ if not isinstance(body, dict) else "object without a data list"
        raise UniFiError(
            f"{label} answered 200 with a body that is not a system-log page ({kind}), "
            f"so the log could not be read"
        )
    rows = [r for r in body["data"] if isinstance(r, dict)]
    total = body.get("total_element_count")
    total_int = total if isinstance(total, int) and not isinstance(total, bool) else None
    if isinstance(body.get("has_next"), bool):
        has_more = bool(body["has_next"])
    else:
        pages = body.get("total_page_count")
        page_no = body.get("page_number")
        if isinstance(pages, int) and isinstance(page_no, int):
            has_more = page_no + 1 < pages
        else:
            has_more = False
    return rows, total_int, has_more and bool(rows)


# ---------------------------------------------------------------------------
# Entry shaping
# ---------------------------------------------------------------------------


def iso_utc(ms: object) -> str | None:
    """Epoch milliseconds (or seconds) as an ISO-8601 UTC string."""
    if isinstance(ms, bool) or not isinstance(ms, int | float) or ms <= 0:
        return None
    seconds = ms / 1000 if ms > 1e12 else float(ms)
    return datetime.fromtimestamp(seconds, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def render_message(entry: dict[str, Any]) -> str:
    """Fill ``message_raw``'s ``{PLACEHOLDER}`` tokens from ``parameters``.

    Same rule as unpoller ``SystemLogEntry.Msg()``: a parameter's ``name``,
    else its ``id``, else the placeholder stays as written.
    """
    raw = entry.get("message_raw")
    if not isinstance(raw, str) or not raw:
        title = entry.get("message") or entry.get("title_raw") or ""
        return str(title)
    params = entry.get("parameters")
    params = params if isinstance(params, dict) else {}

    def fill(match: re.Match[str]) -> str:
        param = params.get(match.group(1))
        if isinstance(param, dict):
            for field in ("name", "id"):
                value = param.get(field)
                if isinstance(value, str) and value:
                    return value
        return match.group(0)

    return _PLACEHOLDER.sub(fill, raw)


def shape_log_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """A system-log entry with ``time`` and a rendered ``message`` added."""
    shaped = dict(entry)
    shaped["time"] = iso_utc(entry.get("timestamp"))
    shaped["message"] = render_message(entry)
    return shaped


def _obj(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _str(value: object) -> str | None:
    if isinstance(value, str) and value:
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return None


def _int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _ip(*values: object) -> str | None:
    for value in values:
        text = _str(value)
        if text is None:
            continue
        try:
            ipaddress.ip_address(text)
        except ValueError:
            continue
        return text
    return None


def _mac(*values: object) -> str | None:
    for value in values:
        if is_mac(value):
            return normalize_mac(value)
    return None


def _flow_action(value: object) -> str:
    text = str(value or "").lower()
    if text in {"blocked", "block", "drop", "dropped"}:
        return "blocked"
    if text in {"allowed", "allow", "alert", "alerted"}:
        return "alerted"
    return "unknown"


def _is_ips_flow(row: dict[str, Any]) -> bool:
    policies = row.get("policies")
    if isinstance(policies, list):
        for policy in policies:
            if not isinstance(policy, dict):
                continue
            kind = str(policy.get("type", "")).upper()
            if kind == "INTRUSION_PREVENTION" or "HONEYPOT" in kind:
                return True
    return bool(_obj(row.get("ips")))


def detection_from_flow(row: dict[str, Any]) -> dict[str, Any] | None:
    """One ``traffic-flows`` row as a detection, or ``None`` if not an IPS match.

    A row with no intrusion-prevention policy and no ``ips`` block is dropped,
    so a controller that ignored the ``policy_type`` filter cannot pass
    ordinary traffic off as detections.
    """
    if not _is_ips_flow(row):
        return None
    src = _obj(row.get("source"))
    dst = _obj(row.get("destination"))
    ips = _obj(row.get("ips"))
    policies = [p for p in row.get("policies") or [] if isinstance(p, dict)]
    ips_policy = next(
        (p for p in policies if str(p.get("type", "")).upper() == "INTRUSION_PREVENTION"), {}
    )
    ts = _int(row.get("time")) or _int(row.get("flow_start_time"))
    src_name = _str(src.get("client_name")) or _str(src.get("device_name"))
    dst_name = _str(dst.get("client_name")) or _str(dst.get("device_name"))
    return {
        "time": iso_utc(ts),
        "timestamp_ms": ts,
        "action": _flow_action(row.get("action")),
        "src_ip": _ip(src.get("ip")),
        "src_port": _int(src.get("port")),
        "src_mac": _mac(src.get("mac")),
        "dst_ip": _ip(dst.get("ip")),
        "dst_port": _int(dst.get("port")),
        "dst_mac": _mac(dst.get("mac")),
        "protocol": _str(row.get("protocol")),
        "direction": _str(row.get("direction")),
        "signature": _str(ips.get("signature")) or _str(ips_policy.get("name")),
        "signature_id": _int(ips.get("signature_id")),
        "category": _str(ips.get("category_name")) or _str(ips_policy.get("ips_category")),
        "severity": _str(row.get("risk")),
        "client_name": src_name or dst_name,
        "source": "traffic-flows",
        "id": _str(row.get("id")),
    }


def detection_from_alert(row: dict[str, Any]) -> dict[str, Any]:
    """One ``system-log/threat-alert`` entry as a detection.

    These rows carry no ports and no signature; the alert title stands in for
    the signature so the caller still sees what fired.
    """
    params = _obj(row.get("parameters"))
    src_client = _obj(params.get("SRC_CLIENT"))
    dst_client = _obj(params.get("DST_CLIENT"))
    client = _obj(params.get("CLIENT"))
    key = str(row.get("key") or row.get("event") or "").upper()
    if "BLOCKED" in key:
        action = "blocked"
    elif "DETECTED" in key or "HONEYPOT" in key:
        action = "alerted"
    else:
        action = "unknown"
    src_ip_param = _obj(params.get("SRC_IP"))
    dst_ip_param = _obj(params.get("DST_IP"))
    ts = _int(row.get("timestamp"))
    name = (
        _str(src_client.get("name"))
        or _str(dst_client.get("name"))
        or _str(client.get("name"))
        or _str(src_client.get("hostname"))
        or _str(client.get("hostname"))
    )
    return {
        "time": iso_utc(ts),
        "timestamp_ms": ts,
        "action": action,
        "src_ip": _ip(src_ip_param.get("id"), src_ip_param.get("name"), src_client.get("ip")),
        "src_port": None,
        "src_mac": _mac(src_client.get("id"), src_client.get("mac"), client.get("id")),
        "dst_ip": _ip(dst_ip_param.get("id"), dst_ip_param.get("name"), dst_client.get("ip")),
        "dst_port": None,
        "dst_mac": _mac(dst_client.get("id"), dst_client.get("mac")),
        "protocol": None,
        "direction": None,
        "signature": _str(row.get("title_raw")) or _str(row.get("message")),
        "signature_id": None,
        "category": _str(row.get("subcategory")) or _str(row.get("category")),
        "severity": _str(row.get("severity")),
        "client_name": name,
        "source": "system-log/threat-alert",
        "id": _str(row.get("id")),
        "message": render_message(row) or None,
    }


def _same_end(a: dict[str, Any], b: dict[str, Any], a_side: str, b_side: str) -> bool:
    a_ip, b_ip = a.get(f"{a_side}_ip"), b.get(f"{b_side}_ip")
    if a_ip and a_ip == b_ip:
        return True
    a_mac, b_mac = a.get(f"{a_side}_mac"), b.get(f"{b_side}_mac")
    return bool(a_mac) and a_mac == b_mac


def merge_detections(
    flows: list[dict[str, Any]], alerts: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Flows first, plus every alert no flow already describes; newest first.

    A flow and an alert describe the same detection when they are within
    :data:`_SAME_DETECTION_MS` of each other and join the same two ends, in
    either direction. The flow wins because it carries ports and signature.
    """

    def covered(alert: dict[str, Any]) -> bool:
        a_ts = alert.get("timestamp_ms") or 0
        for flow in flows:
            f_ts = flow.get("timestamp_ms") or 0
            if abs(f_ts - a_ts) >= _SAME_DETECTION_MS:
                continue
            forward = _same_end(alert, flow, "src", "src") and _same_end(alert, flow, "dst", "dst")
            reverse = _same_end(alert, flow, "src", "dst") and _same_end(alert, flow, "dst", "src")
            if forward or reverse:
                return True
        return False

    merged = list(flows) + [a for a in alerts if not covered(a)]
    merged.sort(key=lambda d: d.get("timestamp_ms") or 0, reverse=True)
    return merged


def finish_detections(
    flows: list[dict[str, Any]],
    alerts: list[dict[str, Any]],
    *,
    sources: list[dict[str, Any]],
    failures: list[str],
    window: tuple[int, int, int],
    client: str,
    limit: int,
) -> dict[str, Any]:
    """Merge, filter and wrap detections in the ``list_threat_detections`` envelope.

    Shared by the real client and stub mode so both answer in one shape.
    ``window`` is ``(hours, start_ms, end_ms)``. When ``failures`` is not
    empty the envelope opens with a ``warning`` and says ``complete: false``:
    a partial list must never read as a full one.
    """
    hours, start_ms, end_ms = window
    detections = merge_detections(flows, alerts)
    matcher = client_matcher(client) if client else None
    if matcher is not None:
        detections = [d for d in detections if matches_client(d, matcher)]
    returned = detections[:limit]
    result: dict[str, Any] = {}
    if failures:
        result["warning"] = (
            f"Only part of the IPS record was read: {'; '.join(failures)}. Detections "
            f"from that source are missing, so a short or empty list here is not "
            f"proof that nothing was blocked."
        )
    result.update(
        {
            "complete": not failures,
            "window": {"hours": hours, "from": iso_utc(start_ms), "to": iso_utc(end_ms)},
            "client_filter": client or None,
            "sources": sources,
            "matched": len(detections),
            "returned": len(returned),
            "detections": returned,
        }
    )
    return result


def client_matcher(client: str) -> tuple[str, str] | None:
    """Parse a client filter into ``("ip", value)`` or ``("mac", value)``.

    Returns ``None`` when ``client`` is neither, so the tool can refuse it
    rather than filter on something that can never match.
    """
    text = client.strip()
    try:
        return ("ip", str(ipaddress.ip_address(text)))
    except ValueError:
        pass
    if is_mac(text):
        return ("mac", normalize_mac(text))
    return None


def matches_client(detection: dict[str, Any], matcher: tuple[str, str]) -> bool:
    """``True`` when either end of ``detection`` is the matched IP or MAC."""
    kind, value = matcher
    return value in (detection.get(f"src_{kind}"), detection.get(f"dst_{kind}"))


__all__ = [
    "MAX_SCAN_ROWS",
    "SYSTEM_LOG_PAGE_SIZE",
    "TRAFFIC_FLOW_PAGE_SIZE",
    "client_matcher",
    "detection_from_alert",
    "detection_from_flow",
    "finish_detections",
    "ips_flow_body",
    "iso_utc",
    "matches_client",
    "merge_detections",
    "parse_page",
    "render_message",
    "shape_log_entry",
    "system_log_body",
]
