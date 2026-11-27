"""``diagnose_site``: one deterministic answer to "is my network healthy?".

Why this file exists
--------------------
Answering "is the network OK, and if not, what is wrong?" used to take an
agent six to eight calls (site health, devices, clients, alarms, IPS
detections...) and then its own reasoning over raw controller records, with
no shared notion of what counts as a problem. This tool makes the five reads
once, runs a fixed list of rules over them, and returns findings in the
contract defined in :mod:`._findings`: what was observed (with its source),
what the rule concludes, how confident it is, what it could not see, and
which tool to call next.

What it is not
--------------
* Not an LLM. No model call, no generated prose. The consuming agent does
  the reasoning; this tool supplies evidence and rule-based findings.
* Not a reachability or topology tool, and it keeps no history. Those are
  later layers (ADR 0010).
* Not the console-layer check. When the Network application cannot be read
  at all, the answer is ``unknown`` and the top-level ``next`` points at
  ``get_console_health``, which probes UniFi OS separately.

Honesty rules
-------------
Every read is caught on its own. A read that raises, or returns something
that is not the documented shape, marks every rule that needs it as not
evaluated, and the verdict can never be ``healthy`` while a rule able to find
a critical problem is in that list. An empty list from a read that succeeded
is evidence; an empty list from one that failed is not, and is never
produced. Thresholds are module constants, echoed in every response.

Determinism
-----------
The same backend state produces byte-identical output: findings are sorted,
subjects are sorted, nothing reads the clock. The two time-windowed reads
(alarms, IPS) pass ``hours`` to the backend and only counts come back out, so
no wall-clock timestamp reaches the response.
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from mcp_unifi.annotations import READ_ONLY
from mcp_unifi.clients.mac import is_mac, normalize_mac
from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.dispatcher import resolve_backend
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules.network._common import format_json, make_err
from mcp_unifi.modules.network._findings import (
    Finding,
    NextStep,
    NotEvaluated,
    Severity,
    cap_findings,
    clean_text,
    finding,
    finding_sort_key,
    next_step,
    not_evaluated,
    observed,
    subject,
    verdict,
)

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.backends import Backend
    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.network.diagnose")

# ---------------------------------------------------------------------------
# Thresholds. Conservative defaults chosen for this tool, NOT vendor guidance.
# Every one is echoed in the response under ``thresholds``.
# ---------------------------------------------------------------------------

#: Look-back for the alarm and IPS reads, in hours.
WINDOW_HOURS = 24
#: A connected device above this CPU percentage is a warning.
DEVICE_CPU_PCT_WARN = 90.0
#: A connected device above this memory percentage is a warning.
DEVICE_MEM_PCT_WARN = 90.0
#: A wireless client whose ``signal`` is below this (dBm) counts as weak.
WEAK_SIGNAL_DBM = -75
#: An AP with at least this many weak clients is a warning.
WEAK_CLIENTS_PER_AP_WARN = 3
#: Findings kept per rule; the rest are counted under ``truncated``.
MAX_FINDINGS_PER_RULE = 10
#: Rows read from the alarm and IPS logs.
LOG_READ_LIMIT = 100
#: Site-health subsystems evaluated. ``vpn`` is left out on purpose: a site
#: with no VPN configured reports it as ``warning`` (the seeded stub does
#: too), which would make every such site permanently degraded.
HEALTH_SUBSYSTEMS: tuple[str, ...] = ("wan", "www", "lan", "wlan")

#: Device ``state`` the controller uses for "connected" and "disconnected".
#: Other values (upgrading, provisioning, heartbeat missed, adopting...) are
#: reported by number, without a name this server has not verified.
STATE_CONNECTED = 1
STATE_DISCONNECTED = 0

THRESHOLDS: dict[str, Any] = {
    "window_hours": WINDOW_HOURS,
    "device_cpu_pct_warn": DEVICE_CPU_PCT_WARN,
    "device_mem_pct_warn": DEVICE_MEM_PCT_WARN,
    "weak_signal_dbm": WEAK_SIGNAL_DBM,
    "weak_clients_per_ap_warn": WEAK_CLIENTS_PER_AP_WARN,
    "max_findings_per_rule": MAX_FINDINGS_PER_RULE,
    "log_read_limit": LOG_READ_LIMIT,
    "health_subsystems": list(HEALTH_SUBSYSTEMS),
}

# Source names are the tool an agent would call to see the same data.
SRC_DEVICES = "list_devices"
SRC_HEALTH = "get_site_health"
SRC_CLIENTS = "list_clients"
SRC_ALARMS = "list_alarms"
SRC_THREATS = "list_threat_detections"
SOURCES: tuple[str, ...] = (SRC_DEVICES, SRC_HEALTH, SRC_CLIENTS, SRC_ALARMS, SRC_THREATS)

#: Longest error text carried from a failed read.
MAX_ERROR_CHARS = 160

# ---------------------------------------------------------------------------
# Snapshot: the five reads, each with its own outcome
# ---------------------------------------------------------------------------


@dataclass
class SourceResult:
    """One read. ``ok`` is False when it raised or returned the wrong shape."""

    name: str
    ok: bool
    records: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""
    #: Set when the read succeeded but says it is incomplete.
    partial: str = ""


Snapshot = dict[str, SourceResult]


def _dict_rows(value: Any) -> list[dict[str, Any]] | None:
    if not isinstance(value, list):
        return None
    return [row for row in value if isinstance(row, dict)]


def _shape_list(name: str, raw: Any) -> SourceResult:
    rows = _dict_rows(raw)
    if rows is None:
        return SourceResult(
            name, ok=False, error=f"{name} returned {type(raw).__name__}, not a list"
        )
    return SourceResult(name, ok=True, records=rows)


def _shape_alarms(raw: Any) -> SourceResult:
    rows = _dict_rows(raw.get("alarms")) if isinstance(raw, dict) else None
    if rows is None:
        return SourceResult(SRC_ALARMS, ok=False, error="list_alarms envelope has no alarms list")
    partial = ""
    if raw.get("window_fully_read") is False or raw.get("more_available") is True:
        partial = "the alarm log holds more rows than were read"
    return SourceResult(SRC_ALARMS, ok=True, records=rows, partial=partial)


def _shape_threats(raw: Any) -> SourceResult:
    rows = _dict_rows(raw.get("detections")) if isinstance(raw, dict) else None
    if rows is None:
        return SourceResult(
            SRC_THREATS, ok=False, error="list_threat_detections envelope has no detections list"
        )
    partial = ""
    if raw.get("complete") is False:
        partial = "the IPS read was incomplete (a source failed or was cut off)"
    return SourceResult(SRC_THREATS, ok=True, records=rows, partial=partial)


async def _read(
    name: str, call: Callable[[], Awaitable[Any]], shape: Callable[[Any], SourceResult]
) -> SourceResult:
    try:
        raw = await call()
    except UniFiError as exc:
        logger.warning("diagnose_site: %s failed: %s", name, exc)
        return SourceResult(name, ok=False, error=clean_text(str(exc), MAX_ERROR_CHARS))
    return shape(raw)


async def collect(backend: Backend) -> Snapshot:
    """Make the five reads, in a fixed order, each failing on its own."""
    results = [
        await _read(SRC_DEVICES, backend.list_devices, lambda r: _shape_list(SRC_DEVICES, r)),
        await _read(SRC_HEALTH, backend.get_site_health, lambda r: _shape_list(SRC_HEALTH, r)),
        await _read(SRC_CLIENTS, backend.list_clients, lambda r: _shape_list(SRC_CLIENTS, r)),
        await _read(
            SRC_ALARMS,
            lambda: backend.list_alarms(LOG_READ_LIMIT, False, WINDOW_HOURS),
            _shape_alarms,
        ),
        await _read(
            SRC_THREATS,
            lambda: backend.list_threat_detections(WINDOW_HOURS, LOG_READ_LIMIT, ""),
            _shape_threats,
        ),
    ]
    return {r.name: r for r in results}


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

#: What a rule returns: its findings and any evaluation gaps.
RuleOutcome = tuple[list[Finding], list[NotEvaluated]]


@dataclass(frozen=True)
class Rule:
    id: str
    #: Every severity this rule can emit. A rule that can emit ``critical``
    #: blocks a ``healthy`` verdict whenever it is not fully evaluated.
    severities: frozenset[str]
    #: Reads the rule cannot run without.
    requires: tuple[str, ...]
    #: Every tool this rule can name in ``next`` (checked against the registry).
    next_tools: frozenset[str]
    evaluate: Callable[[Snapshot], RuleOutcome]
    summary: str


def _mac(record: dict[str, Any], key: str = "mac") -> str:
    """The record's MAC in canonical form, or ``""`` when it is not a MAC."""
    value = record.get(key)
    return normalize_mac(value) if is_mac(value) else ""


def _device_subject(dev: dict[str, Any]) -> dict[str, str]:
    return subject(
        "device",
        mac=_mac(dev),
        name=dev.get("name") or dev.get("model"),
        device_type=str(dev.get("type") or ""),
    )


def _adopted(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # A record the controller marks ``adopted: false`` is pending adoption and
    # was never part of the site, so it cannot be "offline".
    return [d for d in devices if d.get("adopted") is not False]


def _int_state(dev: dict[str, Any]) -> int | None:
    state = dev.get("state")
    if isinstance(state, bool) or not isinstance(state, int):
        return None
    return state


def _device_steps(dev: dict[str, Any]) -> list[NextStep]:
    mac = _mac(dev)
    return [next_step("get_device_stats", mac=mac)] if mac else []


def _devices_or_gap(snap: Snapshot, rule_id: str) -> list[dict[str, Any]] | NotEvaluated:
    devices = _adopted(snap[SRC_DEVICES].records)
    if not devices:
        return not_evaluated(rule_id, "list_devices returned no adopted devices")
    return devices


def _devices_with_state(
    snap: Snapshot, rule_id: str
) -> tuple[list[tuple[dict[str, Any], int]], list[NotEvaluated]]:
    """Adopted devices paired with their numeric ``state``, plus any coverage gap."""
    devices = _devices_or_gap(snap, rule_id)
    if isinstance(devices, dict):
        return [], [devices]
    pairs = [(d, s) for d in devices if (s := _int_state(d)) is not None]
    missing = len(devices) - len(pairs)
    if not pairs:
        return [], [not_evaluated(rule_id, "no device record carries a numeric state")]
    if missing:
        reason = f"{missing} of {len(devices)} adopted devices carry no numeric state"
        return pairs, [not_evaluated(rule_id, reason, scope="partial")]
    return pairs, []


def _offline(snap: Snapshot) -> RuleOutcome:
    rule_id = "device.offline"
    pairs, gaps = _devices_with_state(snap, rule_id)
    out = [
        finding(
            rule_id,
            "critical",
            _device_subject(dev),
            [observed("state", state, SRC_DEVICES)],
            inferred="The controller reports this adopted device as disconnected.",
            confidence="high",
            next_steps=[*_device_steps(dev), next_step("list_events", hours=WINDOW_HOURS)],
        )
        for dev, state in pairs
        if state == STATE_DISCONNECTED
    ]
    return out, gaps


def _not_connected(snap: Snapshot) -> RuleOutcome:
    rule_id = "device.not_connected"
    pairs, gaps = _devices_with_state(snap, rule_id)
    out = [
        finding(
            rule_id,
            "warning",
            _device_subject(dev),
            [observed("state", state, SRC_DEVICES)],
            inferred=(
                "The device is adopted but not in the connected state; it may be "
                "upgrading, provisioning, or missing heartbeats."
            ),
            confidence="medium",
            next_steps=_device_steps(dev),
        )
        for dev, state in pairs
        if state not in (STATE_CONNECTED, STATE_DISCONNECTED)
    ]
    return out, gaps


def _pct(dev: dict[str, Any], key: str) -> float | None:
    stats = dev.get("system-stats")
    if not isinstance(stats, dict):
        stats = dev.get("sys_stats")
    if not isinstance(stats, dict):
        return None
    raw = stats.get(key)
    if isinstance(raw, bool) or raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _resource_rule(
    rule_id: str, key: str, limit: float, label: str
) -> Callable[[Snapshot], RuleOutcome]:
    def evaluate(snap: Snapshot) -> RuleOutcome:
        devices = _devices_or_gap(snap, rule_id)
        if isinstance(devices, dict):
            return [], [devices]
        # Stats on a disconnected device are its last report, not its state.
        connected = [d for d in devices if _int_state(d) == STATE_CONNECTED]
        if not connected:
            return [], [not_evaluated(rule_id, "no adopted device is connected")]
        values = [(d, _pct(d, key)) for d in connected]
        missing = sum(1 for _, v in values if v is None)
        if missing == len(connected):
            return [], [not_evaluated(rule_id, f"no connected device reports system-stats {key}")]
        gaps = (
            [
                not_evaluated(
                    rule_id,
                    f"{missing} of {len(connected)} connected devices report no system-stats {key}",
                    scope="partial",
                )
            ]
            if missing
            else []
        )
        out = [
            finding(
                rule_id,
                "warning",
                _device_subject(dev),
                [observed(f"system-stats.{key}", value, SRC_DEVICES)],
                inferred=f"{label} use is above the {limit:g}% threshold.",
                confidence="medium",
                limitations=["one sample; a short spike reads the same as sustained load"],
                next_steps=_device_steps(dev),
            )
            for dev, value in values
            if value is not None and value > limit
        ]
        return out, gaps

    return evaluate


def _upgradable(snap: Snapshot) -> RuleOutcome:
    rule_id = "device.upgradable"
    devices = _devices_or_gap(snap, rule_id)
    if isinstance(devices, dict):
        return [], [devices]
    flagged = [d for d in devices if isinstance(d.get("upgradable"), bool)]
    if not flagged:
        return [], [not_evaluated(rule_id, "no device record carries an upgradable flag")]
    gaps = []
    if len(flagged) < len(devices):
        gaps.append(
            not_evaluated(
                rule_id,
                f"{len(devices) - len(flagged)} of {len(devices)} adopted devices carry no "
                "upgradable flag",
                scope="partial",
            )
        )
    out: list[Finding] = []
    for dev in flagged:
        if dev["upgradable"] is not True:
            continue
        facts = [observed("upgradable", True, SRC_DEVICES)]
        if dev.get("version"):
            facts.append(observed("version", dev.get("version"), SRC_DEVICES))
        if dev.get("upgrade_to_firmware"):
            facts.append(
                observed("upgrade_to_firmware", dev.get("upgrade_to_firmware"), SRC_DEVICES)
            )
        out.append(
            finding(
                rule_id,
                "info",
                _device_subject(dev),
                facts,
                inferred=(
                    "The controller offers a firmware update for this device. This server "
                    "has no upgrade tool; apply it from the UniFi console."
                ),
                confidence="high",
            )
        )
    return out, gaps


def _health_by_subsystem(snap: Snapshot) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for rec in snap[SRC_HEALTH].records:
        name = rec.get("subsystem")
        if isinstance(name, str) and name not in out:
            out[name] = rec
    return out


def _status(rec: dict[str, Any] | None) -> str | None:
    if rec is None:
        return None
    status = rec.get("status")
    return status.lower() if isinstance(status, str) and status else None


def _wan_down(snap: Snapshot) -> RuleOutcome:
    rule_id = "wan.down"
    by_name = _health_by_subsystem(snap)
    if not by_name:
        return [], [not_evaluated(rule_id, "get_site_health returned no subsystem records")]
    status = _status(by_name.get("wan"))
    if status is None:
        return [], [not_evaluated(rule_id, "site health carries no wan record with a status")]
    if status != "error":
        return [], []
    return [
        finding(
            rule_id,
            "critical",
            subject("subsystem", name="wan"),
            [observed("status", status, SRC_HEALTH)],
            inferred=(
                "The controller reports the WAN subsystem in error, which usually means "
                "the internet uplink is down."
            ),
            confidence="medium",
            next_steps=[
                next_step("get_wan_status"),
                next_step("list_events", hours=WINDOW_HOURS),
            ],
        )
    ], []


_STATUS_SEVERITY: dict[str, Severity] = {"error": "critical", "warning": "warning"}


def _subsystem_not_ok(snap: Snapshot) -> RuleOutcome:
    rule_id = "health.subsystem_not_ok"
    by_name = _health_by_subsystem(snap)
    if not by_name:
        return [], [not_evaluated(rule_id, "get_site_health returned no subsystem records")]
    out: list[Finding] = []
    missing: list[str] = []
    for name in HEALTH_SUBSYSTEMS:
        status = _status(by_name.get(name))
        if status is None:
            missing.append(name)
            continue
        # wan in error is reported once, by wan.down.
        if status == "ok" or (name == "wan" and status == "error"):
            continue
        severity = _STATUS_SEVERITY.get(status, "info")
        out.append(
            finding(
                rule_id,
                severity,
                subject("subsystem", name=name),
                [observed("status", status, SRC_HEALTH)],
                inferred=f"The controller reports the {name} subsystem as not ok.",
                confidence="medium" if severity != "info" else "low",
                next_steps=[next_step("get_site_health")],
            )
        )
    if len(missing) == len(HEALTH_SUBSYSTEMS):
        return [], [not_evaluated(rule_id, "site health carries none of the evaluated subsystems")]
    gaps = (
        [
            not_evaluated(
                rule_id,
                "site health carries no status for: " + ", ".join(missing),
                scope="partial",
            )
        ]
        if missing
        else []
    )
    return out, gaps


def _weak_signal(snap: Snapshot) -> RuleOutcome:
    rule_id = "wifi.weak_signal_clients"
    wireless = [c for c in snap[SRC_CLIENTS].records if c.get("is_wired") is False]
    gaps: list[NotEvaluated] = []
    with_signal: list[tuple[str, int]] = []
    for client in wireless:
        signal = client.get("signal")
        ap_mac = _mac(client, "ap_mac")
        if not ap_mac or isinstance(signal, bool) or not isinstance(signal, int | float):
            continue
        with_signal.append((ap_mac, int(signal)))
    missing = len(wireless) - len(with_signal)
    if missing:
        gaps.append(
            not_evaluated(
                rule_id,
                f"{missing} of {len(wireless)} wireless clients report no signal or AP",
                scope="partial",
            )
        )
    per_ap: dict[str, list[int]] = {}
    for ap_mac, signal in with_signal:
        per_ap.setdefault(ap_mac, []).append(signal)

    devices_ok = snap[SRC_DEVICES].ok
    names = {_mac(d): d.get("name") or d.get("model") for d in snap[SRC_DEVICES].records}
    out: list[Finding] = []
    for ap_mac in sorted(per_ap):
        signals = per_ap[ap_mac]
        weak = [s for s in signals if s < WEAK_SIGNAL_DBM]
        if len(weak) < WEAK_CLIENTS_PER_AP_WARN:
            continue
        out.append(
            finding(
                rule_id,
                "warning",
                subject("access_point", mac=ap_mac, name=names.get(ap_mac)),
                [
                    observed("weak_clients", len(weak), SRC_CLIENTS),
                    observed("wireless_clients", len(signals), SRC_CLIENTS),
                    observed("weakest_signal_dbm", min(weak), SRC_CLIENTS),
                ],
                inferred=(
                    f"{len(weak)} clients on this AP are below {WEAK_SIGNAL_DBM} dBm; they "
                    "may be far from it, or its placement or transmit power may need review."
                ),
                confidence="medium",
                limitations=[] if devices_ok else ["AP name unavailable: list_devices failed"],
                next_steps=[next_step("get_device_radios", device_mac=ap_mac)],
            )
        )
    return out, gaps


def _alarms(snap: Snapshot) -> RuleOutcome:
    rule_id = "alarms.active"
    src = snap[SRC_ALARMS]
    counts = Counter(clean_text(a.get("key")) or "(no key)" for a in src.records)
    limitations = [f"{src.partial}; counts are lower bounds"] if src.partial else []
    out = [
        finding(
            rule_id,
            "warning",
            subject("alarm_key", name=key),
            [observed("count", count, SRC_ALARMS), observed("key", key, SRC_ALARMS)],
            inferred=(
                f"Critical-log entries of this kind in the last {WINDOW_HOURS} hours: {count}."
            ),
            confidence="high",
            limitations=limitations,
            next_steps=[next_step("list_alarms", hours=WINDOW_HOURS)],
        )
        for key, count in sorted(counts.items())
    ]
    return out, []


def _threats(snap: Snapshot) -> RuleOutcome:
    rule_id = "threats.detected"
    src = snap[SRC_THREATS]
    if src.partial and not src.records:
        # An empty partial read is not proof that nothing was detected.
        return [], [not_evaluated(rule_id, src.partial)]
    groups: dict[str, list[dict[str, Any]]] = {}
    for det in src.records:
        action = clean_text(det.get("action")).lower() or "unknown"
        groups.setdefault(action, []).append(det)
    limitations = [f"{src.partial}; counts are lower bounds"] if src.partial else []
    out: list[Finding] = []
    for action in sorted(groups):
        rows = groups[action]
        blocked = action == "blocked"
        categories = Counter(clean_text(r.get("category")) for r in rows if r.get("category"))
        facts = [observed("count", len(rows), SRC_THREATS), observed("action", action, SRC_THREATS)]
        if categories:
            top = sorted(categories.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
            facts.append(observed("top_category", top, SRC_THREATS))
        out.append(
            finding(
                rule_id,
                "info" if blocked else "warning",
                subject("threat_action", name=action),
                facts,
                inferred=(
                    f"Detections Threat Management blocked in the last {WINDOW_HOURS} hours: "
                    f"{len(rows)}; the protection acted."
                    if blocked
                    else f"Detections in the last {WINDOW_HOURS} hours not recorded as blocked: "
                    f"{len(rows)}."
                ),
                confidence="high" if blocked else "medium",
                limitations=limitations,
                next_steps=[next_step("list_threat_detections", hours=WINDOW_HOURS)],
            )
        )
    return out, []


RULES: tuple[Rule, ...] = (
    Rule(
        "device.offline",
        frozenset({"critical"}),
        (SRC_DEVICES,),
        frozenset({"get_device_stats", "list_events"}),
        _offline,
        "An adopted device reports state 0 (disconnected).",
    ),
    Rule(
        "device.not_connected",
        frozenset({"warning"}),
        (SRC_DEVICES,),
        frozenset({"get_device_stats"}),
        _not_connected,
        "An adopted device reports a state other than connected or disconnected.",
    ),
    Rule(
        "device.high_cpu",
        frozenset({"warning"}),
        (SRC_DEVICES,),
        frozenset({"get_device_stats"}),
        _resource_rule("device.high_cpu", "cpu", DEVICE_CPU_PCT_WARN, "CPU"),
        "A connected device's system-stats cpu is above device_cpu_pct_warn.",
    ),
    Rule(
        "device.high_memory",
        frozenset({"warning"}),
        (SRC_DEVICES,),
        frozenset({"get_device_stats"}),
        _resource_rule("device.high_memory", "mem", DEVICE_MEM_PCT_WARN, "Memory"),
        "A connected device's system-stats mem is above device_mem_pct_warn.",
    ),
    Rule(
        "device.upgradable",
        frozenset({"info"}),
        (SRC_DEVICES,),
        frozenset(),
        _upgradable,
        "The controller flags a device upgradable.",
    ),
    Rule(
        "wan.down",
        frozenset({"critical"}),
        (SRC_HEALTH,),
        frozenset({"get_wan_status", "list_events"}),
        _wan_down,
        "Site health reports the wan subsystem with status error.",
    ),
    Rule(
        "health.subsystem_not_ok",
        frozenset({"critical", "warning", "info"}),
        (SRC_HEALTH,),
        frozenset({"get_site_health"}),
        _subsystem_not_ok,
        "A wan, www, lan or wlan subsystem status is not ok (error is critical, warning is "
        "warning, anything else is info).",
    ),
    Rule(
        "wifi.weak_signal_clients",
        frozenset({"warning"}),
        (SRC_CLIENTS,),
        frozenset({"get_device_radios"}),
        _weak_signal,
        "An AP has weak_clients_per_ap_warn or more wireless clients below weak_signal_dbm.",
    ),
    Rule(
        "alarms.active",
        frozenset({"warning"}),
        (SRC_ALARMS,),
        frozenset({"list_alarms"}),
        _alarms,
        "The critical log holds entries in the window, one finding per alarm key.",
    ),
    Rule(
        "threats.detected",
        frozenset({"warning", "info"}),
        (SRC_THREATS,),
        frozenset({"list_threat_detections"}),
        _threats,
        "Threat Management recorded detections in the window; blocked ones are info, the "
        "rest warning.",
    ),
)

#: Rules whose not-evaluated status blocks a ``healthy`` verdict.
CRITICAL_CAPABLE: frozenset[str] = frozenset(r.id for r in RULES if "critical" in r.severities)

#: Next step offered at the top level whenever a read failed.
SOURCE_FAILURE_NEXT: NextStep = next_step("get_console_health")


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def _summary(result: str, findings: list[Finding], gaps: list[NotEvaluated], failed: int) -> str:
    counts = Counter(f["severity"] for f in findings)
    crit, warn, info = counts["critical"], counts["warning"], counts["info"]
    gap_rules = len({g["rule"] for g in gaps})
    if result == "critical":
        head = f"{crit} critical and {warn} warning finding(s)."
    elif result == "unknown":
        head = (
            f"Health cannot be confirmed: a check able to find a critical problem did not "
            f"fully run. {warn} warning finding(s) so far."
        )
    elif result == "degraded":
        head = f"{warn} warning finding(s), no critical ones."
    else:
        head = "No critical or warning findings."
    tail = []
    if info:
        tail.append(f"{info} info finding(s)")
    if gap_rules:
        tail.append(f"{gap_rules} rule(s) not fully evaluated")
    if failed:
        tail.append(f"{failed} of {len(SOURCES)} reads failed")
    return head + (" " + "; ".join(tail) + "." if tail else "")


def build_report(snap: Snapshot, *, controller: str, stub_mode: bool) -> dict[str, Any]:
    """Run every rule over a snapshot. Pure: no I/O, no clock."""
    findings: list[Finding] = []
    gaps: list[NotEvaluated] = []
    truncated: dict[str, int] = {}
    evaluated: list[str] = []
    for rule in RULES:
        failed = [s for s in rule.requires if not snap[s].ok]
        if failed:
            gaps.append(not_evaluated(rule.id, f"required read failed: {', '.join(failed)}"))
            continue
        found, rule_gaps = rule.evaluate(snap)
        kept, dropped = cap_findings(rule.id, found, MAX_FINDINGS_PER_RULE)
        findings.extend(kept)
        truncated.update(dropped)
        gaps.extend(rule_gaps)
        if not any(g["scope"] == "rule" for g in rule_gaps):
            evaluated.append(rule.id)
    findings.sort(key=finding_sort_key)
    gaps.sort(key=lambda g: (g["rule"], g["scope"], g["reason"]))

    failed_reads = [snap[s] for s in SOURCES if not snap[s].ok]
    checks: list[dict[str, Any]] = []
    for name in SOURCES:
        res = snap[name]
        check: dict[str, Any] = {"source": name, "ok": res.ok}
        if res.ok:
            check["records"] = len(res.records)
            if res.partial:
                check["partial"] = res.partial
        else:
            check["error"] = res.error
        checks.append(check)

    result = verdict(findings, gaps, CRITICAL_CAPABLE)
    return {
        "diagnosis": "site",
        "controller": controller,
        "stub_mode": stub_mode,
        "verdict": result,
        "summary": _summary(result, findings, gaps, len(failed_reads)),
        "findings": findings,
        "truncated": dict(sorted(truncated.items())),
        "not_evaluated": gaps,
        "rules_evaluated": sorted(evaluated),
        "checks": checks,
        "next": [SOURCE_FAILURE_NEXT] if failed_reads else [],
        "thresholds": THRESHOLDS,
    }


async def diagnose(backend: Backend, *, controller: str, stub_mode: bool) -> dict[str, Any]:
    return build_report(await collect(backend), controller=controller, stub_mode=stub_mode)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool(annotations=READ_ONLY)
    @audited("diagnose_site", mutates=False)
    async def diagnose_site(controller: str = "default") -> str:
        """Diagnose a whole site in one call: verdict, findings, and what to check next.

        Call this FIRST for "is my network healthy?" or "what is wrong?". It
        reads devices, site health, clients, alarms and IPS detections, runs
        fixed rules (no AI), and returns ``verdict`` (healthy, degraded,
        critical, unknown), ``findings`` (each with ``observed`` facts and
        their source, ``inferred``, ``confidence``, ``limitations``, and
        ``next`` tool calls), ``not_evaluated``, ``checks`` and
        ``thresholds``. A failed read is never read as clean: its rules are
        listed as not evaluated, and if one of them can find a critical
        problem the verdict is unknown, not healthy. Use the granular tools
        named in ``next`` to investigate further.

        Side effects: None (read-only, five reads).

        Example: diagnose_site(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            name = registry.resolve_name(controller)
        except UniFiError as exc:
            return err(str(exc))
        report = await diagnose(backend, controller=name, stub_mode=settings.stub_mode)
        return format_json(report)
