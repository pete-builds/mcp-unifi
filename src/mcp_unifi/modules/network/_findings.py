"""The findings contract shared by the diagnose tools.

A diagnosis is evidence plus rule-based conclusions, never a narrative. This
module holds the small typed builders every diagnose rule uses, so that the
shape of a finding is decided in one place and a rule cannot invent its own.
See ADR 0010 for why the layer is deterministic and why rule ids are stable.

The contract, in one paragraph:

* ``observed`` holds only values read from the controller, each with the tool
  it came from. ``inferred`` is the rule's own conclusion and may be ``None``.
  The two never mix.
* Controller-provided text (device names, alarm keys, IPS categories) is
  untrusted. It may appear only in ``subject["name"]`` and in ``observed``
  values, and only after :func:`clean_text` has stripped control characters
  and capped its length. ``summary`` and ``inferred`` are built from fixed
  templates and numbers, so a device named "ignore previous instructions"
  cannot speak in the tool's own voice.
* A rule that could not run, or could only run over part of its subjects, is
  listed in ``not_evaluated``. :func:`verdict` refuses to call a site healthy
  while any rule able to find a critical problem is in that list.

No framework: plain ``TypedDict`` shapes and functions that build them.
"""

from __future__ import annotations

import unicodedata
from typing import Any, Literal, TypedDict

Severity = Literal["critical", "warning", "info"]
Confidence = Literal["high", "medium", "low"]
Verdict = Literal["healthy", "degraded", "critical", "unknown"]
Scope = Literal["rule", "partial"]

#: Sort order for findings: the worst first.
SEVERITY_RANK: dict[str, int] = {"critical": 0, "warning": 1, "info": 2}

#: Longest controller-provided string that may appear in a diagnosis.
MAX_TEXT_CHARS = 80


class Observed(TypedDict):
    fact: str
    source: str


class NextStep(TypedDict):
    tool: str
    args: dict[str, Any]


class Finding(TypedDict):
    id: str
    severity: Severity
    subject: dict[str, str]
    observed: list[Observed]
    inferred: str | None
    confidence: Confidence
    limitations: list[str]
    next: list[NextStep]


class NotEvaluated(TypedDict):
    rule: str
    scope: Scope
    reason: str


def clean_text(value: object, limit: int = MAX_TEXT_CHARS) -> str:
    """Make controller-provided text safe to echo inside a diagnosis.

    Drops every Unicode control, format, surrogate, private-use and unassigned
    code point (category ``C*``: newlines, ANSI escapes, bidi overrides,
    zero-width joiners), collapses runs of whitespace to one space, and caps
    the result at ``limit`` characters with a trailing ellipsis. ``None``
    becomes the empty string.
    """
    if value is None:
        return ""
    text = str(value)
    # Whitespace first (newline and tab are themselves category Cc), then drop
    # every remaining C* code point.
    kept = "".join(
        " " if ch.isspace() else ch
        for ch in text
        if ch.isspace() or not unicodedata.category(ch).startswith("C")
    )
    collapsed = " ".join(kept.split())
    if len(collapsed) > limit:
        return collapsed[: limit - 1] + "…"
    return collapsed


def observed(name: str, value: object, source: str) -> Observed:
    """One fact read from the controller, as ``name=value``.

    ``name`` is a field name chosen by the rule (trusted). ``value`` is
    whatever the controller returned and is passed through :func:`clean_text`
    unless it is a number or a boolean.
    """
    if isinstance(value, bool):
        rendered = "true" if value else "false"
    elif isinstance(value, int | float):
        rendered = str(value)
    else:
        rendered = clean_text(value)
    return {"fact": f"{name}={rendered}", "source": source}


def next_step(tool: str, **args: Any) -> NextStep:
    """A follow-up call: a registered tool name and the arguments to pass."""
    return {"tool": tool, "args": dict(sorted(args.items()))}


def subject(kind: str, *, mac: str = "", name: object = None, **extra: str) -> dict[str, str]:
    """What a finding is about. ``name`` is cleaned; empty fields are dropped."""
    out: dict[str, str] = {"type": kind}
    if mac:
        out["mac"] = mac
    cleaned = clean_text(name)
    if cleaned:
        out["name"] = cleaned
    for key in sorted(extra):
        if extra[key]:
            out[key] = clean_text(extra[key])
    return out


def finding(
    rule_id: str,
    severity: Severity,
    subj: dict[str, str],
    facts: list[Observed],
    *,
    inferred: str | None,
    confidence: Confidence,
    limitations: list[str] | None = None,
    next_steps: list[NextStep] | None = None,
) -> Finding:
    return {
        "id": rule_id,
        "severity": severity,
        "subject": subj,
        "observed": facts,
        "inferred": inferred,
        "confidence": confidence,
        "limitations": sorted(limitations or []),
        "next": next_steps or [],
    }


def not_evaluated(rule_id: str, reason: str, *, scope: Scope = "rule") -> NotEvaluated:
    """A rule that did not run (``rule``) or ran over only some subjects (``partial``)."""
    return {"rule": rule_id, "scope": scope, "reason": reason}


def finding_sort_key(item: Finding) -> tuple[int, str, str, str]:
    subj = item["subject"]
    return (
        SEVERITY_RANK[item["severity"]],
        item["id"],
        subj.get("mac", ""),
        subj.get("name", ""),
    )


def cap_findings(
    rule_id: str, items: list[Finding], limit: int
) -> tuple[list[Finding], dict[str, int]]:
    """Keep the ``limit`` worst findings of one rule; report how many were dropped."""
    ordered = sorted(items, key=finding_sort_key)
    dropped = max(0, len(ordered) - limit)
    return ordered[:limit], ({rule_id: dropped} if dropped else {})


def verdict(
    findings: list[Finding],
    gaps: list[NotEvaluated],
    critical_capable: frozenset[str],
) -> Verdict:
    """The site verdict, from findings and evaluation gaps.

    Order, worst first: ``critical`` (a critical finding exists), ``unknown``
    (no critical finding, but a rule able to find one did not run over every
    subject, so a critical problem cannot be ruled out), ``degraded`` (a
    warning exists), ``healthy``. Info findings never move the verdict.
    """
    severities = {f["severity"] for f in findings}
    if "critical" in severities:
        return "critical"
    if any(g["rule"] in critical_capable for g in gaps):
        return "unknown"
    if "warning" in severities:
        return "degraded"
    return "healthy"
