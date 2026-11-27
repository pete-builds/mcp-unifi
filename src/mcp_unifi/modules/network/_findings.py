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

    ``name`` is a field name chosen by the rule (trusted, never contains
    ``=``). ``value`` is whatever the controller returned. It is rendered
    here and cleaned by :func:`finding`, the one seam every finding passes
    through, so a rule cannot forget to clean it.
    """
    if isinstance(value, bool):
        rendered = "true" if value else "false"
    elif isinstance(value, int | float):
        rendered = str(value)
    else:
        rendered = "" if value is None else str(value)
    return {"fact": f"{name}={rendered}", "source": source}


def next_step(tool: str, **args: Any) -> NextStep:
    """A follow-up call: a registered tool name and the arguments to pass."""
    return {"tool": tool, "args": dict(sorted(args.items()))}


def subject(kind: str, *, mac: str = "", name: object = None, **extra: object) -> dict[str, str]:
    """What a finding is about. Values are cleaned by :func:`finding`; empty ones are dropped."""
    out: dict[str, str] = {"type": kind}
    if mac:
        out["mac"] = mac
    if name is not None:
        out["name"] = str(name)
    for key in sorted(extra):
        if extra[key] is not None:
            out[key] = str(extra[key])
    return out


def _clean_subject(subj: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in subj.items():
        cleaned = clean_text(value)
        if cleaned:
            out[key] = cleaned
    return out


def _clean_fact(fact: Observed) -> Observed:
    name, _, value = fact["fact"].partition("=")
    return {"fact": f"{name}={clean_text(value)}", "source": fact["source"]}


def _clean_step(step: NextStep) -> NextStep:
    args = {
        key: clean_text(value) if isinstance(value, str) else value
        for key, value in step["args"].items()
    }
    return {"tool": step["tool"], "args": args}


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
    """Build a finding. The one seam where controller-derived text is cleaned.

    Every subject value, every observed value and every string argument of
    a next step goes through :func:`clean_text` here, whichever rule built
    it. ``inferred`` and ``limitations`` are the rule's own fixed text and
    are not cleaned: a rule must never put controller text in them.
    """
    return {
        "id": rule_id,
        "severity": severity,
        "subject": _clean_subject(subj),
        "observed": [_clean_fact(f) for f in facts],
        "inferred": inferred,
        "confidence": confidence,
        "limitations": sorted(limitations or []),
        "next": [_clean_step(step) for step in next_steps or []],
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
    *,
    blind: bool = False,
) -> Verdict:
    """The site verdict, from findings and evaluation gaps.

    Order, worst first: ``critical`` (a critical finding exists), ``unknown``
    (no critical finding, but a rule able to find one did not run over every
    subject, so a critical problem cannot be ruled out), ``degraded`` (a
    warning exists), ``healthy``. Info findings never move the verdict.

    ``blind`` is set when a read failed for a reason other than "this route
    does not exist on this firmware", or a rule crashed. A blind diagnosis
    can still be ``critical`` or ``degraded`` on what it did see, but it is
    never ``healthy``: it becomes ``unknown``.
    """
    severities = {f["severity"] for f in findings}
    if "critical" in severities:
        return "critical"
    if any(g["rule"] in critical_capable for g in gaps):
        return "unknown"
    if "warning" in severities:
        return "degraded"
    return "unknown" if blind else "healthy"
