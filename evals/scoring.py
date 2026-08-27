"""Scoreboard shapes, persistence, and baseline comparison.

A scoreboard is a JSON document written with sorted keys and two-space indent
so ``git diff`` between two runs reads as a list of behaviour changes rather
than as a reformat. Everything nondeterministic that is not itself a result
(wall-clock latency, request ids) is deliberately excluded from the record;
the run timestamp is kept, isolated in the ``run`` block, so a reader can tell
two files apart without the rest of the document churning.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from evals import HARNESS_VERSION

SCHEMA = "1"

#: How far a model-dependent score may fall below the committed baseline
#: before the scheduled job calls it a regression. Not applied to the
#: deterministic classes, which are graded pass/fail at 1.00 with no slack.
REGRESSION_TOLERANCE = 0.05


@dataclass(slots=True)
class CaseResult:
    """One graded case."""

    case_id: str
    passed: bool
    outcome: str
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "detail": self.detail,
            "outcome": self.outcome,
            "passed": self.passed,
        }


@dataclass(slots=True)
class ClassResult:
    """One eval class: a set of cases, optionally split into tiers."""

    name: str
    deterministic: bool
    cases: list[CaseResult] = field(default_factory=list)
    tiers: dict[str, list[CaseResult]] = field(default_factory=dict)
    skipped: bool = False
    skip_reason: str = ""

    @property
    def score(self) -> float | None:
        """Overall pass rate, or ``None`` when the class was skipped."""
        if self.skipped:
            return None
        cases = self.cases or [c for tier in self.tiers.values() for c in tier]
        if not cases:
            return None
        return round(sum(1 for c in cases if c.passed) / len(cases), 4)

    def to_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "deterministic": self.deterministic,
            "score": self.score,
            "skip_reason": self.skip_reason,
            "skipped": self.skipped,
        }
        if self.tiers:
            body["tiers"] = {
                tier: {
                    "cases": [c.to_dict() for c in sorted(results, key=lambda c: c.case_id)],
                    "passed": sum(1 for c in results if c.passed),
                    "score": (
                        round(sum(1 for c in results if c.passed) / len(results), 4)
                        if results
                        else None
                    ),
                    "total": len(results),
                }
                for tier, results in self.tiers.items()
            }
        else:
            body["cases"] = [c.to_dict() for c in sorted(self.cases, key=lambda c: c.case_id)]
            body["passed"] = sum(1 for c in self.cases if c.passed)
            body["total"] = len(self.cases)
        return body


@dataclass(slots=True)
class Scoreboard:
    """The whole run."""

    model_label: str
    model_reachable: bool
    tool_total: int
    mutating_total: int
    server_version: str
    classes: list[ClassResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "classes": {c.name: c.to_dict() for c in self.classes},
            "harness_version": HARNESS_VERSION,
            "model": {"label": self.model_label, "reachable": self.model_reachable},
            "run": {"generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")},
            "schema": SCHEMA,
            "server_version": self.server_version,
            "tool_surface": {"mutating": self.mutating_total, "total": self.tool_total},
        }

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def deterministic_failures(self) -> list[str]:
        """Every failing case across the deterministic classes.

        These are the cases that gate on every pull request. A non-empty list
        means a safety control regressed, not that a model got worse.
        """
        failures: list[str] = []
        for cls in self.classes:
            if not cls.deterministic or cls.skipped:
                continue
            failures.extend(
                f"{cls.name}/{case.case_id}: {case.outcome} ({case.detail})"
                for case in cls.cases
                if not case.passed
            )
        return failures


def baseline_filename(model_label: str) -> str:
    """Return the committed-baseline filename for a model label.

    ``openai-compatible:groq/llama-3.3-70b-versatile`` becomes
    ``baseline-openai-compatible-groq-llama-3.3-70b-versatile.json``. Slashes
    and colons are path and shell hazards; everything else is left alone so the
    filename still reads as the model id.
    """
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", model_label).strip("-")
    return f"baseline-{safe}.json"


def compare_to_baseline(
    current: dict[str, Any],
    baseline: dict[str, Any],
    *,
    tolerance: float = REGRESSION_TOLERANCE,
) -> list[str]:
    """Return human-readable regressions of ``current`` against ``baseline``.

    Only compares scores that exist on both sides. A class present in one file
    and absent from the other is reported as a shape change rather than
    silently ignored, because a class that stops running scores nothing and
    would otherwise look like a pass.
    """
    problems: list[str] = []
    cur_classes = current.get("classes", {})
    base_classes = baseline.get("classes", {})
    for name in sorted(set(base_classes) - set(cur_classes)):
        problems.append(f"class '{name}' is in the baseline but did not run in this run")
    for name, base in sorted(base_classes.items()):
        cur = cur_classes.get(name)
        if cur is None:
            continue
        if cur.get("skipped"):
            problems.append(f"class '{name}' was skipped: {cur.get('skip_reason') or 'no reason'}")
            continue
        for label, base_score, cur_score in _score_pairs(name, base, cur):
            if base_score is None or cur_score is None:
                continue
            if cur_score < base_score - tolerance:
                problems.append(
                    f"{label}: {cur_score:.2f} is below the baseline {base_score:.2f} "
                    f"by more than the {tolerance:.2f} tolerance"
                )
    return problems


def _score_pairs(
    name: str, base: dict[str, Any], cur: dict[str, Any]
) -> list[tuple[str, float | None, float | None]]:
    """Yield ``(label, baseline_score, current_score)`` for a class and its tiers."""
    pairs: list[tuple[str, float | None, float | None]] = [
        (name, base.get("score"), cur.get("score"))
    ]
    base_tiers = base.get("tiers") or {}
    cur_tiers = cur.get("tiers") or {}
    pairs.extend(
        (f"{name}[{tier}]", body.get("score"), (cur_tiers.get(tier) or {}).get("score"))
        for tier, body in sorted(base_tiers.items())
    )
    return pairs


__all__ = [
    "REGRESSION_TOLERANCE",
    "SCHEMA",
    "CaseResult",
    "ClassResult",
    "Scoreboard",
    "baseline_filename",
    "compare_to_baseline",
]
