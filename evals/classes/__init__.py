"""The three eval classes. Each module exposes one ``run_*`` coroutine."""

from __future__ import annotations

from pathlib import Path

import yaml

CASES_DIR = Path(__file__).resolve().parent.parent / "cases"


def load_cases(name: str) -> list[dict[str, object]]:
    """Load ``evals/cases/<name>.yaml`` as a list of case dicts."""
    raw = yaml.safe_load((CASES_DIR / f"{name}.yaml").read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise TypeError(f"{name}.yaml must be a list of cases, got {type(raw).__name__}")
    return [dict(case) for case in raw]


__all__ = ["CASES_DIR", "load_cases"]
