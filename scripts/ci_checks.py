"""Repository-local CI checks for supply-chain and secret hygiene."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

PACKAGE_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==(\S+) \\s*$")
SOURCE_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==(\S+)")
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(
        r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*['\"][^'\"]{8,}['\"]"
    ),
)


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def check_lockfile(path: Path, source: Path | None = None) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    errors: list[str] = []
    locked: dict[str, str] = {}
    current: tuple[str, int] | None = None
    has_hash = False
    for number, line in enumerate(lines, 1):
        match = PACKAGE_LINE.match(line)
        if match:
            if current and not has_hash:
                errors.append(f"{path}:{current[1]}: {current[0]} has no sha256 hash")
            current = (match.group(1), number)
            has_hash = False
            locked[_normalise(match.group(1))] = match.group(2)
        elif current and line.strip().startswith("--hash=sha256:"):
            digest = line.strip().removeprefix("--hash=sha256:").rstrip(chr(92)).strip()
            has_hash = len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)
    if current and not has_hash:
        errors.append(f"{path}:{current[1]}: {current[0]} has no sha256 hash")
    if source and source.exists():
        for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
            match = SOURCE_LINE.match(line.strip())
            if not match:
                continue
            name, version = match.groups()
            actual = locked.get(_normalise(name))
            if actual is None:
                errors.append(f"{source}:{number}: {name}=={version} is missing from {path}")
            elif actual != version:
                errors.append(
                    f"{source}:{number}: {name}=={version} differs from {path} ({actual})"
                )
    return errors


def scan_text(text: str, label: str = "input") -> list[str]:
    return [
        f"{label}: credential-like material matched pattern {index}"
        for index, pattern in enumerate(SECRET_PATTERNS, 1)
        if pattern.search(text)
    ]


def tracked_secret_scan(root: Path) -> list[str]:
    result = subprocess.run(  # noqa: S603 - fixed git argv, no shell
        ["git", "-C", str(root), "ls-files", "-z"],  # noqa: S607
        check=True,
        capture_output=True,
        text=False,
    )
    paths = [root / item for item in result.stdout.decode().split("\0") if item]
    allowed = {".py", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".env", ".example", ".in", ".lock"}
    findings: list[str] = []
    for path in paths:
        relative = path.relative_to(root)
        if (
            "tests" in relative.parts
            or "docs" in relative.parts
            or "scripts" in relative.parts
            or path.name in {"NOTICE", "LICENSE"}
        ):
            continue
        if path.suffix not in allowed and path.name not in {"Dockerfile", "docker-compose.yml"}:
            continue
        findings.extend(
            scan_text(path.read_text(encoding="utf-8", errors="replace"), str(relative))
        )
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("check", choices=("locks", "secrets"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.check == "locks":
        errors = []
        pairs = (
            ("requirements.lock", "requirements.in"),
            ("requirements-dev.lock", "requirements-dev.in"),
        )
        for lock, source in pairs:
            errors.extend(check_lockfile(root / lock, root / source))
    else:
        errors = tracked_secret_scan(root)
    for error in errors:
        print(f"::error::{error}")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
