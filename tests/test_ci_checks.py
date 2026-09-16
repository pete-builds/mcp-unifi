from pathlib import Path

from scripts.ci_checks import check_lockfile, scan_text

ROOT = Path(__file__).parents[1]


def test_lockfiles_are_hash_pinned_and_match_direct_requirements() -> None:
    assert check_lockfile(ROOT / "requirements.lock", ROOT / "requirements.in") == []
    assert check_lockfile(ROOT / "requirements-dev.lock", ROOT / "requirements-dev.in") == []


def test_secret_scan_rejects_private_key_fixture_without_echoing_value() -> None:
    value = "-----BEGIN PRIVATE KEY-----fixture-only-value"
    findings = scan_text(value, "negative-fixture")
    assert findings
    assert value not in " ".join(findings)


def test_lock_check_rejects_missing_hash_fixture(tmp_path: Path) -> None:
    lock = tmp_path / "requirements.lock"
    source = tmp_path / "requirements.in"
    lock.write_text("example==1.2.3 \\\n    # no hash\n", encoding="utf-8")
    source.write_text("example==1.2.3\n", encoding="utf-8")
    findings = check_lockfile(lock, source)
    assert findings == [f"{lock}:1: example has no sha256 hash"]
