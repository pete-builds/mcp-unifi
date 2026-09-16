# CI quality and supply-chain gates

Pull requests and pushes to `main` run required checks in `.github/workflows/ci.yml`.
The jobs are split so failures identify the boundary needing attention:

- Lockfile drift recompiles declared inputs with the pinned fleet workflow.
- Supply-chain integrity installs hash-pinned dependencies, verifies every direct
  pin and artifact hash, scans tracked source/deployment inputs for high-confidence
  credential material, and checks generated tool/capability manifests.
- Lint + Type Check runs Ruff lint/security rules, format checking, and strict mypy.
- Tests + Coverage runs pytest and fails below the 80% branch-aware threshold.
- Build image + Trivy scan builds without publishing and blocks HIGH or CRITICAL
  filesystem and image findings (unfixed findings follow the explicit policy).

Local equivalents:

    python scripts/ci_checks.py locks
    python scripts/ci_checks.py secrets
    uv run python scripts/generate_tool_manifest.py --check
    uv run ruff check src tests evals
    uv run ruff format --check src tests evals
    uv run mypy src/mcp_unifi evals
    uv run pytest --cov-report=term --cov-report=xml --cov-fail-under=80
    docker build --tag mcp-unifi:ci .
    trivy fs --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 .
    trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 mcp-unifi:ci

The negative fixtures in `tests/test_ci_checks.py` prove secret and lock checks
fail closed without returning the fixture value in diagnostics. CI scans the
authoritative checkout and does not add a real secret fixture. No CI job publishes
an image or receives production credentials. High/critical exceptions require an
owner, expiry, and written approval; none are configured by this repository.
