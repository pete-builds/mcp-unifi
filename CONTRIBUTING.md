# Contributing

Thanks for the interest. `mcp-unifi` is a personal project but PRs are welcome — especially for bug fixes, additional UniFi gateway compatibility (UDM Pro, UXG, etc.), and Protect coverage gaps.

## Before you open a PR

- For non-trivial changes, open an issue first to discuss the approach. Saves both of us time if there's a design constraint you can't see from the outside.
- Every public tool needs a verb-first description with `Side effects:`, `Rollback:` (if composite), `Example:`, and a `dry_run` reference if destructive — see existing tools in `src/mcp_unifi/modules/` for the pattern.
- Every destructive tool needs `dry_run` support and an audit-log entry.
- Composite tools need a property test in `tests/property/` exercising the rollback path.

## Development loop

```bash
# Create + activate a venv (Python 3.13+ required)
uv venv && source .venv/bin/activate

# Install with hash-locked deps
uv pip sync requirements-dev.lock
uv pip install -e . --no-deps

# Test suite (currently ~880 tests; run `pytest --collect-only` for the exact
# count). Coverage is gated at 80% branch coverage in CI.
pytest

# Lint + type-check
ruff check . && ruff format --check . && mypy src/

# Run the server in stub mode against a local Claude
docker compose up --build
```

Stub mode is the default; you do not need a UniFi gateway to develop or run the test suite.

## Reporting bugs / proposing tools

Use the issue templates. For bugs, include the gateway model + firmware (visible in `get_site_health` output) — most UniFi quirks are firmware-version-dependent.

## Release procedure

`release.yml` refers you here, so here it is.

A release is cut by pushing a `v*.*.*` tag. Before that tag exists, **every
version surface must already say the new version in a merged commit**. The
release workflow verifies all seven and fails closed if any disagree, because
tags v0.10.0 through v0.16.0 shipped misreporting their own version when the
bump happened inside the runner instead.

The surfaces, all bumped together:

| Surface | Field |
| --- | --- |
| `pyproject.toml` | `version` |
| `src/mcp_unifi/__init__.py` | `__version__` |
| `manifest.json` | `version` |
| `server.json` | `version` **and** `packages[0].identifier` (the `ghcr.io/…:X.Y.Z` pin) |
| `docker-compose.yml` | the `image:` tag |
| `charts/mcp-unifi/Chart.yaml` | `appVersion` |

Plus one the workflow does *not* check: `charts/mcp-unifi/Chart.yaml`
`version`, the chart's own semver. chart-releaser runs with
`CR_SKIP_EXISTING: "true"`, so leaving it alone means the chart silently is
not republished. Bump it whenever the chart or the app version changes.

`CHANGELOG.md` needs a literal `## [X.Y.Z] - YYYY-MM-DD` heading. The workflow
extracts that section verbatim as the GitHub release body and aborts if it is
missing or empty, so rename `## [Unreleased]` rather than adding a heading
beneath it.

Steps:

```bash
git checkout -b release/X.Y.Z
# bump the surfaces above; rename the Unreleased heading
git commit -am "release: X.Y.Z"
# open the PR, let CI go green, merge it
git checkout main && git pull
git tag vX.Y.Z && git push origin vX.Y.Z
```

The tag fans out to three workflows: `release.yml` (multi-arch build, cosign
keyless signature, SLSA provenance, SBOM, `.dxt` bundle, GitHub release),
`helm-release.yml`, and `publish-mcp.yml` (MCP Registry, which polls GHCR for
up to 30 minutes waiting on the image the release build is still producing).

## Scope

Currently in scope: Network module, Protect module, Access module (read-only — writes deferred until session-token auth lands), the safety substrate (dry-run, audit, rollback), and distribution. **Out of scope** for now: UniFi Drive, UniFi Talk. Open an issue if you want to discuss adding one of these as a new module.

## License

Contributions are MIT-licensed, same as the rest of the project.
