# Contributing

Thanks for the interest. `mcp-unifi` is a personal project but PRs are welcome — especially for bug fixes, additional UniFi gateway compatibility (UDM Pro, UXG, etc.), and Protect coverage gaps.

## Before you open a PR

- For non-trivial changes, open an issue first to discuss the approach. Saves both of us time if there's a design constraint you can't see from the outside.
- Every public tool needs a verb-first description with `Side effects:`, `Rollback:` (if composite), `Example:`, and a `dry_run` reference if destructive — see existing tools in `src/mcp_unifi/modules/` for the pattern.
- Every destructive tool needs `dry_run` support and an audit-log entry.
- Composite tools need a property test in `tests/property/` exercising the rollback path.

## Development loop

```bash
# Create + activate a venv (Python 3.13 required)
uv venv && source .venv/bin/activate

# Install with hash-locked deps
uv pip sync requirements-dev.lock
uv pip install -e . --no-deps

# Test suite (380+ tests, ~91% coverage; targets parity per-module)
pytest

# Lint + type-check
ruff check . && ruff format --check . && mypy src/

# Run the server in stub mode against a local Claude
docker compose up --build
```

Stub mode is the default; you do not need a UniFi gateway to develop or run the test suite.

## Reporting bugs / proposing tools

Use the issue templates. For bugs, include the gateway model + firmware (visible in `get_site_health` output) — most UniFi quirks are firmware-version-dependent.

## Scope

Currently in scope: Network module, Protect module, the safety substrate (dry-run, audit, rollback), distribution. **Out of scope** for now: UniFi Access, UniFi Drive, UniFi Talk. Open an issue if you want to discuss adding one of these as a new module.

## License

Contributions are MIT-licensed, same as the rest of the project.
