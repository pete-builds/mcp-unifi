# Baseline verification record

This record applies to the pinned revision documented in `UPSTREAM.md`:
`97f057c42d02b127739e33689c1700dcf853e810` (version `0.24.0`). It is a
record of the T001 preflight and is not evidence of a deployment.

## Checkout and toolchain

- Repository: `TaltosLabs/taltos-unifi-mcp` private fork
- Working tree before this scaffold: clean
- Python: `3.13.5`
- Development install: PASS (editable install completed)
- Source layout: `src/mcp_unifi`
- Test layout: `tests/` with Network, Protect, and Access suites

## Checks

- Tool manifest check: PASS
- Ruff lint: PASS
- Mypy strict: PASS (62 source files)
- Pytest: PASS — 1,240 passed, 2 warnings, exit 0
- Ruff format check: FAIL — 10 generated documentation tool examples under
  `docs/site/src/content/docs/tools/`
- Secret scan: PASS — no real secret fixture was introduced or found in the
  repository safety review; test-only sentinel values remain test data

The formatting failure is inherited generated-document drift from the pinned
baseline. T001 recorded it without changing generated files. It is retained as
an explicit follow-on review item rather than silently reformatted in this
attribution task.

## Scope and limitations

The checks above exercise the recorded checkout and local test configuration;
they do not prove controller connectivity, a production deployment, or the
security of external dependencies. No live UniFi credentials were used. No
functional source code or write behavior was changed by this scaffold.
