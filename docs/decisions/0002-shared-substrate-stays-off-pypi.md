# 0002. Keep the shared MCP substrate off PyPI

**Status:** Accepted (fleet-level decision, 2026-08-12)

## Context

Several MCP servers in this fleet need the same plumbing: settings loading, a
standard error envelope, structured logging with secret redaction, an audit sink.
`pete-mcp-core` was extracted to hold that substrate.

Three servers consume it: `mcp-searxng`, `mcp-spotify`, and `mcp-threatintel`. All
three are the same author's, all three deploy as GHCR images pulled onto one host.
Each declared `pete-mcp-core>=0.1.0` in its `pyproject.toml`, which meant install
resolved against PyPI, where the package does not exist. Their CI was red for over
a week for that reason alone.

## Decision

`pete-mcp-core` is **not published to PyPI**. Consumers depend on it through a PEP
508 direct reference to an immutable commit tarball:

```
pete-mcp-core @ https://github.com/pete-builds/pete-mcp-core/archive/<sha>.tar.gz
```

Publishing to PyPI claims a permanent global name and immutable version filenames
in a public registry, in order to buy version resolution that three private
consumers on one host do not need.

**This repository is not one of the three consumers.** `mcp-unifi` declares no
dependency on `pete-mcp-core` and carries its own substrate: `config.py`,
`audit.py`, `redaction.py`, `logging_setup.py`, `responses.py`. Whether that was a
deliberate decision or simply the order things were built in is not recorded
anywhere this record's author could verify. What is verifiable is the current
state: no reference to `pete-mcp-core` exists anywhere in this repo. The record
lives here because the same reasoning governs any future move of this repo's
substrate into the shared package.

## Alternatives considered

**Publish to PyPI.** Rejected. The release workflow actually ran on 2026-08-09 and
got as far as the publish job before failing with `invalid-publisher`: the trusted
publisher had never been created, and creating one requires a pypi.org login. So
the cost is not only the name claim, it is also a manual credential step outside
CI. The benefit purchased is version-range resolution across three repos with one
owner, which is not a problem those repos have.

**`git+https://` dependency URLs.** Rejected on packaging mechanics rather than
policy. pip installs a plain tarball with no `git` binary present, but a
`git+https` reference needs one. Using tarballs kept the `python:3.13-slim` runtime
images unchanged. This mattered most in `mcp-spotify`, whose Dockerfile is single
stage, where `git` would have shipped in the runtime layer.

**A private package index.** Rejected as more infrastructure to run, monitor, and
secure than the dependency it would serve.

**Vendoring the substrate into each consumer.** This is effectively what
`mcp-unifi` does today. It removes the dependency question entirely and costs
divergence: a fix to redaction has to be made in each copy, and the copies drift.
Acceptable for one repo, not as a fleet strategy.

## Consequences and accepted costs

- **Dependabot cannot see through a SHA pin.** A direct reference to a commit
  tarball is opaque to it. When `pete-mcp-core` changes, the SHA has to be bumped
  by hand in all three dependent repos. Nothing will open a PR to remind anyone.
  This is the accepted cost and it is the whole cost.
- Consumers need `[tool.hatch.metadata] allow-direct-references = true`, because
  hatchling rejects direct references otherwise. That line has to be explained to
  anyone reading those `pyproject.toml` files.
- A `v0.1.0` tag exists on `pete-mcp-core`, points at a commit behind `main`, and
  is inert. Nothing was ever published under it. Re-pushing it re-fires the release
  workflow into the same red run.
- Anyone outside this fleet who wants the substrate has to install from a GitHub
  URL rather than `pip install pete-mcp-core`.

## Reversal condition

Publish to PyPI when **a consumer exists that is not the author's own**, or when
the servers stop being deployed as pinned GHCR images and start being installed as
libraries by someone who needs version ranges. Either one turns "versioning nobody
needs" into versioning someone needs.

A second, weaker trigger: if manual SHA bumps across three repos are ever missed
long enough that a security fix in the substrate sits undeployed, the Dependabot
blindness has become the more expensive side of the trade and the decision should
be re-costed.

Until then this is the standing answer, not a stopgap.
