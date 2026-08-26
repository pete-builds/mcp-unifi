# syntax=docker/dockerfile:1.7

# ---------------------------------------------------------------------------
# Builder stage: compile wheels from the hash-locked requirements.
# ---------------------------------------------------------------------------
# Base image pinned by digest so the base bits are stable across rebuilds.
# The runtime stage layers Debian security upgrades on top, so bit-for-bit
# reproducibility is not guaranteed — see the runtime stage's comment.
# Refresh with:
#   docker pull python:3.13-slim
#   docker inspect python:3.13-slim --format '{{index .RepoDigests 0}}'
# Dependabot keeps it fresh weekly via .github/dependabot.yml.
#
# The TAG must stay 3.13: pyproject.toml (requires-python, mypy python_version,
# ruff target-version), the CI matrix, and requirements*.lock (compiled with
# --python-version 3.13) all target 3.13. Moving the tag alone silently ships a
# runtime that no lockfile or check ever exercised. Retarget all of them
# together or not at all.
#
# This already happened once: a Dependabot *digest* bump carried the tag from
# 3.13 to 3.14 and shipped Python 3.14.7 to production, rewriting these refresh
# lines to say 3.14 on the way through so the drift documented itself as
# intent. A digest is opaque, so the tag beside it gets edited without reading
# as a version change. CI now asserts the built image's Python minor version
# (see the build-image job in .github/workflows/ci.yml), so that failure mode
# is loud rather than silent. If Dependabot proposes a FROM line whose tag is
# not 3.13, close the PR.
FROM python:3.13-slim@sha256:ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a AS builder

WORKDIR /build

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Build minimal wheels into /wheels so the runtime stage can install offline.
COPY requirements.lock ./requirements.lock
RUN pip install --no-cache-dir --require-hashes --target /wheels -r requirements.lock

COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir --target /wheels --no-deps .

# ---------------------------------------------------------------------------
# Runtime stage: slim image with only the installed package + UID 1000 user.
# ---------------------------------------------------------------------------
# Same pin as the builder stage. Keep both stages on the identical tag+digest.
FROM python:3.13-slim@sha256:ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a AS runtime

# Apply Debian security patches on top of the pinned base. This intentionally
# trades bit-for-bit reproducibility for current CVE fixes between base
# rebuilds (libcap2 CVE-2026-4878, libsystemd0/libudev1 CVE-2026-29111, etc).
# Two rebuilds of the same commit may differ if the Debian mirror publishes
# a new security update between them. The Python deps below are still fully
# hash-locked via ``pip --require-hashes``.
#
# The ADD below must stay directly above the RUN. Without it the comment above
# was not true: CI builds with `cache-from: type=gha`, this RUN's cache key is
# only its command string, and that never changes, so buildkit served the layer
# from cache indefinitely and "current CVE fixes" meant whatever was current the
# day the layer was first built. Verified on 2026-08-26 across this fleet: builds
# logged `#11 CACHED` for this step while the image still shipped libssl3t64
# 3.5.6-1~deb13u2, well after 3.5.7-1~deb13u2 (CVE-2026-14456) had landed in
# trixie-security. The Trivy gate then failed with nothing in the repo to change.
#
# trixie-security's Release file changes when and only when a security update is
# published, so keying the layer to it rebuilds exactly when there is something
# to install and stays cached otherwise.
ADD https://deb.debian.org/debian-security/dists/trixie-security/Release /tmp/debian-security-release
RUN apt-get update && apt-get -y upgrade \
    && rm -rf /tmp/debian-security-release /var/lib/apt/lists/*

# MCP Registry ownership-verification label. The value MUST match the
# `name` field in server.json so the registry can verify the publisher
# controls this image. See:
# https://github.com/modelcontextprotocol/registry/blob/main/docs/modelcontextprotocol-io/package-types.mdx
LABEL io.modelcontextprotocol.server.name="io.github.pete-builds/unifi"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/site-packages \
    PATH=/app/site-packages/bin:$PATH

# Non-root user with pinned UID 1000 (no shell, no home).
RUN groupadd --system --gid 1000 mcp \
    && useradd --system --uid 1000 --gid 1000 --no-create-home --shell /usr/sbin/nologin mcp

WORKDIR /app
COPY --from=builder /wheels /app/site-packages
RUN chown -R mcp:mcp /app

# Runtime does not use pip: the wheels above are pre-installed and the entrypoint
# runs `python -m mcp_unifi.server`. Removing pip drops its vendored dependencies
# (msgpack, setuptools, requests, ...), which Trivy scans as if they were
# installed packages and flags for CVEs unreachable from this server.
RUN pip uninstall -y pip

USER mcp

EXPOSE 3714

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s \
    CMD ["python", "-m", "mcp_unifi.healthcheck"]

ENTRYPOINT ["python", "-m", "mcp_unifi.server"]
