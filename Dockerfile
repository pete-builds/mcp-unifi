# syntax=docker/dockerfile:1.7

# ---------------------------------------------------------------------------
# Builder stage: compile wheels from the hash-locked requirements.
# ---------------------------------------------------------------------------
# Base image pinned by digest so the base bits are stable across rebuilds.
# The runtime stage layers Debian security upgrades on top, so bit-for-bit
# reproducibility is not guaranteed — see the runtime stage's comment.
# Refresh with:
#   docker pull python:3.14-slim
#   docker inspect python:3.14-slim --format '{{index .RepoDigests 0}}'
# Dependabot keeps it fresh weekly via .github/dependabot.yml.
FROM python:3.14-slim@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6 AS builder

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
FROM python:3.14-slim@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6 AS runtime

# Apply Debian security patches on top of the pinned base. This intentionally
# trades bit-for-bit reproducibility for current CVE fixes between base
# rebuilds (libcap2 CVE-2026-4878, libsystemd0/libudev1 CVE-2026-29111, etc).
# Two rebuilds of the same commit may differ if the Debian mirror publishes
# a new security update between them. The Python deps below are still fully
# hash-locked via ``pip --require-hashes``.
RUN apt-get update && apt-get -y upgrade && rm -rf /var/lib/apt/lists/*

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

USER mcp

EXPOSE 3714

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s \
    CMD ["python", "-m", "mcp_unifi.healthcheck"]

ENTRYPOINT ["python", "-m", "mcp_unifi.server"]
