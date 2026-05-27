# Security Policy

## Reporting a vulnerability

If you find a security issue, please **do not** open a public GitHub issue.
Instead, open a private security advisory on this repository:

https://github.com/pete-builds/mcp-unifi/security/advisories/new

I will respond within 7 days. Please include:

- A description of the issue and its impact
- Steps to reproduce (or a proof-of-concept)
- The version (image tag or commit SHA) you tested against
- Any suggested mitigation, if you have one

## Supported versions

Only the most recent minor release receives security fixes. The current
supported version is whatever is tagged latest on the
[Releases page](https://github.com/pete-builds/mcp-unifi/releases).

## Threat model

mcp-unifi is designed to run on a trusted LAN and talk to a single self-hosted
UniFi gateway. As of v0.9.0, the HTTP transport authenticates every request
with a bearer token (`Authorization: Bearer <token>`); the server refuses to
start without tokens by default. Stdio transport stays unauthenticated by
design — the parent process owns the security boundary. Even with bearer
auth on, treat the network as defence in depth: run on a trusted segment,
behind a Tailscale ACL, etc.

The container:

- Runs as a non-root user (UID 1000), no shell, no home directory
- Uses a read-only root filesystem (with a small `tmpfs` for `/tmp`)
- Drops `no-new-privileges` and runs no capabilities beyond default
- Pins the base image by digest and installs Python deps with `--require-hashes`
- Never logs the API key or WLAN passphrases (a redacting JSON formatter scrubs
  known sensitive keys defensively)
- Does not call out to any cloud service. The only outbound HTTPS connection
  is to the configured `UNIFI_HOST`

The API key is read from the `UNIFI_API_KEY` environment variable and sent in
the `X-API-Key` header on every request to the gateway. It is never written to
disk by this server, never echoed in logs, and never returned in MCP responses.

## What this server does NOT do

- It does not expose any cloud Site Manager / Ubiquiti Account integration.
- It does not store any state between restarts (stub-mode data is in-memory only).
- It does not authenticate MCP clients. Run it on a trusted network or behind a
  reverse proxy with auth.
- It does not auto-update. Pin a specific tag in your `docker-compose.yml`.
