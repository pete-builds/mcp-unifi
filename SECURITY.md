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

mcp-unifi is designed to run on a trusted LAN and talk to a self-hosted UniFi
gateway. Even with the transport-layer bearer auth described below, treat the
network as defence in depth: run on a trusted segment, behind a Tailscale ACL,
etc.

## MCP client authentication

Behavior depends on transport:

- **Streamable HTTP transport** (Docker, Helm, standalone HTTP): every MCP
  request is authenticated with a bearer token (`Authorization: Bearer
  <token>`). The server refuses to start with the HTTP transport unless
  `MCP_UNIFI_AUTH_TOKENS` is set (default `MCP_UNIFI_AUTH_REQUIRED=true`).
  Auth can be disabled with `MCP_UNIFI_AUTH_REQUIRED=false` — only appropriate
  for loopback-bound single-host deployments. See the
  [Authentication guide](https://pete-builds.github.io/mcp-unifi/guides/auth/)
  for setup and audit-log integration.
- **Stdio transport** (`.dxt`, `uvx`, `pipx`): unauthenticated by design. The
  parent process (Claude Desktop, Claude Code) owns the security boundary;
  adding transport auth on top would be theatre.

## Secret handling

- `UNIFI_API_KEY` and every per-controller `api_key` value are wrapped in
  Pydantic's `SecretStr`. Reading the cleartext requires `.get_secret_value()`;
  `repr()` and structured logging never echo the raw key.
- The API key is sent in the `X-API-Key` header on every request to the
  gateway. It is never written to disk by this server, never echoed in logs,
  and never returned in MCP responses.
- One canonical pattern list (`mcp_unifi.redaction.SENSITIVE_KEY_PATTERNS`)
  covers three emitters: the structured logger, the audit log, and tool
  responses. It matches `api_key` and the `X-API-Key` header spelling,
  `passphrase`/`x_passphrase`,
  `password`/`passwd`/`x_password`, `secret`, `token`, `psk`,
  `pre_shared_key`/`preshared_key`, `private_key`/`privkey`, the device
  management and mesh keys `authkey`/`vwirekey`, and the Access visitor
  `pass_code`/`passcode`.
- The structured logger scrubs those keys from any log record, and the audit
  log applies the same scrub to tool kwargs and results before writing.
- Read paths that return controller records redact those values to
  `[REDACTED]` before the response leaves the server: WLANs, networks
  (WireGuard, site-to-site IPsec, and RADIUS key material), devices
  (`x_authkey`, `x_vwirekey`) and the device-stats views built from them,
  dynamic DNS, the guest portal, Teleport, Access credentials, and Access
  visitor passes. `backup_config` substitutes the `<redacted-on-backup>`
  sentinel instead, which `restore_config` recognises and answers by forcing
  the restored resource to `enabled=false`.
- Write paths redact too, on both the `dry_run` preview that echoes the
  caller's payload and the record the controller echoes back: `create_wlan`,
  `update_wlan`, `create_iot_network`, and `create_guest_network`. The
  composites also redact the `partial` record surfaced when a multi-step
  provision rolls back.
- References are deliberately **not** redacted: `radiusprofile_id` names a
  profile rather than holding its secret, `setting_key` names a settings
  section, and a WireGuard `public_key` is meant to be shared. Redacting any
  of them would break the tools and callers that use them. That is why the
  list holds `authkey` rather than `auth`, and two exact `pass_code`
  spellings rather than `code`.

## Container-level hardening

The published image (`ghcr.io/pete-builds/mcp-unifi`) contributes:

- Runs as a **non-root user (UID 1000)** with **no shell** and **no home
  directory** (baked into the Dockerfile).
- **Base image pinned by digest**. Debian security upgrades are applied on
  top of the pinned base at build time.
- Python dependencies installed with **`pip --require-hashes`** from a
  hash-locked `requirements.lock`.
- **cosign keyless OIDC signature** on every published image; **CycloneDX
  SBOM** attached to every release; **SLSA build provenance** attested via
  `docker/build-push-action`.
- **`io.modelcontextprotocol.server.name`** label so the MCP Registry can
  verify the publisher controls the image.

## Runtime hardening (applied by Compose or Helm — not `docker run`)

The following protections come from the runtime configuration in
`docker-compose.example.yml`, `docker-compose.yml`, and the Helm chart. A
plain `docker run` without those flags does **not** apply them:

- **Read-only root filesystem** (`read_only: true` / Helm
  `securityContext.readOnlyRootFilesystem: true`), with a small `tmpfs` for
  `/tmp` (16 MiB in the compose example).
- **`no-new-privileges`** set on the container (`security_opt:
  no-new-privileges:true` / Helm `securityContext.allowPrivilegeEscalation:
  false`).
- **All Linux capabilities dropped** in Helm
  (`securityContext.capabilities.drop: [ALL]`). The Docker compose examples
  rely on the default cap set plus `no-new-privileges`; drop caps explicitly
  with `cap_drop: [ALL]` if you want the same posture there.

If you deploy with a bare `docker run`, replicate these flags yourself.

## Network posture

- The server does not call out to any cloud service. The only outbound HTTPS
  connections are to the configured `UNIFI_HOST` (and `UNIFI_ACCESS_HOST`
  when the Access module is enabled).
- The Helm chart ships an optional `NetworkPolicy` template
  (`networkPolicy.enabled: true`) so cluster operators can pin ingress and
  egress explicitly.

## What this server does NOT do

- It does not expose any cloud Site Manager / Ubiquiti Account integration.
- It does not store any state between restarts (stub-mode data is in-memory
  only; audit log is append-only on disk when `MCP_UNIFI_AUDIT_SINK=file`).
- It does not implement per-tool RBAC. Per-**module** scoping is supported
  via the `client_id:token:module1|module2` token form (see the
  [Authentication guide](https://pete-builds.github.io/mcp-unifi/guides/auth/)),
  so a client can be restricted to Network / Protect / Access. Finer per-tool
  scopes are a v1.x decision.
- It does not implement rate limiting or a token-rotation API. Rotate by
  editing `MCP_UNIFI_AUTH_TOKENS` and restarting.
- It does not auto-update. Pin a specific tag in your `docker-compose.yml`
  or Helm `image.tag`.
