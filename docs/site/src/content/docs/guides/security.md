---
draft: false
title: Security Model
description: Threat model, hardening, image signing, and supply-chain provenance.
---

mcp-unifi is designed to run on a trusted home or homelab LAN, behind your existing network boundary. This page covers the threat model, the hardening that's baked into the image, and how to verify the supply chain.

## Threat model

- **Trusted boundary**: starting in v0.9.0, the HTTP transport requires a bearer token on every request (see the [Authentication guide](/mcp-unifi/guides/auth/)). The server refuses to start without tokens by default. Stdio transport remains unauthenticated by design — the parent process owns the security boundary. Even with auth on, run the server inside a trusted LAN segment or behind a Tailscale ACL: defence in depth.
- **Local-network only**: the server talks to your UniFi gateway over the **local API** (X-API-Key header to `https://<gateway>/proxy/network/...`). It does not call out to any Ubiquiti cloud endpoint, does not require a UI account, and does not require Site Manager / Cloud Console enrollment.
- **Self-signed gateway certs**: most home gateways present a self-signed certificate. `UNIFI_VERIFY_SSL` defaults to `false` for that reason. Set it to `true` once you've installed a real certificate.

## Read-only mode

Set `MCP_UNIFI_READONLY=true` and the server becomes structurally incapable of changing anything. Every tool that mutates is dropped from `tools/list` and refused on `tools/call`; read tools behave exactly as before.

Both halves matter. Hiding a tool from the listing only removes the suggestion — a client that hard-codes a tool name, replays a cached manifest, or simply guesses would still reach the tool body. The call-time refusal is the control; the listing filter is what keeps a model from trying in the first place. The refusal is the standard `{"error": ..., "stub_mode": ...}` envelope every other tool failure uses, so no caller needs a second error path.

This is **defense in depth on top of a read-only UniFi API key**, not a substitute. Give the server a read-only key and the controller refuses writes; add this setting and the server never attempts one. Use both. Reach for the flag when the server is exposed to an agent you are still evaluating, during an audit or incident review where nothing should change, or on a second instance you keep pointed at production for reads while a separate instance holds write credentials.

### How tools are classified

Each tool declares its own classification at registration:

```python
@mcp.tool()
@audited("list_networks", mutates=False)
async def list_networks(...) -> str: ...
```

`mutates` is a required argument, and registration fails if a tool has not declared it — the server refuses to start rather than let an unclassified tool default into being callable. A test enumerates every registered tool and fails CI on the same condition, so a tool added later cannot silently slip through.

Classification is deliberately **not** derived from tool names. Twelve mutating tools carry none of the write-shaped prefixes a name-based gate would match:

`confirm_destructive_action`, `restore_config`, `block_client`, `unblock_client`, `quarantine_client`, `reconnect_client`, `restart_device`, `rename_device`, `locate_device`, `toggle_traffic_rule`, `toggle_traffic_route`, `trigger_speedtest`

The first is the reason the shortcut is unusable: `confirm_destructive_action` is the tool that *executes* a queued delete. A prefix-matching gate would ship a "read-only" server that still commits deletions.

Judgment calls, recorded so they are not re-litigated:

- **`trigger_speedtest` mutates.** It changes no configuration, but it makes the gateway saturate the WAN for 30-60 seconds on demand. Read-only has to mean the server cannot make the hardware do work, not just that it cannot edit config. `get_speedtest_results` stays available.
- **`locate_device` mutates.** It flashes a physical LED until something turns it off. Changing what the hardware is doing in the room is not a read.
- **`rename_device` mutates.** Cosmetic, but persisted, and it is the label every other tool's output shows.
- **`backup_config` is a read.** It is a fan-out of GETs returned to the caller; it writes nothing to the controller. Taking a backup is exactly what you want to still be able to do in read-only mode.
- **`get_console_health` and `get_console_firmware` are reads** even though the console path may POST a login. Authenticating is how the server reads UniFi OS at all, and `get_console_health` is the one tool that still answers when the Network application is down.
- **Every `delete_*` tool mutates**, including its preview phase. Preview-then-confirm is an interlock against mistakes, not an access control.

## Secret handling

- `UNIFI_API_KEY` and all per-controller `api_key` values are wrapped in Pydantic's `SecretStr`. Reading the cleartext requires `.get_secret_value()`; `repr()` and structured logging never echo the raw key.
- The startup `safe_repr()` log line includes only an `api_key_set: true/false` boolean per controller, never the key itself.
- One canonical pattern list (`mcp_unifi.redaction.SENSITIVE_KEY_PATTERNS`) covers three emitters: the structured logger, the audit log, and tool responses. It matches `api_key`, `passphrase`/`x_passphrase`, `password`/`x_password`, `secret`, `token`, `psk`, `pre_shared_key`/`preshared_key`, and `private_key`/`privkey`.
- Read paths that return controller records replace those values with `[REDACTED]` before the response leaves the server, in stub mode and real mode alike: WLANs (`x_passphrase`), networks (WireGuard `x_private_key`/`x_preshared_key`, site-to-site `x_ipsec_pre_shared_key`, RADIUS `x_secret`), dynamic DNS (`x_password`), the guest portal, Teleport, and Access credentials. `backup_config` substitutes its own `<redacted-on-backup>` sentinel so `restore_config` can recognise it and force the restored resource to `enabled=false`.
- References are deliberately **not** redacted. `radiusprofile_id` names a profile; it is not the shared secret, and redacting it would break the tools that resolve it.
- The audit log applies the same scrub to tool kwargs before writing.

## Container-level hardening (baked into the image)

The published image (`ghcr.io/pete-builds/mcp-unifi`) contributes:

- **Non-root**: runs as **UID 1000**, no shell, no home directory.
- **Hash-pinned deps**: Python dependencies installed with `pip --require-hashes` from a hash-locked `requirements.lock`. The base image is pinned by digest.
- **Trivy scan**: CI fails the build on any HIGH or CRITICAL vulnerability finding. Current status: zero findings.
- **Multi-arch**: `linux/amd64` and `linux/arm64` from one release.

## Runtime hardening (applied by Compose or Helm)

The following protections come from the runtime configuration, not the image itself. A plain `docker run` without these flags does **not** apply them — replicate them yourself if you deploy that way:

- **Read-only root filesystem**: `read_only: true` in compose / `securityContext.readOnlyRootFilesystem: true` in Helm. `/tmp` is `tmpfs` for ephemeral writes (audit log, runtime caches).
- **`no-new-privileges`**: `security_opt: no-new-privileges:true` in compose / `securityContext.allowPrivilegeEscalation: false` in Helm. Prevents setuid escalation paths.
- **Capabilities dropped**: `securityContext.capabilities.drop: [ALL]` in Helm; add `cap_drop: [ALL]` in compose for the same posture.
- **NetworkPolicy** (Kubernetes): the chart ships an optional `NetworkPolicy` template so operators can pin ingress and egress explicitly.

## Supply-chain provenance

### cosign keyless signature

Every published image is signed via [cosign](https://docs.sigstore.dev/cosign/overview/) keyless OIDC. The signing identity is the GitHub Actions workflow that built the image; verification confirms the image came from that workflow on this repo, not from someone with a stolen GHCR token.

```bash
cosign verify ghcr.io/pete-builds/mcp-unifi:latest \
  --certificate-identity-regexp 'https://github.com/pete-builds/mcp-unifi' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

A successful verification prints the signature payload (certificate subject, issuer, GitHub workflow ref). Failure means the tag does not have a valid signature from this repo.

### SBOM

Each release attaches a CycloneDX SBOM generated by [Syft](https://github.com/anchore/syft):

```bash
# Download from the GitHub release assets
curl -L -o sbom.cdx.json \
  https://github.com/pete-builds/mcp-unifi/releases/download/v0.5.0-rc.2/sbom.cdx.json
```

The SBOM lists every Python package, OS package, and file digest baked into the image. Useful for vulnerability scanning, license auditing, or comparing across releases.

### Provenance attestation

The release workflow uses `docker/build-push-action` with `provenance: true`, attaching a build attestation to each image. Inspect it with:

```bash
docker buildx imagetools inspect \
  ghcr.io/pete-builds/mcp-unifi:latest \
  --format '{{ json .Provenance }}'
```

## What's intentionally not in scope

- **No per-tool RBAC.** Per-**module** scoping is supported (`client_id:token:module1|module2` in `MCP_UNIFI_AUTH_TOKENS`; see the [Authentication guide](/mcp-unifi/guides/auth/)) so a client can be restricted to Network, Protect, or Access. Finer per-tool scopes are a v1.x decision.
- **No token rotation API.** Rotate by editing `MCP_UNIFI_AUTH_TOKENS` and restarting.
- **No rate limiting.**
- **No remote-control of the audit log.** The log is local. Ship it to your SIEM with whatever you already use (Fluent Bit, syslog forwarder, etc).
- **No tenant isolation.** One server instance = one tenant. Multi-tenant SaaS deployment is a post-v1.0 question.

For vulnerability reports, see [SECURITY.md](https://github.com/pete-builds/mcp-unifi/blob/main/SECURITY.md).
