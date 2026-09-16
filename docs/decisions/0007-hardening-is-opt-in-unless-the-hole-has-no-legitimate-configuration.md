# 0007. Hardening that narrows a working install is opt-in; hardening that closes a hole with no legitimate configuration is mandatory

**Status:** Accepted. The line is already implemented across six surfaces of the
code; this record names it. The application to PR #154 below is a design
decision, not shipped code, and is marked as such.

## Context

Six security-relevant defaults and requirements already exist in this server.
Each was decided on its own, in its own release, and the reasoning for each was
consistent with the others without anyone stating the rule they shared:

| Surface | Where | Default | Release |
|---|---|---|---|
| `stub_mode` | `src/mcp_unifi/config.py:115` | `True`: the server talks to no real gateway until told to | since 0.1 |
| `readonly` | `src/mcp_unifi/config.py:126` | `False`: "existing deployments are unaffected" | 0.21.0 |
| `verify_ssl` | `src/mcp_unifi/config.py:60`, `:203` | `False`, per [ADR 0003](0003-verify-ssl-defaults-off.md) | 0.20.0 |
| `protect_api` | `src/mcp_unifi/config.py:61`, `:204` | `internal`: "for backward compatibility" | 0.24.0 |
| `mutates=` on `@audited()` | [ADR 0001](0001-explicit-write-classification.md) | **no default; the server refuses to start** | 0.21.0 |
| `auth_required` | `src/mcp_unifi/config.py:285`, `src/mcp_unifi/server.py:224` | **`True`: an HTTP listener with no tokens refuses to start** | 0.19 |

Four are opt-in. Two are mandatory and fail closed. Both mandatory ones carry an
explicit escape hatch: `MCP_UNIFI_AUTH_REQUIRED=false` logs a warning naming the
exposure, and stdio transport returns no auth provider at all because the parent
process owns that boundary.

Two external forks have now proposed making the hardened shape mandatory.
`adibirzu/mcp-unifi` flipped `verify_ssl` to `true` in August 2026, and ADR 0003
records why that was declined while two of the same fork's three findings were
accepted. On 2026-09-16, PR #154 from Taltos GmbH (`@Taltos-ch`) proposed a
`validate_runtime()` that in real mode rejects any controller without
`api_key_file`, any controller with `verify_ssl` not `True`, any UniFi OS
username/password, and any HTTP transport without `MCP_UNIFI_AUTH_TOKEN_FILE`
and `MCP_UNIFI_CLIENT_ID`. The shipped `docker-compose.yml` and README pass
every one of those as environment variables, and #154 changes neither, so every
documented real-mode deployment would fail at startup with no migration path.

The second fork made the question general. Answering it per-flag again would
mean answering it a third time for the next fork.

## Decision

**A hardening control is opt-in when a real, working deployment exists whose
configuration it would reject, and that configuration is defensible in its own
threat model. It is mandatory, and fails closed, when no such configuration
exists.**

The test is asked of the deployment, not of the control. "Is TLS verification
better?" is always yes and decides nothing. "Does a working deployment exist
that this rejects, and is it defensible?" decides it:

- A self-signed console on a home LAN, reached by IP, with the API key in an
  environment variable: working, documented, and defensible on a trusted
  broadcast domain. So `verify_ssl`, file-backed secrets, and file-backed bearer
  tokens are **opt-in**.
- An HTTP listener with no bearer token, reachable by anything on the network,
  fronting controller writes: no threat model makes that defensible beyond a
  single host, and that single case has its own explicit, logged opt-out. So
  `auth_required` is **mandatory**.
- A tool registered without saying whether it writes: there is no deployment
  that legitimately wants an unclassified tool, so `mutates=` is **mandatory**.

Two corollaries the existing code already follows:

1. **Opt-in shapes carry hardened defaults inside them.** Opting into the
   hardened path should not require opting into each of its parts. #154's own
   `_default_tls_policy` is the correct model: when `api_key_file` is set,
   `verify_ssl` defaults to `True`. That validator is adopted as the design for
   the opt-in path. It is the separate hard rejection in `validate_runtime()`,
   twenty lines below it, that fails the test above, and it contradicts the
   good default sitting next to it.
2. **A mandatory control's escape hatch is explicit, named in the error, and
   logged when used.** `auth_required` does this today. A silent fallback is
   not an escape hatch; ADR 0003 rejects that shape outright.

### Applied to #154 (design, not implemented)

| #154 mandate | Verdict | Reason |
|---|---|---|
| `api_key_file` required per controller | Opt-in | Environment variables are the documented, working configuration. Add `api_key_file` as a supported alternative. |
| `MCP_UNIFI_AUTH_TOKEN_FILE` + `MCP_UNIFI_CLIENT_ID` required on HTTP | Opt-in | Same. `MCP_UNIFI_AUTH_TOKENS` keeps working; the file form is added alongside. |
| `verify_ssl` must be `True` | Opt-in, per ADR 0003 | Adopt `_default_tls_policy`; drop the hard raise. |
| Reject `os_username` / `os_password` | **Not hardening** | It removes the console-session tools with no replacement. A regression carrying a security label. File-backed console credentials, which #154's own review suggests, is the fix. |

The self-hosted CI runner in the same PR is a separate question of who controls
the build pipeline and is outside this record's scope; it is declined on its own
grounds.

## Alternatives considered

**Mandatory across the board, as both forks did.** Rejected on the same
measurement ADR 0003 made: against the primary deployment target, every
documented real-mode install fails its first startup. Proposed twice, by two
unrelated contributors, and declined twice for one reason, which is itself the
argument for writing the reason down.

**Everything opt-in, including `auth_required`.** Rejected because the test
gives a different answer there. An unauthenticated network listener onto
controller writes is a hole in every threat model except single-host, and
single-host has the escape hatch. Making it opt-in would ship the hole by
default to protect a case that is already protected.

**Default on, with automatic fallback on failure.** Rejected in ADR 0003 and
restated here because it is the tempting middle path: a control that silently
downgrades has the posture of off and the appearance of on, which is worse than
either honest setting.

**Flip the opt-in defaults now, because an enterprise deployment shape has
appeared.** Rejected as premature. ADR 0003's reversal condition is that the
*primary* target changes; a second shape appearing beside it is not that. The
correct response to a second shape is to make the hardened path available and
internally consistent, then run the dated path in the reversal condition below
rather than break the first shape to serve the second.

## Consequences and accepted costs

- **Opt-in controls protect almost nobody by default.** Most installs never
  change a default. This record accepts that for a release, not indefinitely;
  the reversal condition is the schedule.
- **Two configuration shapes to test and document.** The env-var shape and the
  file-backed shape both have to work, and today the file-backed shape has no
  path in the shipped compose file or README. That is a build cost this decision
  creates and does not discharge.
- **Contributors hardening for regulated environments will keep proposing
  mandatory.** Each time, this record is the answer, and it will read as a plain
  "no" to them unless the deprecation path below is real and dated. A doctrine
  with no schedule is a refusal.
- **Nothing warns an operator running the legacy shape.** ADR 0003 names a
  one-time startup warning for unverified controllers as an interim step and
  records it as not implemented. That is still true, and it now applies to
  env-var secrets as well. The warning is the first step of the reversal path
  and is not built.

## Reversal condition

Flip a specific opt-in control to mandatory when **both** hold:

1. The hardened shape has shipped, has been the documented default for **new**
   installs for at least one minor release, and a startup warning has named the
   legacy shape on every boot during that release.
2. A major version is being cut, so the break is announced where breaks belong.

That is the full path: opt-in, then warn, then flip at a major. Any of it
skipped is a working install broken without notice, which is the outcome this
record exists to prevent.

Independently, ADR 0003's own condition stands: when the primary deployment
target stops being a self-signed LAN gateway, revisit `verify_ssl` without
waiting for the path above.

The line itself is wrong if a control ever has to go mandatory to stop real
harm before the path completes. If that happens, write the superseding record
and break the install on purpose, in a major, with the reason attached. Do not
quietly move a default.
