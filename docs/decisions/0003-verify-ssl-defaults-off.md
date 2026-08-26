# 0003. `verify_ssl` defaults to `false`

**Status:** Accepted

## Context

Every HTTP client in this server takes a `verify_ssl` flag: `clients/unifi.py`,
`clients/unifi_os.py`, `clients/protect.py`, and `clients/access.py`. It flows from
`Settings` (`unifi_verify_ssl`) or from a per-controller entry in the controllers
YAML (`ControllerConfig.verify_ssl`).

The primary deployment target is a self-hosted UniFi gateway on a home LAN,
reached at `https://<lan-ip>:443/proxy/network`. Those consoles ship a self-signed
certificate for an IP address. There is no hostname to match and no chain to walk.

An external fork, `adibirzu/mcp-unifi`, flipped the default to `true`.

## Decision

`verify_ssl` defaults to `false` in both `ControllerConfig` and the legacy
single-controller `Settings` fields, at `src/mcp_unifi/config.py:60` and
`src/mcp_unifi/config.py:168`. Operators who terminate TLS with a real certificate
set it to `true` per controller.

## Alternatives considered

**Default to `true`, as the fork did.** Rejected on out-of-box behaviour. Against
the primary target, a `true` default turns the first tool call into a TLS
verification error. The failure surfaces to the user as a broken MCP server, and
the fix is a config flag they have not read about yet. The decision trades a
strictly better default *for a deployment shape this server is not primarily aimed
at* against a working first run for the shape it is.

This was a real trade-off against a real contributor, not a dismissal. **Two of
that fork's three findings were accepted** and became the v0.20.0 secret-redaction
work: the substring pattern gap where `psk` matched `wpa_psk` but nothing in
`x_ipsec_pre_shared_key` or `x_preshared_key`, and the wiring gap where `redact()`
only ran where a module happened to call it. Adrian Birzu (`@adibirzu`) is credited
by name in the CHANGELOG for both. Only the TLS default was declined.

**Default to `true` with an automatic fallback to `false` on a verification
failure.** Rejected outright. A client that silently downgrades on TLS failure has
the security posture of `false` while presenting the posture of `true`, which is
worse than either. If verification is on it has to fail closed.

**Pin the console's self-signed certificate.** A real option and strictly better
than either default: verification against a pinned cert, no CA needed. Not built,
because it needs a fetch-and-trust bootstrap step, per-controller cert storage, and
a rotation story. Recorded here as the alternative most likely to make this
decision obsolete.

## Consequences and accepted costs

- **The default configuration does not authenticate the controller.** On a LAN
  segment an attacker able to intercept traffic to the gateway IP could
  man-in-the-middle the API key and every configuration read and write. This is the
  accepted cost and it should not be softened. The mitigating context is that the
  threat model is a home LAN, the controller is on the same broadcast domain as the
  server, and an attacker with that position already has other paths. That is
  context, not a reason the risk is absent.
- Anyone who deploys this against a controller reachable over an untrusted network
  and does not read the flag inherits that exposure by default.
- The default diverges from the `adibirzu` fork, so configuration written against
  one is not portable to the other without checking this flag.

## Reversal condition

Flip the default to `true` when **UniFi ships consoles with a verifiable
certificate out of the box**, or when the primary deployment target stops being a
self-signed LAN gateway.

Implement certificate pinning, and make it the default, if the server ever gains a
first-run bootstrap step where fetching and trusting the console's certificate can
happen without the user writing config by hand. That would remove the trade-off
rather than resolving it in either direction.

An interim step that needs no decision reversal: emitting a one-time startup
warning naming each controller running unverified. That is not implemented today.
