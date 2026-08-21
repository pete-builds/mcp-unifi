# 0005. Writes stay on the private UniFi Network API

**Status:** Accepted, with an outstanding documentation task

## Context

UniFi exposes two API surfaces on a self-hosted console:

- The **private Network API** behind `/proxy/network/api/s/<site>/...`, plus a
  newer `/proxy/network/v2/api/site/<site>/...` tree. Undocumented, unversioned,
  and free to change between firmware releases.
- The **official Integration API** at `/proxy/network/integration/v1/...`.
  Documented and versioned.

This server runs entirely on the first one. `src/mcp_unifi/clients/unifi.py` builds
its base as `https://{host}:{port}/proxy/network` with a site path of
`/api/s/{site}`, and every write goes through it: 28 calls under `/rest/*`, four
under `/cmd/*`, one under `/set/*`. The v2 tree is referenced in 27 places for the
reads that only exist there. **There is not a single call to `/integration/v1` in
the codebase.**

The fragility is not hypothetical. Live probes against a UCG-Fiber recorded in
`clients/unifi.py` and `SESSION-RESUME.md` found `GET` and `POST /stat/event`
returning 404 `api.err.NotFound` on Network 10.4.57, still 404 on 10.5.67, with
sibling `stat/*` routes answering 200 on the same key. A route this server depends
on simply was not there.

## Decision

Keep writes on the private API. Do not migrate.

The reason is capability, not effort. The same probe that found the missing event
route also checked the official surface: **Integration v1 on that firmware exposes
only `devices` and `clients`.** It has no firewall rules, no VLANs, no WLANs, no
port forwards, no routes, no DHCP reservations, no port profiles. Migrating would
not be a like-for-like port. It would delete most of the tool surface.

## Alternatives considered

**Migrate everything to the Integration API.** Rejected. It cannot express the
operations this server exists to perform. A stable API for a capability set that
excludes the capability is not a substitute.

**Hybrid: use the Integration API where it covers the operation, private endpoints
elsewhere.** Rejected for now, and this is the closest call in this record. The
benefit is narrow, because the covered surface is `devices` and `clients`, which is
a small slice of a 134-tool server. The cost is two client code paths, two auth
shapes to keep working, two error-envelope translations, and a rule about which
surface a given tool uses that every future contributor has to learn. That is a
permanent structural tax for stability on a minority of calls.

**Pin a supported firmware range and refuse to run outside it.** Rejected as
hostile to users, who do not control when a UniFi console updates itself.

**Defensive degradation, which is what is actually built.** Where a private route
is known to be absent on current firmware, the client tolerates it rather than
raising. `list_events` GETs `/stat/event` and returns an empty list on the expected
404 or 400, logged at INFO, forward-compatible with a firmware that restores the
route. This does not remove the fragility, it contains one known instance of it.

## Consequences and accepted costs

- **A firmware update can break writes with no warning and no deprecation notice.**
  There is no contract to appeal to. This is the accepted cost and it is the real
  one.
- Breakage is discovered in production, by a user, at the moment they try to change
  something.
- Endpoint behaviour recorded here was probed against specific firmware versions on
  one hardware model. Nothing guarantees another console behaves the same way.
- The codebase carries thirteen separate places in `clients/unifi.py` alone where a
  firmware quirk or a probe result had to be written down in a docstring, because
  no vendor documentation records it.

**Outstanding task, stated rather than implied:** the honest interim is a
documentation pass marking, per write tool, which endpoint it rides and what is
known about that endpoint's stability. **That pass has not been done.** What can be
stated cheaply and accurately today is the coarse version: *every* write in this
server rides the private surface, so no write carries a stability guarantee. The
per-endpoint detail, which routes have been probed live against which firmware and
which have only ever been exercised in stub mode, is not currently collected
anywhere a user can read it.

## Reversal condition

Migrate a capability to the Integration API the first release in which **that
capability appears there**, checked against a live probe rather than release notes.
The trigger is per-capability, not all-or-nothing, and it reverses the hybrid
rejection above: once the covered surface is large enough that the two-code-path
tax buys stability for most calls rather than a minority, the hybrid becomes
correct.

The concrete check: re-probe `/proxy/network/integration/v1/` on current firmware
and see whether firewall, network, and WLAN resources exist. If they do, this
record is superseded.

Reverse sooner, and accept the hybrid tax immediately, if a firmware update breaks
a private write endpoint that the Integration API already covers. One real outage
in that shape settles the cost argument.
