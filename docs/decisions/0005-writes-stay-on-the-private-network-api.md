# 0005. Writes stay on the private UniFi Network API

**Status:** Superseded by [0008](0008-network-and-wlan-writes-use-the-integration-api.md)
for network and WLAN writes. Still accepted for every other write, with an
outstanding documentation task

## Context

UniFi exposes two API surfaces on a self-hosted console:

- The **private Network API** behind `/proxy/network/api/s/<site>/...`, plus a
  newer `/proxy/network/v2/api/site/<site>/...` tree. Undocumented, unversioned,
  and free to change between firmware releases.
- The **official Integration API** at `/proxy/network/integration/v1/...`.
  Documented and versioned.

This server runs entirely on the first one. `src/mcp_unifi/clients/unifi.py` builds
its base as `https://{host}:{port}/proxy/network` with a site path of
`/api/s/{site}`, and every configuration write goes through it. Counting the
mutating HTTP calls in that one file: 28 under `/rest/*`, four under `/cmd/*`, one
under `/set/*`. The v2 tree is referenced in 27 places for the reads that only
exist there. The other clients (`unifi_os.py`, `protect.py`, `access.py`) issue no
configuration writes at all; the single POST among them is a console login.
**There is not one call to `/integration/v1` anywhere in the codebase.**

The fragility is not hypothetical. Live probes against a UCG-Fiber recorded in
`clients/unifi.py` and `SESSION-RESUME.md` found `GET` and `POST /stat/event`
returning 404 `api.err.NotFound` on Network 10.4.57, still 404 on 10.5.67, with
sibling `stat/*` routes answering 200 on the same key. A route this server depends
on simply was not there.

## Decision

Keep writes on the private API. Do not migrate.

The reason is capability, not effort. The same probe that found the missing event
route also checked the official surface: **Integration v1 on that firmware exposes
only `devices` and `clients`.** (Network 10.4.57; no longer true on 10.6.106, see
the re-probe below.) It has no firewall rules, no VLANs, no WLANs, no
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

The concrete check: run `scripts/probe_integration_api.py` against current
firmware (it reads the server's own env vars and issues GET requests only) and
see whether firewall, network, and WLAN resources exist. If they do, this record
is superseded.

Reverse sooner, and accept the hybrid tax immediately, if a firmware update breaks
a private write endpoint that the Integration API already covers. One real outage
in that shape settles the cost argument.

## Re-probe: 2026-10-17, UniFi Network 10.6.106

Run with `scripts/probe_integration_api.py` from inside the deployed container on a
UCG-Fiber running UniFi Network 10.6.106. GET requests only; no write to the
Integration API was attempted. Both controls held: a deliberately wrong API key
was rejected with 401, and a route that cannot exist returned 404, so a 200 below
means the resource is served and a non-404 4xx means the route exists.

| Resource under `/v1/sites/{siteId}/` | Result |
|---|---|
| `devices`, `clients` | 200 with data (the two found on 10.4.57) |
| `networks` | 200 with data |
| `wifi/broadcasts` | 200 with data |
| `wans`, `vpn/servers`, `radius/profiles` | 200 with data |
| `acl-rules`, `dns/policies`, `traffic-matching-lists`, `device-tags`, `hotspot/vouchers`, `vpn/site-to-site-tunnels` | 200, none configured on this site |
| `firewall/zones`, `firewall/policies` | 400 `api.firewall.zone-based-firewall-not-configured` |

Cross-checked against the private API this server uses, so the 200s are the same
configuration and not an empty shell: WLAN names match one for one. Networks list
4 on v1 against 7 in the private `rest/networkconf`; the 3 missing are exactly the
two WAN entries and the WireGuard VPN server, which v1 serves separately under
`wans` and `vpn/servers`. The private v2 API also reports zero firewall zones and
zero zone policies, which agrees with the 400: this site has not migrated to the
Zone-Based Firewall, and the v1 firewall routes exist for sites that have.

What this changes, measured against the reversal condition above:

- **Networks and WLANs: met.** Both capabilities now appear on the Integration API
  with live data. The per-capability trigger says to migrate them.
- **Firewall: met only in zone form.** v1 carries zone policies and zones. It does
  not carry the legacy firewall rules that `create_firewall_rule` and friends write
  today, and the developer.ui.com reference for 10.6.106 lists no route for them.
- **Still absent from the official reference:** port forwards, static routes, DHCP
  reservations, and port profiles. A full migration remains impossible, so the
  first alternative above stays rejected for the reason it was rejected.
- **The hybrid alternative is reopened.** It lost because the covered surface was
  devices and clients. Networks and WLANs are core write surfaces, which is the
  scale at which this record said the two-code-path tax becomes correct.

Not established by this probe, and needed before any migration ships: that the v1
write routes (`POST`/`PUT`/`DELETE` on networks and WiFi broadcasts) accept the
payloads this server needs to send, and how their validation errors differ from the
private API's. The superseding decision belongs in a new record once that is known.
