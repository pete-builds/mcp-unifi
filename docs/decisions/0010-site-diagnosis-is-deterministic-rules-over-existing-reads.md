# 0010. Site diagnosis is deterministic rules over existing reads, with stable rule ids

**Status:** Accepted. Rules are grounded in fields the code and stubs carry;
several are not live-verified, listed under "Not live-verified".

## Context

The server already covers four of the steps an operator takes around a change:
plan (`dry_run`), approve (the preview token and `confirm_destructive_action`),
verify (`verification.py`) and recover (composite rollback, `restore_config`).
It had nothing that correlates, diagnoses or recommends. Asked "is my network
healthy?", an agent made six to eight calls (`get_site_health`, `list_devices`,
`list_clients`, `list_alarms`, `list_threat_detections`, `get_anomalies`,
`get_speedtest_results`...) and then reasoned over raw controller records with no
shared definition of a problem. Two runs over the same network could reach
different conclusions, and nothing could be graded.

Two tools in the repo already show the shape a trustworthy answer takes:
`get_console_health` (a state enum, a plain summary, a next step, raw evidence,
and "unknown" as inconclusive rather than an outage) and `audit_open_ports`
(honest limitation fields such as `wan_zone_resolved: false` and
`firewall_policies_error`, so a failed read never looks like a clean one).

## Decision

One new read-only tool, `diagnose_site`, in
`src/mcp_unifi/modules/network/diagnose.py`, on a findings contract in
`src/mcp_unifi/modules/network/_findings.py`.

- **Reads.** Five existing backend methods, called once each in a fixed order:
  `list_devices`, `get_site_health`, `list_clients`, `list_alarms` (24 hours,
  critical log) and `list_threat_detections` (24 hours). No new endpoint, no new
  dependency, no storage. Each read is caught on its own (`UniFiError`), and a
  read that returns the wrong shape counts as failed.
- **Rules.** A fixed tuple, `RULES`, each with a stable dotted id, the
  severities it can emit, the reads it requires and the tools it may name in
  `next`. Ten rules: `device.offline`, `device.not_connected`,
  `device.high_cpu`, `device.high_memory`, `device.upgradable`, `wan.down`,
  `health.subsystem_not_ok`, `wifi.weak_signal_clients`, `alarms.active`,
  `threats.detected`.
- **Findings.** `observed` holds only values read from the controller, each
  with the tool it came from. `inferred` is the rule's conclusion, built from a
  fixed template and numbers, and may be null. `confidence`, `limitations` and
  `next` (registered tool plus arguments) complete it.
- **Fail honest.** A rule whose read failed, or whose required field is
  missing, goes in `not_evaluated` with a reason. `scope: "rule"` means it did
  not run, `scope: "partial"` means it ran over only some subjects. A read that
  reports itself cut short (the IPS read's `matched` above `returned`, the
  alarm read's `total` above `returned`, `more_available`, or
  `window_fully_read: false`) is a `partial` gap with the counts, and its
  findings say the counts are lower bounds. The verdict is `critical` if any
  critical finding exists, otherwise `unknown` if any rule able to emit
  `critical` (`device.offline`, `wan.down`, `health.subsystem_not_ok`) is in
  `not_evaluated`, otherwise `degraded` on any warning, otherwise `healthy`,
  with one override: **a diagnosis is "blind" when any read failed for a
  reason other than `UniFiUnsupportedError`, or any rule raised, and a blind
  diagnosis that would have been `healthy` is `unknown` instead.**
  `UniFiUnsupportedError` is what the client raises when a route does not
  exist on this firmware (`list_alarms` when the v2 critical log and the
  legacy fallback are both absent, `list_threat_detections` when both IPS
  routes answer 404/405); its rules are listed as not evaluated, the check
  carries `unsupported: true`, and it does not block `healthy` on its own.
  When any read failed the top-level `next` is `get_console_health`, which
  probes UniFi OS separately.
- **Contained failures.** Each read catches everything it raises: a
  `UniFiError` keeps this server's own cleaned message, anything else keeps
  only its class name (`unexpected TypeError`). Each rule runs inside its own
  handler: a rule that raises is listed as `rule raised <ClassName>`, never
  with the message, and makes the diagnosis blind. Numbers from the
  controller pass through one coercion that rejects NaN and infinity, so a
  bad value is a missing value, not a crash. When a subsystem appears twice in
  site health, the worst status wins, independent of the order the records
  came in.
- **Untrusted text.** Controller-provided strings (device names, models and
  types, firmware versions, alarm keys, IPS actions and categories) may appear
  only in `subject` values and `observed` values. The `finding` builder in
  `_findings.py` is the one seam: it runs `clean_text` over every subject
  value, every observed value and every string argument of every next step,
  whichever rule built the finding, so a new rule cannot forget. `clean_text`
  strips every Unicode `C*` code point, collapses whitespace and caps at 80
  characters. MACs are echoed only when they parse as MACs. `summary`,
  `inferred`, `limitations` and `not_evaluated` reasons are fixed templates
  and numbers.
- **Bounded and deterministic.** At most 10 findings per rule, with the rest
  counted under `truncated`. Findings are sorted by severity, rule id, MAC and
  name. Nothing reads the clock: the two windowed reads pass `hours` to the
  backend and only counts come back, so no wall-clock time reaches the output.
- **Thresholds** are module constants, echoed under `thresholds` in every
  response: CPU and memory above 90 percent, weak signal below -75 dBm, three
  weak clients per AP, a 24-hour window, 100 log rows. **These are this
  project's conservative defaults, not Ubiquiti guidance.**

## Alternatives considered

- **An embedded LLM that reads the records and writes the diagnosis.** Rejected.
  It needs a model, a key and a budget on a server that has none of them; its
  output differs run to run, so it cannot be graded or regression-tested; and it
  would read controller-provided text (device names, alarm messages) as prompt
  input, which is an injection path from anyone who can rename a device. The
  consuming agent is already a model. This tool's job is to hand it evidence it
  can trust, not a second opinion it has to second-guess.
- **Free-text findings without rule ids.** Rejected. A benchmark needs to ask
  "did the tool raise `device.offline` for this MAC" and get a yes or no that
  survives a rewording. Ids are lowercase, dotted, listed in the docs, and a
  rename is a breaking change.
- **A rule framework or plugin registry.** Rejected as weight. Ten rules are
  ten functions and a tuple. `_findings.py` is a handful of `TypedDict`s and
  builders.
- **Probing the console layer inside this tool.** Rejected for now.
  `get_console_health` already owns the UniFi OS probes and their subtle
  envelope rules; duplicating them here would mean two classifiers to keep in
  step. When the Network reads fail, the diagnosis says `unknown` and names that
  tool.
- **Letting a failed alarm, IPS or client read leave the site `healthy`.**
  The first version did this, on the grounds that those rules can only warn.
  Review reproduced `healthy` with three of the five reads failing, which is a
  diagnosis that saw almost nothing calling the site fine. Rejected: any
  failure makes the diagnosis blind. The exemption is narrow and named,
  `UniFiUnsupportedError` only, because the v2 alarm route is not
  live-verified for this server's key (see `UniFiClient.list_alarms`) and
  pinning every diagnosis at `unknown` on a firmware that simply lacks the
  route would make the tool useless there.
- **Including `vpn` in site health.** Rejected: a site with no VPN reports it
  as `warning` (the seeded stub does too), so every such site would read as
  degraded forever.
- **Reachability tests, topology walking, snapshot diffs, anomaly history.**
  Out of scope for this first piece. Each needs either new state or new
  endpoints, and each belongs in its own change.

## Consequences and accepted costs

- An adopted device left unplugged keeps the site `critical` until it is
  reconnected or forgotten in the controller. That is deliberate: the
  controller still counts it as part of the site.
- A transient 5xx on any one of the five reads turns a healthy site
  `unknown` for that call. Re-running is the remedy; the failed read is named.
- A site with a missing `www` record, or a device with no numeric `state`,
  reads `unknown`, not `healthy`. That is the point, but on a firmware that
  drops one of those fields the tool will look permanently inconclusive until a
  rule is adjusted.
- The thresholds are guesses on the safe side. A gateway that idles at 92
  percent memory will warn on every call; the threshold is visible in the
  output so the agent can say why.
- One sample per call. CPU and memory findings carry a limitation saying a
  spike reads the same as sustained load.
- The tool output is pretty-printed JSON through the shared `format_json`
  serialiser. A healthy ten-device site measures under 4 KB, the stub site with
  three findings about 4 KB.
- The generated tool manifest changes, which will conflict with other open PRs
  that regenerate it. Regenerating after rebase resolves it.

## Not live-verified

Grounded in the stub seed, `stats_shape.py` and the client code, but not read
from a real controller by this change:

- `upgradable` and `upgrade_to_firmware` on `/stat/device` records. Absent from
  the stub, so `device.upgradable` is `not_evaluated` there. It degrades the
  same way on a controller that does not send it.
- Device `state` values other than 1. `0` is read as disconnected; every other
  non-1 value is reported by number without a name.
- `system-stats` on switches and APs (the stub switch has none, so CPU and
  memory are partial there).
- Site-health `status` values other than `ok` and `warning` (`error` is
  assumed to be the failure value).
- The v2 `system-log/critical` read behind `list_alarms` (see its docstring).

## Reversal condition

Revisit when either holds: a captured live `/stat/device` or `/stat/health`
record contradicts a field this tool reads (rename the rule's field and its
`not_evaluated` reason, keep the id), or a benchmark run over recorded sites
shows a rule whose findings are wrong more often than right at its stated
confidence (change the threshold or drop the rule, and record the id as
retired, never reused).
