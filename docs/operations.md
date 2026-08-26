# Operating mcp-unifi

This is the document you read before putting this server in front of an agent
that can change your network, and the one you read at 2am when something looks
wrong. It covers what the server measures about itself, what "healthy" means in
numbers, what should wake a person up, and what a tool call actually costs.

Everything here that is presented as a measured number was measured, with the
script that produced it named alongside. Everything that could not be measured
is marked as such rather than filled in with a plausible figure. There is more
of the second kind than I would like, and the reason is stated in each case.

Contents:

1. [Tracing: what the server emits](#1-tracing-what-the-server-emits)
2. [Turning tracing on](#2-turning-tracing-on)
3. [Service level objectives](#3-service-level-objectives)
4. [Error budget](#4-error-budget)
5. [What pages a human, and what does not](#5-what-pages-a-human-and-what-does-not)
6. [Latency distribution](#6-latency-distribution)
7. [Cost per tool call](#7-cost-per-tool-call)
8. [Example collector configuration](#8-example-collector-configuration)

---

## 1. Tracing: what the server emits

One OpenTelemetry span per tool call, named `mcp.tool/<tool_name>`. The span
opens before the tool body runs and closes after the audit record is written,
so its duration is the whole cost of serving the call, which is what the caller
actually waits for.

| Attribute | Type | Present when | What it answers |
|---|---|---|---|
| `mcp.tool.name` | string | always | Which tool was called |
| `mcp.tool.mutates` | bool | always | Was this a write attempt |
| `mcp.tool.dry_run` | bool | the tool has a preview mode and the caller passed the flag | Was the change previewed or applied |
| `mcp.tool.denied_by` | string | the call was refused | Which control refused it: `readonly` or `scope` |
| `mcp.tool.controller` | string | always | Which named controller it was routed to |
| `mcp.tool.client_id` | string | HTTP transport with auth enabled | Which caller |
| `mcp.tool.outcome` | string | always | `ok`, `error`, or `refused` |
| `mcp.tool.error_type` | string | the tool body raised | Exception class name |
| `mcp.server.stub_mode` | bool | always | Was this answered from stub data or a real controller |

`denied_by` is the attribute that makes this work worth doing. The audit log
already records refusals as a distinct field rather than as a convention on the
error string, so an operator can isolate them with one `jq` pass. Putting the
same field on a span makes the same question answerable across time and across
callers in a trace backend: how many write attempts did a given client make
last week, and how many did the write gate refuse? That is a question about a
fleet of agents, not about one process, and a JSONL file on one container is the
wrong shape for it.

`mcp.server.stub_mode` earns its place for a duller reason. A demo deployment
and a production one can point at the same collector, and without that flag
their latency numbers are indistinguishable. Every number in section 6 would be
meaningless in a backend that mixed them.

### Three outcomes, not two

`outcome=refused` is separate from `outcome=error` on purpose. A refusal is not
a failure: the server worked correctly and declined. The audit log conflates
them under `success: false` for backward compatibility with logs already on
disk, and that asymmetry is deliberate and documented in the audit module. A
span has no history to preserve, so it splits them, and the SLOs below depend on
the split: refusals must not consume an availability error budget.

`outcome=ok` follows the audit log's `success` semantics exactly: it means the
tool body returned, which includes returning a formatted error envelope because
the controller rejected the request. A trace showing `outcome=ok` is saying
"the server did its job", not "the change was applied". If you want "did the
controller accept it", that is in the response body and the audit record, not
on the span.

### What is deliberately not on a span

Tool arguments and tool results. Not scrubbed, not truncated: never present.

Span attributes are an emission path exactly like a `dry_run` preview or a list
response, and this repository has already shipped one advisory
(GHSA-m3mv-27vr-gh2w) for treating redaction as a logging concern rather than an
output concern. A trace backend is a persistent, often third-party, often
broadly-readable store; a WPA passphrase reaching one would be the same class of
bug with a worse blast radius.

So the span inverts the audit log's posture. The audit log accepts arbitrary
arguments and scrubs them on the way out. The span accepts a fixed allowlist of
scalars and nothing else, because an allowlist cannot be defeated by a
controller field nobody has seen yet. Two guards enforce it: an attribute key
matching the shared sensitive-key patterns is dropped with a warning, and any
value that is not a `str`, `bool`, `int`, or `float` is dropped rather than
stringified. Stringifying is precisely how a payload sneaks onto a span.

Exception messages are dropped for the same reason. They are free-form and
routinely echo caller input, so the span records the exception *type* only. The
message stays in the audit log, which is local to the operator by default.

---

## 2. Turning tracing on

Tracing is off unless you ask for it, and the OpenTelemetry SDK is not a
dependency of this server.

```bash
pip install 'mcp-unifi[otel]'
export MCP_UNIFI_OTEL_ENABLED=true
export OTEL_EXPORTER_OTLP_ENDPOINT=http://collector.internal:4318
opentelemetry-instrument mcp-unifi
```

| Variable | Default | Meaning |
|---|---|---|
| `MCP_UNIFI_OTEL_ENABLED` | unset (off) | `true`/`1`/`yes`/`on` to enable |
| `MCP_UNIFI_OTEL_SERVICE_NAME` | `mcp-unifi` | Tracer name |

Endpoint, headers, sampling, and protocol use the standard `OTEL_EXPORTER_OTLP_*`
variables read by the SDK itself. This server does not re-invent them and does
not install a tracer provider of its own; use `opentelemetry-instrument`, or
configure a provider in your own entrypoint.

### How "optional" is enforced, precisely

Stated carefully because the imprecise version would be wrong:
`opentelemetry-api` **is** already present in `requirements.lock`, pinned at
1.44.0, because `fastmcp-slim` depends on it. The API on its own is inert:
without an SDK-installed tracer provider it hands back a no-op tracer that
creates no real spans and exports nothing.

What the `otel` extra adds, and what a default install genuinely does not have,
is the **SDK** and the **OTLP exporter**. Neither is in `requirements.in`,
`requirements.lock`, or the `[project] dependencies` table.

On top of that:

- The flag defaults to off, so a deployment that happens to have the SDK
  present from some unrelated library still emits nothing.
- The OpenTelemetry import happens lazily on first use inside a
  `try`/`except ImportError`, never at server start. A missing package
  downgrades to "tracing stays off" plus one warning line.
- The import is attempted once for the life of the process, not once per call,
  including the failing case.
- Every span operation is wrapped. A broken exporter, a collector that went
  away, or an API shape that moved between versions all degrade to no span. An
  observability failure must never become a tool failure, which is the same
  rule the audit log already follows for sink write errors.

Four of the tests in `tests/test_telemetry.py` exist only to hold that line: a
tool call succeeds with tracing off, succeeds when the OpenTelemetry import is
made to fail, succeeds against a tracer whose span creation always raises, and
succeeds against the real OpenTelemetry API with no SDK provider configured.

---

## 3. Service level objectives

Five SLOs. The targets are argued rather than rounded, and two of them are
explicitly provisional because the measurement that would justify a number does
not exist yet.

### SLO 1: Tool call served

**SLI.** Fraction of `tools/call` requests that return a response envelope,
whether that envelope is a success, a formatted controller error, or a refusal.
The denominator is every request that reached the server.

**Target: 99.9% over a rolling 30 days.**

Not 99.99%, and the reason is structural rather than modest. This is a single
container with one replica, no failover, sharing a host with everything else in
a homelab, and it can never be more available than the gateway it talks to. A
UniFi gateway firmware update reboots the controller for several minutes;
99.99% is 4 minutes 19 seconds of budget for a whole month, so one routine
firmware reboot would exhaust the year's budget in a single evening. A target
that a normal maintenance action breaks is not an objective, it is a
decoration.

Not 99% either. That is 7 hours 12 minutes a month, which for a service whose
whole job is to be reachable when you need to change a firewall rule is not a
commitment to anything.

**A refusal counts as served.** A call the write gate or the scope middleware
declines is the server working correctly. Counting refusals against
availability would create pressure to weaken a security control to protect a
number, which is exactly backwards.

### SLO 2: Server-side overhead

**SLI.** p99 of span duration minus the time spent waiting on the controller,
measured over a rolling 7 days.

**Target: p99 under 5 ms.**

Derived from measurement, not from a round number. The measured p99 across
eight representative tools against the stub backend, which is the server's own
work with no network in the path, ranges from 0.29 ms to 0.93 ms (section 6).
Five milliseconds is roughly five times the worst measured case. The headroom is
there for two named things: a busier or slower host than the benchmark machine,
and contention on the audit sink, which `fsync`s once per record and is
therefore the one part of the path sensitive to disk pressure.

Anything under 5 ms is invisible next to a controller round trip and far under
human perception. If this SLO breaks, the cause is the host or the disk, not the
tool.

### SLO 3: End to end tool latency (PROVISIONAL, not yet measurable)

**SLI.** p95 and p99 of full span duration, split by `mcp.tool.mutates`.

**Provisional target: p95 under 2 s for reads, p99 under 5 s for writes.**

Flagged provisional because **no measurement behind it exists**. Every latency
number in this document was taken against the in-memory stub backend, which
bounds the server's own overhead and says nothing at all about controller
round-trip time. UniFi controller response time varies by hardware class, site
size, and how much the controller is already doing, and I have not measured it
under load.

The numbers above are placeholders chosen to be obviously loose. **The first
job after enabling tracing against a real controller is to replace them with a
measured baseline**, taken over at least a week so a nightly backup or a
provision storm shows up in the tail. Until then, treat a breach as a prompt to
go and measure rather than as an incident.

### SLO 4: Refusal integrity

**SLI.** Fraction of calls to mutating tools that are refused while
`MCP_UNIFI_READONLY=true`.

**Target: 100%. No error budget.**

A probabilistic target would be meaningless here. This is a binary security
control, and 99.9% correct means one write in a thousand got through, which is
not a degraded service but a breached one. It is stated as an SLO anyway because
it is the property the whole read-only posture rests on, and because it is
verifiable: the write gate is three fail-closed layers, and a live-enumeration
test asserts that every registered tool carries a classification, so a new tool
added without one stops the server from starting rather than silently becoming
callable.

Any observed value below 100% is an incident, not a budget burn.

### SLO 5: Audit completeness

**SLI.** Fraction of tool calls, dispatched or refused, that produce exactly one
audit record.

**Target: 99.99% over a rolling 30 days.**

Higher than the availability target, because the failure is worse. Audit sink
errors are caught and swallowed by design, so that an audit outage cannot break
a tool call. The cost of that choice is that the server can keep executing
writes while its evidence surface is silently down, and the only thing standing
between that and an unexplainable network change is noticing quickly. 99.99% is
roughly one missing record in ten thousand calls, which for a homelab call
volume means "effectively never, and tell me the first time it happens".

---

## 4. Error budget

Applies to SLO 1 only. SLO 4 has no budget by construction, and SLOs 3 and 5 are
tracked but too new or too provisional to burn against.

At 99.9% over 30 days:

| Window | Budget |
|---|---|
| 30 days | 43 min 12 s |
| 7 days | 10 min 05 s |
| 24 hours | 1 min 26 s |

**Burn rate policy.**

| Burn | Meaning | Action |
|---|---|---|
| 14.4x over 1 hour | 2% of the 30-day budget in an hour | Page (see section 5) |
| 6x over 6 hours | 5% of the budget in six hours | Page |
| 1x over 3 days | On pace to exactly exhaust the budget | Ticket, look at it this week |
| Budget exhausted | No margin left this window | Freeze non-essential deploys of this server until the window rolls |

The freeze is the part that makes a budget mean anything. A budget you never act
on is a metric, not a budget.

**Planned maintenance counts.** A restart to deploy a new image spends budget
like any other unavailability, because from the agent's point of view it is
unavailability. That is deliberate: it prices redeploys, and 43 minutes a month
is plenty for a server that redeploys in seconds.

---

## 5. What pages a human, and what does not

"Alert on errors" is not an answer, so here is the specific list. The premise:
this server is one operator's infrastructure with no on-call rotation, so a page
must be something that is both wrong and actionable at the moment it fires.

### Page

1. **`/health` fails for 5 consecutive minutes.** The server is down or wedged.
   Five minutes rather than one, because a deploy restart is normal and a
   single-probe blip is noise.
2. **Fast error-budget burn: 14.4x for one hour, or 6x for six hours.** Calls are
   failing at a rate that eats a month of budget in days.
3. **Audit sink write failures for 5 consecutive minutes** while calls are still
   being served. This is the specific dangerous state: the server is still
   executing writes against the network while nothing is recording them. It
   pages even though nothing is user-visibly broken, because the damage is
   silent and only compounds.
4. **The server fails to start.** A tool registered without a `mutates`
   declaration, an unknown module name, or a malformed token map all refuse to
   boot on purpose, and a fail-closed server that nobody notices is just an
   outage with extra steps. In practice this surfaces through 1, but alert on
   the restart loop directly if your platform exposes it.

### Do not page

1. **Any refusal.** `denied_by=readonly` and `denied_by=scope` are the controls
   working. This is the single most common way an observability setup gets
   wrong: a security control that fires becomes an alert, the alert becomes
   noise, and the noise becomes a reason to widen the control. Refusals belong
   on a dashboard, never in a pager.
2. **Individual tool errors.** The controller rejecting a bad payload is
   information the calling agent already has in its response envelope, and it
   will usually correct itself. A sustained *rate* of them is covered by 2
   above.
3. **`dry_run` activity of any volume.** A preview changes nothing.
4. **Controller 4xx.** That is a caller problem, not a service problem.
5. **A single restart, or one failed health probe.**
6. **Latency breaching SLO 3** while that SLO is still marked provisional. It is
   a prompt to go and measure, not an incident.

### Ticket, do not page

- **Sustained refusal rate above its usual baseline**, especially concentrated
  on one `mcp.tool.client_id`. The likely cause is dull: a client's scope was
  narrowed and its prompt was not. Worth a look this week. The less likely cause
  is an agent repeatedly attempting writes it should not, which is worth a look
  for entirely different reasons. Either way the response is investigation, not
  a 2am fix, because the control is already holding.
- **Slow error-budget burn (1x over 3 days).**
- **A rise in `outcome=error` concentrated on one tool**, which usually means a
  controller firmware change moved an endpoint.

---

## 6. Latency distribution

### These are stub numbers. Read this paragraph before reading the table.

Every figure below was produced by `scripts/measure_tool_cost.py` against the
server's **in-memory stub backend**. There is no network anywhere in the
measured path and no UniFi controller involved.

What that does tell you: it bounds the server's own overhead. Argument
validation, dispatch, the middleware chain, redaction, the audit write with its
`fsync`, and JSON serialisation are all inside these numbers.

What it does not tell you, at all: how long a real tool call takes. In
production the controller round trip dominates, typically by orders of
magnitude, and I have not measured it. A p50 of 0.3 ms here does not predict a
p50 of 0.3 ms anywhere real. It predicts that when you measure production, the
server's own contribution will be roughly this, and the rest is the controller.

Conditions: 300 iterations per tool after 20 warm-up calls, single process,
Python 3.13.13, macOS on arm64, tracing off, audit sink writing to a local
file. A Linux container on other hardware will differ; rerun the script there.

| Tool | p50 (ms) | p90 (ms) | p99 (ms) | max (ms) |
|---|---|---|---|---|
| `list_networks` | 0.304 | 0.746 | 0.929 | 1.141 |
| `list_clients` | 0.350 | 0.388 | 0.434 | 0.456 |
| `list_devices` | 0.650 | 0.691 | 0.754 | 0.769 |
| `list_firewall_rules` | 0.250 | 0.285 | 0.316 | 0.329 |
| `get_site_health` | 0.261 | 0.287 | 0.343 | 0.377 |
| `get_wan_status` | 0.239 | 0.256 | 0.288 | 0.319 |
| `list_wlans` | 0.251 | 0.280 | 0.329 | 0.338 |
| `create_vlan` (`dry_run=true`) | 0.257 | 0.279 | 0.310 | 0.318 |

Two things in that table are worth noticing.

`list_devices` is the slowest at every percentile, and it is also the tool with
the largest response record (section 7). The server's overhead tracks payload
size, which is what you would expect when the dominant costs are a redaction
walk and two JSON serialisations over the same structure.

`create_vlan` in preview mode costs the same as a read. The preview path does
its validation and redaction and returns without touching a controller, so a
`dry_run` really is cheap, which is what makes "preview everything" a reasonable
default posture for an agent rather than an expensive one.

### Cost of tracing itself

Measured the same way, `list_networks`, tracing off versus tracing on with a
real OpenTelemetry SDK and a batch span processor exporting in-process:

| Configuration | p50 (ms) | p90 (ms) | p99 (ms) |
|---|---|---|---|
| Tracing off | 0.302 | 0.343 | 0.386 |
| Tracing on, SDK plus batch exporter | 0.361 | 0.396 | 0.499 |

**p50 delta: +0.058 ms per call**, about 19% of a very small number. Spans were
confirmed to actually reach the exporter (640 exported during the run), so this
is the cost of really producing and shipping a span, not the cost of a no-op.

Caveat, and it matters: the exporter here was in-process and counted spans
rather than sending them anywhere. A real OTLP exporter adds network I/O, which
the batch processor moves off the request path but does not make free. This
number is a floor, not a full accounting.

---

## 7. Cost per tool call

There is no per-call billing to attribute. This is a self-hosted server talking
to hardware you already own, so a dollar figure would be invented, and inventing
one would be worse than useless: it would be a number people quote.

So the honest question is not "what does a call cost" but "what scarce resource
does a call consume". Four units, three of them measured.

### Unit 1: Controller API calls per tool call (measured, real-mode)

This is the one that matters. The gateway is the constrained resource: on
UCG-class and UDM-class hardware the controller runs on a modest embedded CPU
that is simultaneously routing your traffic, and it is the shared thing an
overenthusiastic agent can degrade for everyone in the house.

Measured by building the server in **real mode** against a mocked HTTP
transport and counting the actual `httpx` requests issued per tool call. The
wire and the controller are simulated; the request objects are real.

| Tool | Controller HTTP requests | Endpoint |
|---|---|---|
| `list_networks` | 1 | `GET /rest/networkconf` |
| `list_clients` | 1 | `GET /stat/sta` |
| `list_devices` | 1 | `GET /stat/device` |
| `list_firewall_rules` | 1 | `GET /rest/firewallrule` |
| `get_site_health` | 1 | `GET /stat/health` |
| `get_wan_status` | 1 | `GET /stat/health` |
| `list_wlans` | 1 | `GET /rest/wlanconf` |

One request per tool call for every read measured. That is the number to hold
onto: for simple reads, tool calls and controller calls are one to one, so an
agent's call count is directly the load it puts on your gateway.

**Not measured, and do not assume it is also 1:** composite tools such as
`provision_homelab_service` and `create_iot_network`, several write paths that
read before they write, and any tool that resolves a MAC address to a device ID
first. Those issue more than one request by construction, and the count varies
with the payload. Measuring them properly needs per-endpoint mocks rather than a
catch-all, which is worth doing and is not done here.

Every write in this server rides the private UniFi surface (`/rest/*`,
`/cmd/*`, `/set/*`) rather than the documented integration API. That is a
compatibility risk, not a cost one, but it is the same set of endpoints these
counts are taken against, so a firmware change can move both at once.

### Unit 2: CPU per tool call (measured, stub)

**0.25 ms of process CPU time per call**, averaged over 2,400 consecutive
`list_networks` calls in one process, tracing off.

Stub-backend number, so it excludes any CPU the controller spends and includes
none of the time this process spends idle waiting on a socket. It is the cost of
the server's own work, and it is small enough that the practical limit on
throughput is the controller, not this container.

### Unit 3: Memory per tool call (measured, stub)

**No measurable peak RSS growth across those 2,400 calls.**

Worth stating explicitly because MCP servers on this fleet have leaked before,
badly enough to be worth a memory note of its own: the historical leak was in
per-session state, and the current protocol revision removed sessions entirely.
Steady-state RSS with no growth over a few thousand calls is the evidence that
the tool path itself holds nothing.

This is not a substitute for watching container memory over weeks. It rules out
a fast leak in the request path, not a slow one somewhere else.

### Unit 4: Audit disk per tool call (measured, stub)

The audit log is the only thing a call leaves behind permanently, so it is a
real cost with a real bill: disk, and eventually rotation.

Measured over 15,601 records written during the benchmark run: **median 1,031
bytes per record, mean 1,105 bytes**. Per tool, median bytes per record:

| Tool | Bytes per audit record |
|---|---|
| `list_devices` | 3,546 |
| `list_clients` | 2,007 |
| `list_networks` | 1,031 |
| `get_site_health` | 730 |
| `create_vlan` (`dry_run=true`) | 713 |
| `get_wan_status` | 492 |
| `list_wlans` | 476 |
| `list_firewall_rules` | 465 |

At roughly 1 KB per call, 10,000 tool calls is about 10 MB. A chatty agent
polling `list_clients` every minute writes on the order of 1 MB a day.

**These are stub record sizes and they understate production.** The audit record
embeds the tool's full result, and a real site returns more clients, more
devices, and wider records than the stub's fixture state. Treat the shape of the
table as correct (the result payload dominates, so the biggest reads cost the
most disk) and the absolute values as a floor. Measure your own with
`wc -c audit.jsonl` after a day.

If that matters, the sink is configurable: `MCP_UNIFI_AUDIT_SINK=syslog` hands
retention to something that already does rotation properly.

### Reproducing all of it

```bash
python scripts/measure_tool_cost.py
```

Prints JSON. The tracing-overhead section is skipped with a note if the `otel`
extra is not installed; everything else runs with the normal dev dependencies.

---

## 8. Example collector configuration

**This is an example, not a supported deployment.** It is self-contained, it is
not tested in CI, and it is here so you have somewhere to start rather than
because this exact stack is recommended.

`otel-collector.example.yaml`:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318

processors:
  batch:
    timeout: 5s
  # Drop the client_id if you would rather not have caller identity leave the
  # host. Everything else on the span is non-identifying by construction.
  # attributes:
  #   actions:
  #     - key: mcp.tool.client_id
  #       action: delete

exporters:
  debug:
    verbosity: normal

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [debug]
```

Point the server at it:

```bash
export MCP_UNIFI_OTEL_ENABLED=true
export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
```

Four queries worth building a dashboard from, in whatever query language your
backend uses:

1. **Refusals by control and caller.** Group spans with `mcp.tool.denied_by`
   present by that attribute and by `mcp.tool.client_id`. This is the
   dashboard panel that replaces a refusal alert.
2. **Write attempts versus previews.** Count spans where
   `mcp.tool.mutates = true`, split by whether `mcp.tool.dry_run` is true. A
   healthy agent previews far more than it applies.
3. **Server overhead percentiles**, filtered to `mcp.server.stub_mode = false`
   so a demo deployment cannot pollute the production distribution. This is the
   SLI for SLO 2.
4. **Errors by tool**, grouped by `mcp.tool.error_type`, which is the signal
   that a firmware change moved an endpoint.
