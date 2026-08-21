"""Measure per-tool-call latency and cost for mcp-unifi.

Everything ``docs/operations.md`` states as a measured number comes out of this
script, so the numbers there can be reproduced and re-derived when the code
changes. Run it from the repo root::

    python scripts/measure_tool_cost.py

It reports three things, from two different harnesses, and the distinction
between them is the whole point:

1. **Latency, stub backend.** The server answering from its in-memory stub
   state, with no network anywhere in the path. This bounds *the server's own
   overhead*: dispatch, validation, the audit write, redaction, JSON
   serialisation. It says nothing whatsoever about how long a real UniFi
   controller takes to answer. Reported at p50/p90/p99/max.

2. **Tracing overhead, stub backend.** The same measurement with tracing off,
   with tracing on against a real in-process SDK exporter, so the cost of the
   feature is a measured delta rather than an assertion. Requires the ``otel``
   extra; skipped with a printed note if it is not installed.

3. **Controller HTTP requests per tool call, real backend against a mocked
   transport.** A ``respx`` catch-all counts the HTTP requests each tool
   actually issues to the controller. This is a real count of real request
   objects; only the wire and the controller are simulated.

Nothing here estimates. If a number cannot be measured it is not printed.
"""

from __future__ import annotations

import asyncio
import json
import os
import resource
import statistics
import time
from typing import Any

import httpx
import respx

os.environ.setdefault("MCP_UNIFI_AUDIT_SINK", "file")
os.environ.setdefault("MCP_UNIFI_AUDIT_PATH", "/tmp/mcp-unifi-bench-audit.jsonl")  # noqa: S108

from mcp_unifi import telemetry
from mcp_unifi.clients.stubs import make_stub_state
from mcp_unifi.clients.unifi import UniFiClient
from mcp_unifi.config import Settings
from mcp_unifi.server import build_server

ITERATIONS = 300
WARMUP = 20

#: Representative of the three shapes of work the server does: a plain list, a
#: read that composes several backend calls, and a write in preview mode.
CASES: list[tuple[str, dict[str, Any]]] = [
    ("list_networks", {}),
    ("list_clients", {}),
    ("list_devices", {}),
    ("list_firewall_rules", {}),
    ("get_site_health", {}),
    ("get_wan_status", {}),
    ("list_wlans", {}),
    (
        "create_vlan",
        {"name": "bench", "vlan_id": 999, "subnet": "10.99.0.1/24", "dry_run": True},
    ),
]


def _settings() -> Settings:
    return Settings(
        stub_mode=True,
        log_format="text",
        mcp_transport="stdio",
        auth_required=False,
    )


def _pct(values: list[float], q: float) -> float:
    ordered = sorted(values)
    idx = min(len(ordered) - 1, round(q * (len(ordered) - 1)))
    return ordered[idx]


def _summarise(name: str, samples: list[float]) -> dict[str, Any]:
    return {
        "tool": name,
        "n": len(samples),
        "p50_ms": round(statistics.median(samples), 3),
        "p90_ms": round(_pct(samples, 0.90), 3),
        "p99_ms": round(_pct(samples, 0.99), 3),
        "max_ms": round(max(samples), 3),
        "mean_ms": round(statistics.fmean(samples), 3),
    }


async def _time_tool(server: Any, name: str, args: dict[str, Any], n: int) -> list[float]:
    for _ in range(WARMUP):
        await server.call_tool(name, dict(args))
    samples: list[float] = []
    for _ in range(n):
        start = time.perf_counter()
        await server.call_tool(name, dict(args))
        samples.append((time.perf_counter() - start) * 1000.0)
    return samples


async def latency_stub() -> list[dict[str, Any]]:
    telemetry.reset_tracer()
    rows: list[dict[str, Any]] = []
    for name, args in CASES:
        server = build_server(_settings(), stub=make_stub_state())
        rows.append(_summarise(name, await _time_tool(server, name, args, ITERATIONS)))
    return rows


async def cpu_and_memory_per_call() -> dict[str, Any]:
    """CPU seconds and peak RSS growth across a fixed batch of calls."""
    telemetry.reset_tracer()
    server = build_server(_settings(), stub=make_stub_state())
    for _ in range(WARMUP):
        await server.call_tool("list_networks", {})
    rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    cpu_before = time.process_time()
    calls = ITERATIONS * len(CASES)
    for _ in range(calls):
        await server.call_tool("list_networks", {})
    cpu_ms = (time.process_time() - cpu_before) * 1000.0
    rss_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return {
        "calls": calls,
        "cpu_ms_per_call": round(cpu_ms / calls, 4),
        "peak_rss_growth_bytes": _rss_bytes(rss_after - rss_before),
        "peak_rss_growth_bytes_per_call": round(_rss_bytes(rss_after - rss_before) / calls, 1),
    }


def _rss_bytes(raw: int) -> int:
    """``ru_maxrss`` is kilobytes on Linux and bytes on macOS."""
    return raw if os.uname().sysname == "Darwin" else raw * 1024


async def tracing_overhead() -> dict[str, Any] | None:
    """Delta between tracing off and tracing on with a real in-process SDK."""
    try:
        from opentelemetry import trace as ot_trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import (
            BatchSpanProcessor,
            SpanExporter,
            SpanExportResult,
        )
    except ImportError:
        return None

    class CountingExporter(SpanExporter):  # type: ignore[misc]
        def __init__(self) -> None:
            self.count = 0

        def export(self, spans: Any) -> Any:
            self.count += len(list(spans))
            return SpanExportResult.SUCCESS

        def shutdown(self) -> None:
            return None

    telemetry.reset_tracer()
    server = build_server(_settings(), stub=make_stub_state())
    off = await _time_tool(server, "list_networks", {}, ITERATIONS)

    exporter = CountingExporter()
    provider = TracerProvider()
    provider.add_span_processor(BatchSpanProcessor(exporter))
    ot_trace.set_tracer_provider(provider)
    os.environ[telemetry.ENV_ENABLED] = "true"
    telemetry.reset_tracer()
    assert telemetry.get_tracer() is not None
    server = build_server(_settings(), stub=make_stub_state())
    on = await _time_tool(server, "list_networks", {}, ITERATIONS)
    provider.force_flush()
    os.environ.pop(telemetry.ENV_ENABLED, None)
    telemetry.reset_tracer()

    return {
        "off": _summarise("list_networks (tracing off)", off),
        "on": _summarise("list_networks (tracing on, SDK + batch exporter)", on),
        "p50_delta_ms": round(statistics.median(on) - statistics.median(off), 4),
        "spans_exported": exporter.count,
    }


async def controller_requests_per_call() -> list[dict[str, Any]]:
    """Count real HTTP requests each tool issues, with the wire mocked."""
    counted: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        counted.append(f"{request.method} {request.url.path}")
        return httpx.Response(200, json={"meta": {"rc": "ok"}, "data": []})

    rows: list[dict[str, Any]] = []
    settings = Settings(
        stub_mode=False,
        log_format="text",
        mcp_transport="stdio",
        auth_required=False,
        unifi_host="127.0.0.1",
        unifi_api_key="bench-key",
        unifi_verify_ssl=False,
    )
    read_cases = [(n, a) for n, a in CASES if not n.startswith("create_")]
    with respx.mock(assert_all_called=False) as mock:
        mock.route().mock(side_effect=handler)
        for name, args in read_cases:
            client = UniFiClient(host="127.0.0.1", api_key="bench-key", verify_ssl=False)
            server = build_server(settings, unifi=client)
            counted.clear()
            await server.call_tool(name, dict(args))
            rows.append(
                {
                    "tool": name,
                    "controller_http_requests": len(counted),
                    "paths": sorted(set(counted)),
                }
            )
            await client.aclose()
    return rows


async def main() -> None:
    report: dict[str, Any] = {
        "iterations_per_tool": ITERATIONS,
        "warmup_per_tool": WARMUP,
        "python": os.sys.version.split()[0],
        "platform": f"{os.uname().sysname} {os.uname().machine}",
        "latency_stub_backend_ms": await latency_stub(),
        "cpu_and_memory": await cpu_and_memory_per_call(),
        "tracing_overhead": await tracing_overhead(),
        "controller_http_requests_per_call": await controller_requests_per_call(),
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
