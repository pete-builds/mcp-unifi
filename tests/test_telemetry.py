"""Tests for the optional OpenTelemetry span emitted around every tool call.

The suite runs against whatever the normal dev lockfile installs, and adds
**nothing** for tracing. Checked while writing these tests:
``opentelemetry-api==1.44.0`` is already in ``requirements.lock`` and
``requirements-dev.lock``, pulled in transitively by ``fastmcp-slim``. The SDK
and the OTLP exporter are not, and neither is a tracer provider, so the API
hands back a no-op tracer and nothing is ever exported.

That shapes the tests two ways. The "library is missing" path is **simulated**
by making ``importlib.import_module`` raise, rather than relying on the
package being absent, because relying on absence would be a test of the
environment rather than of the code. And the "library is present" path is
tested twice: once against the real API (proving the genuine call shape works
and exports nothing without a provider), and once against a recording fake
injected via :func:`mcp_unifi.telemetry.set_tracer`, which is the only way to
assert what a span actually carries without installing an SDK and an
in-memory exporter.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from mcp_unifi import telemetry
from mcp_unifi.clients.stubs import StubState
from mcp_unifi.config import Settings
from mcp_unifi.modules._audit import audited
from mcp_unifi.server import build_server

# ---------------------------------------------------------------------------
# Recording fake
# ---------------------------------------------------------------------------


class FakeSpan:
    def __init__(self, name: str) -> None:
        self.name = name
        self.attributes: dict[str, Any] = {}
        self.status: Any = None

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value

    def set_status(self, status: Any) -> None:
        self.status = status


class FakeTracer:
    """Minimal stand-in for an OpenTelemetry tracer."""

    def __init__(self) -> None:
        self.spans: list[FakeSpan] = []

    @contextmanager
    def start_as_current_span(self, name: str, **_kwargs: Any) -> Iterator[FakeSpan]:
        span = FakeSpan(name)
        self.spans.append(span)
        yield span

    def only(self) -> FakeSpan:
        assert len(self.spans) == 1, f"expected exactly one span, got {len(self.spans)}"
        return self.spans[0]


class ExplodingTracer:
    """Tracer whose span creation always fails, standing in for a broken SDK."""

    def start_as_current_span(self, name: str, **_kwargs: Any) -> Any:
        raise RuntimeError("exporter is on fire")


@pytest.fixture()
def tracer() -> Iterator[FakeTracer]:
    fake = FakeTracer()
    telemetry.set_tracer(fake)
    yield fake
    telemetry.reset_tracer()


def _settings(*, readonly: bool = False) -> Settings:
    return Settings(
        stub_mode=True,
        log_format="text",
        mcp_transport="stdio",
        auth_required=False,
        readonly=readonly,
    )


# ---------------------------------------------------------------------------
# Optionality: the whole reason this module is shaped the way it is
# ---------------------------------------------------------------------------


def test_tracing_is_off_by_default() -> None:
    """No env var set means no tracer, so every span is the null span."""
    telemetry.reset_tracer()
    assert telemetry.is_enabled({}) is False
    assert telemetry.get_tracer() is None


def test_enabling_without_the_packages_installed_is_not_fatal(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The failure mode a downstream operator hits: flag on, library absent.

    The absence is simulated rather than relied on, because
    ``opentelemetry-api`` happens to arrive transitively via ``fastmcp`` in
    this project's lockfile. Simulating it means the test asserts the code
    path instead of asserting a property of whatever happens to be installed
    today, which is exactly the sort of accidental pass that stops being a
    test the moment a transitive dependency shifts.
    """
    telemetry.reset_tracer()
    monkeypatch.setenv(telemetry.ENV_ENABLED, "true")

    real_import = telemetry.importlib.import_module

    def no_opentelemetry(name: str, *a: Any, **k: Any) -> Any:
        if name.startswith("opentelemetry"):
            raise ImportError(f"No module named {name!r}")
        return real_import(name, *a, **k)

    monkeypatch.setattr(telemetry.importlib, "import_module", no_opentelemetry)
    with caplog.at_level(logging.WARNING, logger="mcp_unifi.telemetry"):
        assert telemetry.get_tracer() is None
    assert any("opentelemetry" in r.message.lower() for r in caplog.records)
    telemetry.reset_tracer()


@pytest.mark.asyncio
async def test_tools_still_work_when_opentelemetry_cannot_be_imported(
    monkeypatch: pytest.MonkeyPatch, stub_state: StubState
) -> None:
    """Enabled flag plus a missing library must degrade, not fail."""
    telemetry.reset_tracer()
    monkeypatch.setenv(telemetry.ENV_ENABLED, "true")
    real_import = telemetry.importlib.import_module

    def no_opentelemetry(name: str, *a: Any, **k: Any) -> Any:
        if name.startswith("opentelemetry"):
            raise ImportError(f"No module named {name!r}")
        return real_import(name, *a, **k)

    monkeypatch.setattr(telemetry.importlib, "import_module", no_opentelemetry)
    server = build_server(_settings(), stub=stub_state)
    result = await server.call_tool("list_networks", {})
    assert json.loads(result.content[0].text)
    telemetry.reset_tracer()


@pytest.mark.asyncio
async def test_real_opentelemetry_api_with_no_sdk_exports_nothing_and_still_works(
    monkeypatch: pytest.MonkeyPatch, stub_state: StubState
) -> None:
    """Smoke the genuine OpenTelemetry API, not the fake.

    ``opentelemetry-api`` is present transitively, so this exercises the real
    ``get_tracer`` and the real span object. With no SDK and no tracer
    provider installed, the API hands back a no-op tracer: spans are created,
    attributes are accepted, and nothing is exported anywhere. That is the
    state a default deployment is in, and it must be indistinguishable from
    tracing being off as far as the caller is concerned.
    """
    pytest.importorskip("opentelemetry.trace")
    telemetry.reset_tracer()
    monkeypatch.setenv(telemetry.ENV_ENABLED, "true")
    tracer = telemetry.get_tracer()
    assert tracer is not None
    server = build_server(_settings(), stub=stub_state)
    result = await server.call_tool("list_networks", {})
    assert json.loads(result.content[0].text)
    telemetry.reset_tracer()


def test_the_import_is_attempted_once_not_per_call(monkeypatch: pytest.MonkeyPatch) -> None:
    """A server without OpenTelemetry pays one failed import, not one per call."""
    telemetry.reset_tracer()
    monkeypatch.setenv(telemetry.ENV_ENABLED, "true")
    calls: list[str] = []
    real_import = telemetry.importlib.import_module

    def counting_import(name: str, *a: Any, **k: Any) -> Any:
        if name.startswith("opentelemetry"):
            calls.append(name)
        return real_import(name, *a, **k)

    monkeypatch.setattr(telemetry.importlib, "import_module", counting_import)
    for _ in range(5):
        telemetry.get_tracer()
    assert len(calls) <= 1
    telemetry.reset_tracer()


@pytest.mark.asyncio
async def test_a_tool_behaves_identically_with_tracing_off(stub_state: StubState) -> None:
    telemetry.reset_tracer()
    server = build_server(_settings(), stub=stub_state)
    result = await server.call_tool("list_networks", {})
    assert json.loads(result.content[0].text)


@pytest.mark.asyncio
async def test_a_broken_tracer_does_not_break_a_tool_call(stub_state: StubState) -> None:
    """An observability failure must never become a tool failure."""
    telemetry.set_tracer(ExplodingTracer())
    try:
        server = build_server(_settings(), stub=stub_state)
        result = await server.call_tool("list_networks", {})
        assert json.loads(result.content[0].text)
    finally:
        telemetry.reset_tracer()


# ---------------------------------------------------------------------------
# What a span actually carries
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_tool_span_attributes(tracer: FakeTracer, stub_state: StubState) -> None:
    server = build_server(_settings(), stub=stub_state)
    await server.call_tool("list_networks", {})
    span = tracer.only()
    assert span.name == telemetry.SPAN_NAME_PREFIX + "list_networks"
    assert span.attributes[telemetry.ATTR_TOOL] == "list_networks"
    assert span.attributes[telemetry.ATTR_MUTATES] is False
    assert span.attributes[telemetry.ATTR_CONTROLLER] == "default"
    assert span.attributes[telemetry.ATTR_OUTCOME] == telemetry.OUTCOME_OK
    assert span.attributes[telemetry.ATTR_STUB_MODE] is True
    # A read tool has no preview mode, so the attribute is absent rather than
    # false. Absence is the signal.
    assert telemetry.ATTR_DRY_RUN not in span.attributes
    assert telemetry.ATTR_DENIED_BY not in span.attributes


@pytest.mark.asyncio
async def test_write_tool_span_records_mutates_and_dry_run(
    tracer: FakeTracer, stub_state: StubState
) -> None:
    server = build_server(_settings(), stub=stub_state)
    await server.call_tool(
        "create_vlan",
        {"name": "span-test", "vlan_id": 77, "subnet": "10.77.0.1/24", "dry_run": True},
    )
    span = tracer.only()
    assert span.attributes[telemetry.ATTR_MUTATES] is True
    assert span.attributes[telemetry.ATTR_DRY_RUN] is True
    assert span.attributes[telemetry.ATTR_OUTCOME] == telemetry.OUTCOME_OK


@pytest.mark.asyncio
async def test_readonly_refusal_is_queryable_on_the_span(
    tracer: FakeTracer, stub_state: StubState
) -> None:
    """The interesting query: which calls did a control refuse, and which one."""
    server = build_server(_settings(readonly=True), stub=stub_state)
    await server.call_tool("delete_vlan", {"network_id": "whatever"})
    span = tracer.only()
    assert span.attributes[telemetry.ATTR_DENIED_BY] == "readonly"
    assert span.attributes[telemetry.ATTR_OUTCOME] == telemetry.OUTCOME_REFUSED
    assert span.attributes[telemetry.ATTR_MUTATES] is True


@pytest.mark.asyncio
async def test_tool_exception_records_type_but_not_message(tracer: FakeTracer) -> None:
    """Exception messages are free-form and can echo caller input; drop them."""

    @audited("exploding_probe", mutates=False)
    async def exploding_probe() -> str:
        raise ValueError("secret-looking detail nobody should export")

    with pytest.raises(ValueError):
        await exploding_probe()

    span = tracer.only()
    assert span.attributes[telemetry.ATTR_OUTCOME] == telemetry.OUTCOME_ERROR
    assert span.attributes[telemetry.ATTR_ERROR_TYPE] == "ValueError"
    joined = " ".join(str(v) for v in span.attributes.values())
    assert "secret-looking detail" not in joined


# ---------------------------------------------------------------------------
# Redaction: a span is an emission path like any other
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_argument_ever_reaches_a_span(tracer: FakeTracer, stub_state: StubState) -> None:
    """The strongest form of the guarantee: args are not on the span at all.

    ``create_wlan`` carries a WPA passphrase. The audit log scrubs it. The span
    never receives it in the first place, which is a stronger property than
    scrubbing because it cannot be defeated by a field name the scrubber has
    not seen.
    """
    passphrase = "correct-horse-battery-staple"
    server = build_server(_settings(), stub=stub_state)
    await server.call_tool(
        "create_wlan",
        {
            "name": "span-wlan",
            "passphrase": passphrase,
            "network_id": "net-1",
            "dry_run": True,
        },
    )
    span = tracer.only()
    joined = " ".join(f"{k}={v}" for k, v in span.attributes.items())
    assert passphrase not in joined
    assert "span-wlan" not in joined


def test_a_sensitive_attribute_key_is_refused(
    tracer: FakeTracer, caplog: pytest.LogCaptureFixture
) -> None:
    """Fail closed if a future call site tries to put a secret on a span."""
    with (
        telemetry.tool_span("probe", mutates=False) as span,
        caplog.at_level(logging.WARNING, logger="mcp_unifi.telemetry"),
    ):
        recorded = span.set("mcp.tool.x_passphrase", "hunter2")
    assert recorded is False
    assert "mcp.tool.x_passphrase" not in tracer.only().attributes
    assert any("sensitive span attribute" in r.message for r in caplog.records)


def test_non_scalar_values_are_dropped_not_stringified(tracer: FakeTracer) -> None:
    """Stringifying is how a payload sneaks onto a span. Drop instead."""
    with telemetry.tool_span("probe", mutates=False) as span:
        assert span.set("mcp.tool.payload", {"x_passphrase": "hunter2"}) is False
        assert span.set("mcp.tool.records", [{"a": 1}]) is False
        assert span.set("mcp.tool.count", 3) is True
    assert "mcp.tool.payload" not in tracer.only().attributes
    assert "mcp.tool.records" not in tracer.only().attributes
    assert tracer.only().attributes["mcp.tool.count"] == 3


def test_none_values_are_absent_rather_than_stringified(tracer: FakeTracer) -> None:
    with telemetry.tool_span("probe", mutates=False, denied_by=None) as span:
        assert span.enabled is True
    assert telemetry.ATTR_DENIED_BY not in tracer.only().attributes


def test_null_span_accepts_every_call() -> None:
    """The disabled path must expose the same surface, so call sites never branch."""
    assert telemetry.NULL_SPAN.enabled is False
    assert telemetry.NULL_SPAN.set(telemetry.ATTR_TOOL, "x") is False
    telemetry.NULL_SPAN.set_many({telemetry.ATTR_TOOL: "x"})
    telemetry.NULL_SPAN.record_error(ValueError("nope"))


def test_coerce_dry_run_refuses_to_guess() -> None:
    assert telemetry.coerce_dry_run(True) is True
    assert telemetry.coerce_dry_run(False) is False
    assert telemetry.coerce_dry_run(None) is None
    assert telemetry.coerce_dry_run("true") is None
    assert telemetry.coerce_dry_run(1) is None
