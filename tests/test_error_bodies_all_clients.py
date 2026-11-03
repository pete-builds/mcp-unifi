"""Every controller client describes a failed response without echoing it.

``test_error_bodies.py`` pinned the helper on the one call site that used it
(``apgroups``). Seven other raise sites, across the Network legacy and v2
paths, the Integration API, Protect, and Access, still pasted
``resp.text[:300]`` into the error. A controller that echoes a rejected record
back would put its secret into the tool result and the audit log.

Each case drives the real request method through respx with an error body
that carries both a usable error code and a secret, then checks the code
survives and the secret does not. A case fails if its raise site goes back to
raw body text.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import pytest
import respx

from mcp_unifi.clients.access import AccessClient
from mcp_unifi.clients.errors import UniFiError, describe_error_body
from mcp_unifi.clients.integration import IntegrationWrites
from mcp_unifi.clients.protect import ProtectClient
from mcp_unifi.clients.unifi import UniFiClient

SECRET = "hunter2-wpa-passphrase-do-not-leak"

#: Shapes each API really returns on a 4xx, each echoing a secret-bearing record.
LEGACY_BODY = {
    "meta": {"rc": "error", "msg": "api.err.InvalidPayload"},
    "data": [{"name": "Home", "x_passphrase": SECRET}],
}
V2_BODY = {
    "code": "api.err.TrafficRuleInvalid",
    "message": "bad rule",
    "rule": {"x_passphrase": SECRET},
}
INTEGRATION_BODY = {
    "statusCode": 400,
    "code": "api.request.argument-type-mismatch",
    "message": "invalid value",
    "echo": {"passphrase": SECRET},
}
PROTECT_BODY = {"error": "Camera not adopted", "camera": {"password": SECRET}}
ACCESS_BODY = {"message": "door locked", "credential": {"pin_code": SECRET}}

Call = Callable[[], Awaitable[Any]]


def _json(status: int, body: dict[str, Any]) -> httpx.Response:
    return httpx.Response(
        status, content=json.dumps(body).encode(), headers={"content-type": "application/json"}
    )


async def _raise_message(
    make: Callable[[], tuple[Any, Call]], status: int, body: dict[str, Any]
) -> str:
    with respx.mock(assert_all_called=True) as router:
        router.route().mock(return_value=_json(status, body))
        owner, call = make()
        try:
            with pytest.raises(UniFiError) as caught:
                await call()
        finally:
            await owner.aclose()
    return str(caught.value)


def _unifi() -> UniFiClient:
    return UniFiClient(host="gw.test", api_key="k", verify_ssl=False)


CASES: list[tuple[str, Callable[[], tuple[Any, Call]], int, dict[str, Any], str]] = []


def _case(name: str, status: int, body: dict[str, Any], expect: str):
    def deco(make: Callable[[], tuple[Any, Call]]) -> Callable[[], tuple[Any, Call]]:
        CASES.append((name, make, status, body, expect))
        return make

    return deco


@_case("network legacy", 400, LEGACY_BODY, "api.err.InvalidPayload")
def _legacy() -> tuple[Any, Call]:
    c = _unifi()
    return c, lambda: c._request("PUT", "/rest/wlanconf/abc", json={"x": 1})


@_case("network v2", 400, V2_BODY, "api.err.TrafficRuleInvalid")
def _v2() -> tuple[Any, Call]:
    c = _unifi()
    return c, lambda: c._v2_request("POST", "/trafficrules", json={"x": 1})


@_case("integration 4xx", 400, INTEGRATION_BODY, "api.request.argument-type-mismatch")
def _integration_4xx() -> tuple[Any, Call]:
    c = _unifi()
    w = IntegrationWrites(c)
    return c, lambda: w._request("POST", "/sites/x/networks", json={"x": 1})


@_case("integration 5xx", 500, INTEGRATION_BODY, "invalid value")
def _integration_5xx() -> tuple[Any, Call]:
    c = _unifi()
    w = IntegrationWrites(c)
    return c, lambda: w._request("POST", "/sites/x/networks", json={"x": 1})


@_case("protect json", 400, PROTECT_BODY, "Camera not adopted")
def _protect() -> tuple[Any, Call]:
    c = ProtectClient(host="gw.test", api_key="k")
    return c, lambda: c._request("PATCH", "/cameras/abc", json={"x": 1})


@_case("protect bytes", 400, PROTECT_BODY, "Camera not adopted")
def _protect_bytes() -> tuple[Any, Call]:
    c = ProtectClient(host="gw.test", api_key="k")
    return c, lambda: c._request_bytes("GET", "/cameras/abc/snapshot")


@_case("access", 400, ACCESS_BODY, "door locked")
def _access() -> tuple[Any, Call]:
    c = AccessClient(host="gw.test", api_key="k")
    return c, lambda: c._request("PUT", "/doors/abc", json={"x": 1})


@pytest.mark.parametrize(
    ("make", "status", "body", "expect"),
    [pytest.param(m, s, b, e, id=n) for n, m, s, b, e in CASES],
)
async def test_raise_site_keeps_the_code_and_drops_the_echo(
    make: Callable[[], tuple[Any, Call]], status: int, body: dict[str, Any], expect: str
) -> None:
    message = await _raise_message(make, status, body)
    assert expect in message
    assert f"returned {status}" in message
    assert SECRET not in message
    assert "x_passphrase" not in message


def test_every_raise_site_has_a_case() -> None:
    """Seven sites were fixed; a new client must add its own case here."""
    assert len(CASES) == 7


def test_v2_and_integration_join_code_and_message() -> None:
    resp = httpx.Response(400, json={"code": "api.err.X", "message": "why"})
    assert describe_error_body(resp) == ": api.err.X: why"


def test_json_with_no_known_field_reports_shape_only() -> None:
    resp = httpx.Response(400, json={"echo": {"x_passphrase": SECRET}})
    detail = describe_error_body(resp)
    assert SECRET not in detail
    assert "application/json" in detail


def test_a_record_under_a_message_key_is_not_echoed() -> None:
    """A controller that puts a record where the message goes is not echoed."""
    resp = httpx.Response(400, json={"error": {"x_passphrase": SECRET}})
    assert SECRET not in describe_error_body(resp)
