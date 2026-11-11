"""A 2xx response whose body is not JSON is a UniFiError, from every client.

Each client called ``resp.json()`` on a successful response with no guard, so a
login page served with a 200, a reverse proxy's own page or a truncated reply
escaped as a raw ``JSONDecodeError``. No tool handler catches that, so it
surfaced as a framework error instead of the error envelope every other
failure gets.

Each case drives the real request method through respx, so a client that goes
back to a bare ``resp.json()`` fails its own case. The body carries a token-like
string to prove the error reports content type and size only, and never copies
the body (an HTML page cannot be key-redacted, and a proxy page can echo
request headers).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import pytest
import respx

from mcp_unifi.clients.access import AccessClient
from mcp_unifi.clients.errors import UniFiError, parse_json_body
from mcp_unifi.clients.integration import IntegrationWrites
from mcp_unifi.clients.protect import ProtectClient
from mcp_unifi.clients.unifi import UniFiClient

ECHOED = "X-API-Key: sk-echoed-by-the-proxy-9f8e7d"
PAGE = f"<html><body>UniFi OS login {ECHOED}</body></html>"

Call = Callable[[], Awaitable[Any]]


def _unifi() -> UniFiClient:
    return UniFiClient(host="gw.test", api_key="k", verify_ssl=False)


CASES: list[tuple[str, Callable[[], tuple[Any, Call]], str]] = []


def _case(name: str, expect: str):
    def deco(make: Callable[[], tuple[Any, Call]]) -> Callable[[], tuple[Any, Call]]:
        CASES.append((name, make, expect))
        return make

    return deco


@_case("network legacy", "UniFi GET /api/s/default/stat/sta")
def _legacy() -> tuple[Any, Call]:
    c = _unifi()
    return c, lambda: c._get("/stat/sta")


@_case("network v2", "UniFi GET (v2) /trafficrules")
def _v2() -> tuple[Any, Call]:
    c = _unifi()
    return c, lambda: c._v2_request("GET", "/trafficrules")


@_case("network apgroups", "UniFi GET apgroups")
def _apgroups() -> tuple[Any, Call]:
    c = _unifi()
    return c, c.list_ap_groups


@_case("integration", "UniFi Integration GET /sites")
def _integration() -> tuple[Any, Call]:
    c = _unifi()
    w = IntegrationWrites(c)
    return c, lambda: w._request("GET", "/sites")


@_case("protect", "Protect GET /cameras")
def _protect() -> tuple[Any, Call]:
    c = ProtectClient(host="gw.test", api_key="k")
    return c, c.list_cameras


@_case("access", "Access GET /doors")
def _access() -> tuple[Any, Call]:
    c = AccessClient(host="gw.test", api_key="k")
    return c, c.list_doors


@pytest.mark.parametrize(
    ("make", "expect"),
    [pytest.param(m, e, id=n) for n, m, e in CASES],
)
async def test_non_json_2xx_raises_unifi_error_naming_call_status_and_shape(
    make: Callable[[], tuple[Any, Call]], expect: str
) -> None:
    with respx.mock(assert_all_called=True) as router:
        router.route().mock(
            return_value=httpx.Response(200, text=PAGE, headers={"content-type": "text/html"})
        )
        owner, call = make()
        try:
            with pytest.raises(UniFiError) as caught:
                await call()
        finally:
            await owner.aclose()
    message = str(caught.value)
    assert expect in message
    assert "returned 200" in message
    assert "not JSON" in message
    assert "text/html" in message
    assert f"{len(PAGE.encode())} bytes" in message
    # Shape only: nothing from the body, including what a proxy echoed.
    assert ECHOED not in message
    assert "sk-echoed" not in message
    assert "login" not in message


def test_every_json_decode_site_has_a_case() -> None:
    """Six sites parse a body; a new one must add its own case here."""
    assert len(CASES) == 6


def test_parse_json_body_passes_valid_json_through() -> None:
    resp = httpx.Response(200, json={"data": [1, 2]})
    assert parse_json_body(resp, "UniFi GET /x") == {"data": [1, 2]}


def test_parse_json_body_reports_a_missing_content_type_and_binary_bytes() -> None:
    resp = httpx.Response(202, content=b"\xff\xfe\x00not json")
    with pytest.raises(UniFiError, match=r"returned 202 .*\(unknown, 11 bytes\)"):
        parse_json_body(resp, "Access GET /y")
