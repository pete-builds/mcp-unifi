"""``request_with_retry`` and timeouts: never replay a sent write, forward overrides."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator

import httpx
import pytest
import respx

from mcp_unifi.clients.errors import UniFiError
from mcp_unifi.clients.retry import request_with_retry

URL = "https://gateway.test/thing"
LOG = logging.getLogger("test_retry_timeout")


@pytest.fixture
async def http() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(timeout=15.0) as c:
        yield c


async def _call(
    http: httpx.AsyncClient, method: str, timeout: float | httpx.Timeout | None = None
) -> httpx.Response:
    return await request_with_retry(
        http, method, URL, logger=LOG, service="UniFi", error_cls=UniFiError, timeout=timeout
    )


@respx.mock
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
async def test_a_read_timeout_on_a_write_is_not_retried(
    http: httpx.AsyncClient, method: str
) -> None:
    """The request was sent, so the console may have applied it."""
    route = respx.route(method=method, url=URL).mock(side_effect=httpx.ReadTimeout("slow"))
    with pytest.raises(UniFiError):
        await _call(http, method)
    assert route.call_count == 1


@respx.mock
async def test_a_connect_error_is_still_retried_once(http: httpx.AsyncClient) -> None:
    route = respx.post(URL).mock(
        side_effect=[httpx.ConnectError("refused"), httpx.Response(200, json={})]
    )
    assert (await _call(http, "POST")).status_code == 200
    assert route.call_count == 2


@respx.mock
async def test_timeout_override_reaches_the_transport(http: httpx.AsyncClient) -> None:
    route = respx.post(URL).mock(return_value=httpx.Response(200, json={}))
    await _call(http, "POST", timeout=httpx.Timeout(60.0, connect=15.0))
    timeout = route.calls.last.request.extensions["timeout"]
    assert timeout["read"] == 60.0
    assert timeout["connect"] == 15.0


@respx.mock
async def test_no_override_keeps_the_client_default(http: httpx.AsyncClient) -> None:
    route = respx.get(URL).mock(return_value=httpx.Response(200, json={}))
    await _call(http, "GET")
    assert route.calls.last.request.extensions["timeout"]["read"] == 15.0
