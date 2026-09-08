"""Tests for the shared single-path-segment identifier validator.

Every client method that interpolates a caller-supplied id into a URL path or
query string routes it through :func:`mcp_unifi.clients.ids.path_segment`.
The validator is the one control standing between a free-text tool argument
and the gateway's URL router, so it is pinned here on its own, independently
of any tool.
"""

from __future__ import annotations

import pytest

from mcp_unifi.clients.ids import InvalidIdentifierError, path_segment
from mcp_unifi.clients.unifi import UniFiError


@pytest.mark.parametrize(
    "value",
    [
        "65f0a1b2c3d4e5f6a7b8c9d0",
        "c1",
        "w1",
        "some-id_1.2:3",
        "AA:BB:CC:DD:EE:FF",
        "ips",
        "teleport",
        "a" * 128,
    ],
)
def test_path_segment_accepts_plain_identifiers(value: str) -> None:
    assert path_segment(value, "thing_id") == value


@pytest.mark.parametrize(
    "value",
    [
        "",
        ".",
        "..",
        "../x",
        "a/b",
        "/rest/wlanconf",
        "a?b",
        "a#b",
        "a&b=c",
        "a b",
        "a%2e%2e",
        "a\nb",
        "a\n",
        "a\r\n",
        "a;b",
        "a\\b",
        "a" * 129,
    ],
)
def test_path_segment_rejects_anything_that_could_change_the_route(value: str) -> None:
    with pytest.raises(InvalidIdentifierError) as excinfo:
        path_segment(value, "thing_id")
    assert "thing_id" in str(excinfo.value)
    assert value not in str(excinfo.value) or value == ""


def test_invalid_identifier_is_a_unifi_error() -> None:
    """Tools catch ``UniFiError`` and return an error envelope, so the
    validator's exception has to be one of those or every tool would need a
    second ``except`` clause."""
    assert issubclass(InvalidIdentifierError, UniFiError)
