"""Tests for ``mcp_unifi.clients.mac``: one normal form for every MAC lookup."""

from __future__ import annotations

import pytest

from mcp_unifi.clients.mac import is_mac, normalize_mac, same_mac


@pytest.mark.parametrize(
    "typed",
    [
        "f4:e2:c6:00:00:02",
        "F4:E2:C6:00:00:02",
        "f4-e2-c6-00-00-02",
        "F4-E2-C6-00-00-02",
        "f4e2.c600.0002",
        "F4E2C6000002",
        "  f4:e2:c6:00:00:02\n",
    ],
)
def test_every_common_form_normalises_to_the_controller_form(typed: str) -> None:
    assert normalize_mac(typed) == "f4:e2:c6:00:00:02"
    assert is_mac(typed)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "not-a-mac",
        "f4:e2:c6:00:00",  # five octets
        "f4:e2-c6:00:00:02",  # mixed separators
        "f4:e2:c6:00:00:0g",  # not hex
        "f4e2c600000",  # eleven digits
    ],
)
def test_anything_else_is_only_trimmed_and_lowered(value: str) -> None:
    assert normalize_mac(value) == value.strip().lower()
    # is_mac and normalize_mac share their patterns: whatever is not
    # reshaped is not a MAC, so a tool refuses it instead of finding nothing.
    assert not is_mac(value)


def test_same_mac() -> None:
    assert same_mac("f4:e2:c6:00:00:02", "F4-E2-C6-00-00-02")
    assert not same_mac("f4:e2:c6:00:00:02", "f4:e2:c6:00:00:03")
    # Two empty values are not "the same device".
    assert not same_mac("", "")
    assert not same_mac(None, "")
