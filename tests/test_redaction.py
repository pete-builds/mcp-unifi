"""Regression tests for :mod:`mcp_unifi.redaction`.

Two things are pinned here, and they fail for different reasons if the
hardening regresses:

1. **Pattern coverage.** ``SENSITIVE_KEY_PATTERNS`` is matched by substring, so
   ``psk`` catches ``wpa_psk`` and misses ``x_ipsec_pre_shared_key`` entirely —
   the spelling has to be listed explicitly. The negative case matters just as
   much: ``radiusprofile_id`` is a *reference*, and a bare ``radius`` pattern
   would redact it and break every tool that resolves a RADIUS profile by id.

2. **Wiring.** ``redact`` is inert unless a read path calls it. The per-tool
   tests live next to their modules (``tests/network/`` and ``tests/access/``);
   what is asserted here is the rule those tests enforce.
"""

from __future__ import annotations

import pytest

from mcp_unifi.redaction import (
    REDACTED,
    REDACTED_OUTPUT,
    is_sensitive,
    redact,
    scrub,
)

# Field names taken from real UniFi controller records. The comment on each is
# the record type it appears on, because "is this a real field" is the question
# a reader will have first.
SECRET_KEYS = [
    "x_passphrase",  # wlanconf: WPA pre-shared key
    "x_ipsec_pre_shared_key",  # networkconf: site-to-site IPsec PSK
    "x_preshared_key",  # networkconf: WireGuard peer pre-shared key
    "x_private_key",  # networkconf: WireGuard server private key
    "x_secret",  # radiusprofile: RADIUS shared secret
    "radius_secret",  # networkconf: RADIUS secret on a VPN network
    "wpa_psk",  # wlanconf (legacy spelling)
    "x_password",  # dynamicdns: provider password
    "api_key",
    "auth_token",
    "client_secret",
]

# Fields that look adjacent to a secret but are references, labels, or
# booleans. Redacting any of these is a bug: callers resolve them.
NON_SECRET_KEYS = [
    "radiusprofile_id",
    "radius_profile_name",
    "x_ipsec_esp_dh_group",
    "wpa_mode",
    "security",
    "name",
    "_id",
    "vpn_type",
    "networkconf_id",
    "enabled",
]


@pytest.mark.parametrize("key", SECRET_KEYS)
def test_is_sensitive_matches_secret_keys(key: str) -> None:
    assert is_sensitive(key) is True
    assert is_sensitive(key.upper()) is True, "matching must be case-insensitive"


@pytest.mark.parametrize("key", NON_SECRET_KEYS)
def test_is_sensitive_leaves_references_alone(key: str) -> None:
    assert is_sensitive(key) is False


def test_redact_covers_a_full_vpn_network_record() -> None:
    """The record shape that motivated this: a site-to-site + WireGuard network.

    Before the fix this returned every key intact except ``x_private_key``:
    ``psk`` does not appear in ``x_ipsec_pre_shared_key`` or
    ``x_preshared_key``, so both went out in cleartext.
    """
    record = {
        "_id": "6501f0a1b2c3d4e5f6a7b8c9",
        "name": "Site-to-Site",
        "purpose": "site-vpn",
        "vpn_type": "ipsec-vpn",
        "x_ipsec_pre_shared_key": "ipsec-psk-do-not-leak",
        "x_preshared_key": "wireguard-psk-do-not-leak",
        "x_private_key": "wireguard-private-do-not-leak",
        "x_secret": "radius-shared-secret-do-not-leak",
        "radius_secret": "radius-secret-do-not-leak",
        "radiusprofile_id": "6501aaaabbbbccccdddd0001",
        "enabled": True,
    }

    out = redact(record)

    for key in (
        "x_ipsec_pre_shared_key",
        "x_preshared_key",
        "x_private_key",
        "x_secret",
        "radius_secret",
    ):
        assert out[key] == REDACTED_OUTPUT, f"{key} was not redacted"

    # References and identity survive untouched.
    assert out["radiusprofile_id"] == "6501aaaabbbbccccdddd0001"
    assert out["name"] == "Site-to-Site"
    assert out["vpn_type"] == "ipsec-vpn"
    assert out["enabled"] is True

    # And no secret value survives anywhere in the structure.
    assert "do-not-leak" not in repr(out)


def test_redact_walks_nested_and_listed_records() -> None:
    """Read paths hand back lists of records and section-grouped dicts."""
    payload = {
        "controller": "default",
        "networks": [
            {"name": "A", "x_ipsec_pre_shared_key": "leak-a"},
            {"name": "B", "x_preshared_key": "leak-b"},
        ],
        "vpn": {"x_private_key": "leak-c"},
        "raw": ({"x_secret": "leak-d"},),
    }

    out = redact(payload)

    assert out["networks"][0]["x_ipsec_pre_shared_key"] == REDACTED_OUTPUT
    assert out["networks"][1]["x_preshared_key"] == REDACTED_OUTPUT
    assert out["vpn"]["x_private_key"] == REDACTED_OUTPUT
    assert out["raw"][0]["x_secret"] == REDACTED_OUTPUT
    assert isinstance(out["raw"], tuple)
    assert "leak" not in repr(out)


def test_redact_does_not_mutate_its_input() -> None:
    record = {"x_preshared_key": "still-here"}
    redact(record)
    assert record["x_preshared_key"] == "still-here"


def test_scrub_uses_the_audit_sentinel() -> None:
    """The audit path keeps ``***`` for backward compatibility."""
    out = scrub({"x_ipsec_pre_shared_key": "leak"})
    assert out["x_ipsec_pre_shared_key"] == REDACTED
