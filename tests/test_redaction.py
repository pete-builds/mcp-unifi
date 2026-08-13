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
    "x_authkey",  # device: management/inform key
    "x_inform_authkey",  # device: inform auth key (some firmware)
    "x_vwirekey",  # device: vwire (wireless mesh uplink) key
    "x_ssh_sha512passwd",  # device: stored SSH password hash
    "pass_code",  # access visitor: the code that opens the door
    "passcode",  # access visitor (alternate spelling)
    "api_key",
    "X-API-Key",  # the header spelling; api_key does not contain it
    "auth_token",
    "client_secret",
]

# Fields that look adjacent to a secret but are references, labels, or
# booleans. Redacting any of these is a bug: callers resolve them. Each entry
# is the concrete near-miss that ruled out a broader pattern — see the
# rejected-candidates list in ``mcp_unifi.redaction``.
NON_SECRET_KEYS = [
    # ruled out a bare ``radius`` pattern
    "radiusprofile_id",
    "radius_profile_name",
    # ruled out ``key`` / ``_key``
    "setting_key",  # echoed by every set_* preview envelope
    "public_key",  # WireGuard peer public key — the caller needs it
    "keys_added",  # guest-portal diff
    "keys_lost",
    # ruled out a bare ``auth`` pattern (hence ``authkey``)
    "auth",  # guest portal: "none" / "hotspot"
    "auth_required",
    # ruled out a bare ``pin`` pattern
    "pin_length",  # access credential: digits in the PIN, not the PIN
    "mapping",  # substring-matches "pin" straight through the middle
    # ruled out a bare ``code`` pattern (hence the exact pass-code spellings)
    "status_code",
    "country_code",
    # identity and shape
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


def test_redact_covers_a_full_device_record() -> None:
    """A device record's credentials matched no pattern at all until 0.19.3.

    This is the failure mode worth naming: ``list_devices`` could have been
    wrapped in ``redact`` and the diff would have looked like a fix, while
    ``x_authkey`` and ``x_vwirekey`` went out in cleartext exactly as before —
    ``psk``, ``secret``, ``token``, ``private_key`` and the rest all miss both
    spellings. Wiring without a matching pattern is a no-op that reads as
    coverage.
    """
    record = {
        "_id": "6501f0a1b2c3d4e5f6a7b8c9",
        "mac": "f4:e2:c6:00:00:02",
        "name": "Garage AP",
        "model": "U6PRO",
        "type": "uap",
        "state": 1,
        "x_authkey": "device-authkey-do-not-leak",
        "x_vwirekey": "device-vwirekey-do-not-leak",
        "x_ssh_sha512passwd": "device-passwd-hash-do-not-leak",
        "x_fingerprint": "aa:bb:cc:dd",
    }

    out = redact(record)

    for key in ("x_authkey", "x_vwirekey", "x_ssh_sha512passwd"):
        assert out[key] == REDACTED_OUTPUT, f"{key} was not redacted"

    # Identity and inventory fields survive; this is redaction, not a drop.
    assert out["mac"] == "f4:e2:c6:00:00:02"
    assert out["name"] == "Garage AP"
    assert out["model"] == "U6PRO"
    assert out["state"] == 1
    # A fingerprint identifies a key without disclosing it, so it stays.
    assert out["x_fingerprint"] == "aa:bb:cc:dd"
    assert "do-not-leak" not in repr(out)


def test_redact_covers_the_api_key_header_spelling() -> None:
    """``api_key`` does not contain ``api-key``, and the docstring said it did.

    Found by the same sweep as the device keys: enumerate every literal dict
    key in ``src/`` and ask which credential-shaped ones ``is_sensitive``
    misses. Request headers are not emitted through a tool response today, so
    this is not a live disclosure — but the log and audit scrubbers run the
    same predicate, and a header dict reaching either of them through an
    exception or an ``extra={}`` would have gone out intact. A pattern list
    whose own docstring overstates it is the failure mode this whole pass is
    about.
    """
    headers = {
        "X-API-Key": "controller-api-key-do-not-leak",
        "X-CSRF-Token": "csrf-do-not-leak",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    out = redact(headers)

    assert out["X-API-Key"] == REDACTED_OUTPUT
    assert out["X-CSRF-Token"] == REDACTED_OUTPUT  # already covered by "token"
    # Non-credential headers are untouched.
    assert out["Content-Type"] == "application/json"
    assert out["Accept"] == "application/json"
    assert "do-not-leak" not in repr(out)


def test_redact_leaves_the_settings_section_name_alone() -> None:
    """``setting_key`` is why there is no ``key`` pattern.

    Every ``set_*`` preview envelope echoes ``{"setting_key": "teleport"}``.
    A ``key`` or ``_key`` pattern would redact that, and the preview would
    stop telling the caller which settings section it was about to write.
    """
    preview = {
        "setting_key": "guest_access",
        "patch": {"auth": "none", "x_password": "portal-password-do-not-leak"},
    }

    out = redact(preview)

    assert out["setting_key"] == "guest_access"
    assert out["patch"]["auth"] == "none"
    assert out["patch"]["x_password"] == REDACTED_OUTPUT
    assert "do-not-leak" not in repr(out)


def test_scrub_uses_the_audit_sentinel() -> None:
    """The audit path keeps ``***`` for backward compatibility."""
    out = scrub({"x_ipsec_pre_shared_key": "leak"})
    assert out["x_ipsec_pre_shared_key"] == REDACTED
