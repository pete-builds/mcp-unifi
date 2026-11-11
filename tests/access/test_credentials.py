"""Tests for the credential tools: list_credentials, get_credential, audit_expiring_credentials."""

from __future__ import annotations

import json
import time

from fastmcp import FastMCP

from mcp_unifi.clients.access_stubs import AccessStubState
from tests.access.conftest import _call


async def test_list_credentials_seed_shape(access_registry: FastMCP) -> None:
    credentials = await _call(access_registry, "list_credentials")
    assert isinstance(credentials, list)
    assert len(credentials) == 3
    types = {c["type"] for c in credentials}
    assert types == {"nfc", "pin", "mobile"}


async def test_get_credential_by_id(
    access_registry: FastMCP, stub_access_state: AccessStubState
) -> None:
    cred_id = stub_access_state.credentials[0]["id"]
    cred = await _call(access_registry, "get_credential", {"credential_id": cred_id})
    assert cred["id"] == cred_id
    assert cred["type"] == "nfc"
    assert "card_id" in cred


async def test_get_credential_redacts_the_card_number(
    access_registry: FastMCP, stub_access_state: AccessStubState
) -> None:
    """The NFC card number is what a cloner needs, so it comes back redacted.

    The key stays, so the caller can still see the credential is an NFC card
    with a number on file; the credential's ``id`` is the handle other tools take.
    """
    cred = stub_access_state.credentials[0]
    number = cred["card_id"]
    raw = await access_registry.call_tool("get_credential", {"credential_id": cred["id"]})
    text = raw.content[0].text
    assert number not in text
    assert json.loads(text)["card_id"] == "[REDACTED]"


async def test_get_credential_not_found(access_registry: FastMCP) -> None:
    result = await _call(access_registry, "get_credential", {"credential_id": "nope"})
    assert "error" in result
    assert "not found" in result["error"]


async def test_audit_expiring_credentials_default_window(
    access_registry: FastMCP,
) -> None:
    """30-day default window catches the 5-day-expiring NFC but not the 90-day PIN."""
    result = await _call(access_registry, "audit_expiring_credentials")
    assert result["horizon_days"] == 30
    assert result["count"] == 1
    cred = result["credentials"][0]
    assert cred["type"] == "nfc"
    assert cred["days_until_expiry"] <= 5


async def test_audit_expiring_credentials_wider_window(
    access_registry: FastMCP,
) -> None:
    """100-day window catches both the 5-day NFC and the 90-day PIN."""
    result = await _call(access_registry, "audit_expiring_credentials", {"days_ahead": 100})
    assert result["count"] == 2
    types = {c["type"] for c in result["credentials"]}
    assert types == {"nfc", "pin"}
    # Sorted by expires_at ascending (NFC first)
    assert result["credentials"][0]["type"] == "nfc"


async def test_audit_expiring_credentials_type_filter(access_registry: FastMCP) -> None:
    """Filtering to NFC only excludes the PIN even with a wide window."""
    result = await _call(
        access_registry,
        "audit_expiring_credentials",
        {"days_ahead": 100, "credential_type": "nfc"},
    )
    assert result["count"] == 1
    assert result["credentials"][0]["type"] == "nfc"


async def test_audit_expiring_credentials_excludes_non_expiring(
    access_registry: FastMCP,
) -> None:
    """Mobile credentials with ``expires_at = None`` never appear in the result."""
    result = await _call(access_registry, "audit_expiring_credentials", {"days_ahead": 365 * 10})
    for cred in result["credentials"]:
        assert cred["type"] != "mobile"


async def test_audit_expiring_credentials_invalid_type(access_registry: FastMCP) -> None:
    result = await _call(
        access_registry,
        "audit_expiring_credentials",
        {"credential_type": "biometric"},
    )
    assert "error" in result
    assert "credential_type" in result["error"]


async def test_audit_expiring_credentials_negative_days(access_registry: FastMCP) -> None:
    result = await _call(access_registry, "audit_expiring_credentials", {"days_ahead": -1})
    assert "error" in result
    assert "days_ahead" in result["error"]


async def test_credential_reads_redact_enrolment_material(
    access_registry: FastMCP, stub_access_state: AccessStubState
) -> None:
    """Access credentials are the one Access record type that holds a secret.

    Card and mobile enrolment tokens are the value, not a reference to it: a
    token in a transcript is a credential in a transcript.
    """
    cred = stub_access_state.credentials[0]
    cred["token"] = "nfc-enrolment-token-do-not-leak"
    cred["x_secret"] = "credential-secret-do-not-leak"
    cred_id = cred["id"]

    listed = await _call(access_registry, "list_credentials")
    single = await _call(access_registry, "get_credential", {"credential_id": cred_id})

    for payload in (next(c for c in listed if c["id"] == cred_id), single):
        assert payload["token"] == "[REDACTED]"
        assert payload["x_secret"] == "[REDACTED]"
        # Identity and type still resolve; this is redaction, not a drop.
        assert payload["id"] == cred_id
        assert payload["type"] == "nfc"


async def test_audit_expiring_credentials_redacts_enrolment_material(
    access_registry: FastMCP, stub_access_state: AccessStubState
) -> None:
    """The third credential reader, missed when the other two were wired.

    ``audit_expiring_credentials`` reads ``list_credentials`` off the backend
    rather than calling the tool, so it never picked up that tool's redaction
    and handed back the raw records. A module counting as "covered" because
    its obvious readers are wired is the same failure as a pattern list
    counting as "covered" because it has entries in it.
    """
    cred = stub_access_state.credentials[0]  # the 5-day NFC, inside the window
    cred["token"] = "nfc-enrolment-token-do-not-leak"
    cred["x_secret"] = "credential-secret-do-not-leak"

    result = await _call(access_registry, "audit_expiring_credentials")

    assert result["count"] == 1
    surfaced = result["credentials"][0]
    assert surfaced["token"] == "[REDACTED]"
    assert surfaced["x_secret"] == "[REDACTED]"
    assert "do-not-leak" not in json.dumps(result)
    # The audit is still an audit: identity, type, and the computed countdown
    # all survive.
    assert surfaced["id"] == cred["id"]
    assert surfaced["type"] == "nfc"
    assert surfaced["days_until_expiry"] <= 5


# ---------------------------------------------------------------------------
# Nothing is skipped silently: expired and unreadable expiries get their own lists
# ---------------------------------------------------------------------------

_DAY_MS = 86_400 * 1000


def _now_ms() -> int:
    return int(time.time() * 1000)


async def test_audit_expiring_credentials_reports_already_expired(
    access_registry: FastMCP, stub_access_state: AccessStubState
) -> None:
    expired = stub_access_state.credentials[2]
    expired["expires_at"] = _now_ms() - 2 * _DAY_MS

    result = await _call(access_registry, "audit_expiring_credentials", {"days_ahead": 30})

    # Still only the 5-day NFC is "expiring"; the expired one is not mixed in.
    assert result["count"] == 1
    assert result["already_expired_count"] == 1
    entry = result["already_expired"][0]
    assert entry["id"] == expired["id"]
    assert entry["days_since_expiry"] in (1, 2)


async def test_audit_expiring_credentials_reports_unparseable_expiry(
    access_registry: FastMCP, stub_access_state: AccessStubState
) -> None:
    nfc, pin, mobile = stub_access_state.credentials
    nfc["expires_at"] = "2026-11-12T00:00:00Z"  # a string
    pin["expires_at"] = (_now_ms() + 3 * _DAY_MS) // 1000  # epoch seconds, not ms
    mobile["expires_at"] = True  # a bool is not a timestamp

    result = await _call(access_registry, "audit_expiring_credentials", {"days_ahead": 30})

    assert result["count"] == 0
    assert result["unparseable_expiry_count"] == 3
    by_id = {c["id"]: c for c in result["unparseable_expiry"]}
    assert set(by_id) == {nfc["id"], pin["id"], mobile["id"]}
    assert by_id[nfc["id"]]["expires_at"] == "2026-11-12T00:00:00Z"
    assert by_id[nfc["id"]]["type"] == "nfc"


async def test_audit_expiring_credentials_zero_expiry_is_unparseable_not_expired(
    access_registry: FastMCP, stub_access_state: AccessStubState
) -> None:
    stub_access_state.credentials[0]["expires_at"] = 0

    result = await _call(access_registry, "audit_expiring_credentials", {"days_ahead": 30})

    assert result["already_expired_count"] == 0
    assert [c["id"] for c in result["unparseable_expiry"]] == [
        stub_access_state.credentials[0]["id"]
    ]


async def test_audit_expiring_credentials_accepts_a_float_millisecond_expiry(
    access_registry: FastMCP, stub_access_state: AccessStubState
) -> None:
    cred = stub_access_state.credentials[1]
    cred["expires_at"] = float(_now_ms() + 3 * _DAY_MS)

    result = await _call(access_registry, "audit_expiring_credentials", {"days_ahead": 30})

    assert cred["id"] in {c["id"] for c in result["credentials"]}
    assert result["unparseable_expiry_count"] == 0


async def test_audit_expiring_credentials_counts_non_expiring(access_registry: FastMCP) -> None:
    result = await _call(access_registry, "audit_expiring_credentials", {"days_ahead": 30})
    # The seeded mobile credential has expires_at = None.
    assert result["no_expiry_count"] == 1
    assert result["already_expired"] == []
    assert result["unparseable_expiry"] == []


async def test_audit_expiring_credentials_type_filter_applies_to_every_list(
    access_registry: FastMCP, stub_access_state: AccessStubState
) -> None:
    nfc, pin, _ = stub_access_state.credentials
    nfc["expires_at"] = _now_ms() - _DAY_MS
    pin["expires_at"] = "soon"

    result = await _call(access_registry, "audit_expiring_credentials", {"credential_type": "pin"})

    assert result["already_expired_count"] == 0
    assert [c["id"] for c in result["unparseable_expiry"]] == [pin["id"]]


async def test_audit_expiring_credentials_redacts_the_new_lists(
    access_registry: FastMCP, stub_access_state: AccessStubState
) -> None:
    cred = stub_access_state.credentials[0]
    cred["expires_at"] = _now_ms() - _DAY_MS
    cred["token"] = "expired-token-do-not-leak"

    result = await _call(access_registry, "audit_expiring_credentials")

    assert result["already_expired"][0]["token"] == "[REDACTED]"
    assert "do-not-leak" not in str(result)
