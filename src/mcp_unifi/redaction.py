"""Canonical secret-redaction rules, shared by every path that emits data.

Why this module exists
----------------------
Redaction used to live inside :mod:`mcp_unifi.audit` and
:mod:`mcp_unifi.logging_setup`, which meant it covered exactly two paths:
the audit log and log records. The **read path was never covered**. So
``list_wlans`` returned every SSID's ``x_passphrase`` in cleartext to the
caller, and ``list_dynamic_dns`` returned provider ``x_password`` values —
while ``update_wlan``'s docstring promised "passphrases are redacted in the
response" and ``list_dynamic_dns``'s promised the password "comes back
redacted". Both promises were false, in a public repository.

The underlying defect was structural: redaction was treated as a *logging*
concern rather than an *output* concern. This module is the single source of
truth for both, so a fix in one place covers every emitter.

Threat model note: the caller here is an LLM, and tool output frequently ends
up in transcripts, logs, and context windows that outlive the request. A WPA
pre-shared key that reaches any of those is disclosed. There is no read path
that legitimately needs a cleartext secret.

Coverage, and where it is enforced
----------------------------------
This module supplies the rule. For a long time it could not enforce it:
nothing intercepted a tool response, so a read path was covered only when its
module called :func:`redact` on the way out. The first pass wired exactly two
modules (``wlans`` and ``dynamic_dns``) while this docstring already spoke as
though reads were redacted by default, so ``list_networks``,
``get_network_details``, ``backup_config``, and the Access credential reads
kept handing back raw controller records — WireGuard ``x_private_key``,
site-to-site ``x_ipsec_pre_shared_key``, and RADIUS ``x_secret`` among them.
Credit to Adrian Birzu (@adibirzu) for finding that gap. Two more rounds of
per-tool wiring followed, and a stub-mode sweep still found 24 Network tools
returning records unredacted.

The rule is now applied in one place: ``modules.network._common.format_json``,
the serialiser every module's tools return through, calls :func:`redact` on
every response. A new tool is covered before its author thinks about it, and a
record type that grows a secret field on a newer firmware (issue #124's
OpenVPN keys) is covered the day it appears. The single deliberate exception
is the preview-then-confirm ``token``, restored after redaction by
``_pending.format_preview_envelope`` because the caller must hand it back.
``tests/test_output_redaction.py`` sweeps every callable tool and fails on the
first leak. The per-tool :func:`redact` calls that already exist stay: the
walk is idempotent and they document which records are known to carry
secrets.

Two failure modes, not one
--------------------------
The wiring gap above is the visible one. The second is quieter and worse: a
tool can call :func:`redact` on a record whose secret field matches no pattern,
and the call is a no-op that *reads* as coverage. Device records were exactly
that — ``x_authkey`` and ``x_vwirekey`` are credentials that ``psk``,
``secret``, ``token`` and the rest all miss, so wrapping ``list_devices``
alone would have changed nothing while looking fixed in the diff. The same
held for the Access visitor ``pass_code``.

So a redaction change is only finished when both halves are checked: the read
path calls :func:`redact`, **and** ``SENSITIVE_KEY_PATTERNS`` actually matches
the field. The test for a new redaction must fail before the change for the
right reason — if it would have passed with the pattern alone, or with the
wiring alone, it is not testing what it claims to.

Write paths count as emitters
-----------------------------
A ``dry_run`` preview echoes the payload the caller supplied, and a create
returns the record the controller echoes back. Both carry the passphrase the
caller just typed straight into the transcript, which is where it outlives the
request. ``wlans`` redacts both; the ``composites`` module now does the same,
including the ``partial`` record surfaced when a composite rolls back.
"""

from __future__ import annotations

import re
from typing import Any

#: Substrings (case-insensitive) that mark a dict key as sensitive. A key
#: matches if any pattern is a substring of the lowercased key. This catches
#: ``api_key``, ``X-API-Key``, ``unifi_api_key``, ``passphrase``,
#: ``x_passphrase``, ``password``, ``x_password``, ``Password``,
#: ``auth_token``, ``Bearer``-style ``token`` keys, ``client_secret``,
#: RADIUS/PSK material (``x_secret``, ``wpa_psk``, ``radius_secret``), the
#: site-to-site IPsec key (``x_ipsec_pre_shared_key``) and the WireGuard peer
#: key (``x_preshared_key``) alongside ``x_private_key``, the device
#: management and mesh keys (``x_authkey``, ``x_inform_authkey``,
#: ``x_vwirekey``), the ``passwd`` spelling of a stored password, the
#: Access visitor pass code in both its spellings, and the five OpenVPN key
#: fields a ``remote-user-vpn`` network record carries (``x_ca_key``,
#: ``x_server_key``, ``x_dh_key``, ``x_shared_client_key``, ``x_auth_key``).
#:
#: The OpenVPN spellings were reported from a live two-controller UniFi OS
#: 5.1 deployment (issue #124): ``list_networks`` handed back the complete
#: OpenVPN PKI, CA private key included, because none of the five contains
#: ``private_key``, ``privkey``, ``psk`` or any other listed substring. Note
#: ``x_auth_key`` with an underscore is a different spelling from the device
#: ``x_authkey`` and matches neither ``authkey`` nor the rejected ``auth``.
#: The certificate fields beside them (``x_ca_crt``, ``x_server_crt``) are
#: public material and stay visible.
#:
#: Substring matching is the whole mechanism, and it cuts both ways. ``psk``
#: catches ``wpa_psk`` but does **not** catch ``x_ipsec_pre_shared_key`` or
#: ``x_preshared_key``, because neither contains the literal three letters —
#: hence the two explicit spellings below. ``password`` likewise does not
#: catch ``passwd``, and ``pass_code`` does not catch ``passcode``. Every
#: spelling a controller actually uses has to be written out. ``api_key``
#: likewise does not catch the ``X-API-Key`` header spelling — this docstring
#: claimed it did, and was wrong for as long as it has existed — so
#: ``api-key`` is listed alongside it.
#:
#: In the other direction, patterns that would swallow references are
#: deliberately absent, and each one below was a real candidate rejected
#: against a real near-miss in this codebase:
#:
#: * ``radius`` → would redact ``radiusprofile_id`` and RADIUS profile names.
#: * ``key`` or ``_key`` → would redact ``setting_key`` (the settings-section
#:   name echoed by every ``set_*`` preview), ``keys_added``/``keys_lost`` in
#:   the guest-portal diff, and the WireGuard ``public_key``, which is not a
#:   secret and is exactly what a caller needs to configure a peer.
#: * ``auth`` → would redact the guest-portal ``auth`` mode (``"none"``,
#:   ``"hotspot"``) and ``auth_required``. Hence ``authkey``, not ``auth``.
#: * ``pin`` → would redact ``pin_length`` on an Access credential, and
#:   substring-matches straight through ``mapping``.
#: * ``code`` → would redact ``status_code``, ``country_code``, and every
#:   other ``*_code`` field. Hence the two exact pass-code spellings.
#:
#: Add a pattern only when it names a value, never a reference.
SENSITIVE_KEY_PATTERNS: frozenset[str] = frozenset(
    {
        "passphrase",
        "x_passphrase",
        "api_key",
        "api-key",
        "password",
        "passwd",
        "secret",
        "token",
        "psk",
        "pre_shared_key",
        "preshared_key",
        "privkey",
        "private_key",
        "authkey",
        "vwirekey",
        "pass_code",
        "passcode",
        "x_ca_key",
        "x_server_key",
        "x_dh_key",
        "x_shared_client_key",
        "x_auth_key",
    }
)

#: Keys that contain a pattern above but name a flag or a reference, never a
#: value. Checked before the patterns, by exact lowercased match, so the list
#: cannot widen by accident the way a pattern can. Each entry is a real
#: collision the serialiser-level sweep hit, and each is pinned in
#: ``tests/test_redaction.py``:
#:
#: * ``secrets_stripped`` → the ``backup_config`` envelope's boolean saying
#:   whether any secret was stripped. ``secret`` matched it, so the flag
#:   itself came out as ``[REDACTED]`` and ``restore_config`` could not read
#:   it back as a bool.
NON_SECRET_KEYS: frozenset[str] = frozenset({"secrets_stripped"})

#: Sentinel written in place of a redacted value on **output** paths.
#: Deliberately human-readable: a caller seeing this should understand the
#: value was withheld on purpose, not that the field is empty or unset.
REDACTED_OUTPUT = "[REDACTED]"

#: Sentinel used on the audit-log path. Kept distinct for backward
#: compatibility with existing audit records and their tests.
REDACTED = "***"

# Free-form exception/log messages are not dictionaries, so key-based
# redaction cannot protect them. These deliberately conservative patterns
# catch the credential forms most likely to be echoed by HTTP clients while
# preserving ordinary diagnostic text (including stable controller error
# codes). Text is bounded separately by ``sanitize_text``.
_TEXT_SECRET_PATTERNS = (
    re.compile(r"(?i)(bearer\s+)[^\s,;]+"),
    re.compile(
        r"(?i)([\"'](?:api[-_ ]?key|password|passwd|passphrase|secret|token|cookie|"
        r"session[_ -]?id|private[_ -]?key|psk)[\"']\s*[:=]\s*)([\"'])(.*?)(\2)"
    ),
    re.compile(
        r"(?i)((?:api[-_ ]?key|password|passwd|passphrase|secret|token|cookie|"
        r"session[_ -]?id|private[_ -]?key|psk)\s*[:=]\s*)[^\s,;]+"
    ),
)
MAX_TEXT_CHARS = 512
MAX_NESTING = 8
MAX_ITEMS = 100
MAX_STRING_CHARS = 1024


def is_sensitive(key: str) -> bool:
    """True when ``key`` names a field whose value must never be emitted."""
    lowered = key.lower()
    if lowered in NON_SECRET_KEYS:
        return False
    return any(pattern in lowered for pattern in SENSITIVE_KEY_PATTERNS)


def _walk(value: Any, sentinel: str) -> Any:
    if isinstance(value, dict):
        return {
            k: (sentinel if is_sensitive(str(k)) else _walk(v, sentinel)) for k, v in value.items()
        }
    if isinstance(value, list):
        return [_walk(item, sentinel) for item in value]
    if isinstance(value, tuple):
        return tuple(_walk(item, sentinel) for item in value)
    return value


def redact(value: Any, sentinel: str = REDACTED_OUTPUT) -> Any:
    """Recursively redact sensitive values for **output to a caller**.

    Dict values whose key matches :data:`SENSITIVE_KEY_PATTERNS` are replaced
    with ``sentinel``. Lists and tuples are walked element-wise; scalars pass
    through. The returned structure is always a fresh object, so callers may
    mutate it without affecting their input.

    Use this on every tool response that carries controller records. It is
    cheap (a dict walk over a payload already destined for ``json.dumps``) and
    it is the only thing standing between a WPA key and a transcript.
    """
    return _walk(value, sentinel)


def scrub(value: Any) -> Any:
    """Recursively redact sensitive values for the **audit log**.

    Identical traversal to :func:`redact`, but writes the ``"***"`` sentinel
    the audit records have always used.
    """
    return _walk(value, REDACTED)


def sanitize_text(value: object, *, max_chars: int = MAX_TEXT_CHARS) -> str:
    """Scrub credentials from free-form text and impose a hard size bound.

    This is for exception messages and diagnostic text, not structured tool
    responses. Unknown text is retained (bounded) because controller error
    codes are useful; credential-looking assignments are replaced first.
    """
    text = str(value)
    text = _TEXT_SECRET_PATTERNS[0].sub(r"\1[REDACTED]", text)
    text = _TEXT_SECRET_PATTERNS[1].sub(r"\1\2[REDACTED]\4", text)
    text = _TEXT_SECRET_PATTERNS[2].sub(r"\1[REDACTED]", text)
    if len(text) > max_chars:
        return text[:max_chars] + "…"
    return text


def bounded(value: Any, *, sentinel: str = REDACTED) -> Any:
    """Redact and bound arbitrary audit/diagnostic payloads recursively.

    Audit records must remain useful but cannot permit a controller response
    or caller-supplied argument to grow without limit. Containers are capped,
    strings are truncated, and excessive nesting is replaced by a marker.
    """

    def walk(item: Any, depth: int) -> Any:
        if depth > MAX_NESTING:
            return "[TRUNCATED]"
        if isinstance(item, dict):
            output: dict[str, Any] = {}
            for index, (key, child) in enumerate(item.items()):
                if index >= MAX_ITEMS:
                    output["[TRUNCATED_ITEMS]"] = f"{len(item) - MAX_ITEMS} item(s) omitted"
                    break
                text_key = sanitize_text(key, max_chars=128)
                output[text_key] = sentinel if is_sensitive(text_key) else walk(child, depth + 1)
            return output
        if isinstance(item, list):
            return [walk(child, depth + 1) for child in item[:MAX_ITEMS]] + (
                [f"[TRUNCATED_ITEMS: {len(item) - MAX_ITEMS} omitted]"]
                if len(item) > MAX_ITEMS
                else []
            )
        if isinstance(item, tuple):
            return tuple(walk(child, depth + 1) for child in item[:MAX_ITEMS])
        if isinstance(item, str):
            return sanitize_text(item, max_chars=MAX_STRING_CHARS)
        return item

    return walk(value, 0)


__all__ = [
    "NON_SECRET_KEYS",
    "REDACTED",
    "REDACTED_OUTPUT",
    "SENSITIVE_KEY_PATTERNS",
    "bounded",
    "is_sensitive",
    "redact",
    "sanitize_text",
    "scrub",
]
