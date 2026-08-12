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

Coverage, stated honestly
-------------------------
This module supplies the rule. It cannot enforce it: nothing here intercepts a
tool response, so a read path is covered only when its module calls
:func:`redact` on the way out. The first pass wired exactly two modules
(``wlans`` and ``dynamic_dns``) while this docstring already spoke as though
reads were redacted by default, so ``list_networks``, ``get_network_details``,
``backup_config``, and the Access credential reads kept handing back raw
controller records — WireGuard ``x_private_key``, site-to-site
``x_ipsec_pre_shared_key``, and RADIUS ``x_secret`` among them. Credit to
Adrian Birzu (@adibirzu) for finding that gap.

Callers are now wired module by module and each one is pinned by a test in
``tests/test_redaction.py``. The invariant to preserve when adding a read tool:
**if it returns a controller record, it calls** :func:`redact`. Projections
(fixed key allowlists) are not an excuse to skip it — an allowlist that grows
later is a leak that ships quietly.
"""

from __future__ import annotations

from typing import Any

#: Substrings (case-insensitive) that mark a dict key as sensitive. A key
#: matches if any pattern is a substring of the lowercased key. This catches
#: ``api_key``, ``X-API-Key``, ``unifi_api_key``, ``passphrase``,
#: ``x_passphrase``, ``password``, ``x_password``, ``Password``,
#: ``auth_token``, ``Bearer``-style ``token`` keys, ``client_secret``,
#: RADIUS/PSK material (``x_secret``, ``wpa_psk``, ``radius_secret``), the
#: site-to-site IPsec key (``x_ipsec_pre_shared_key``) and the WireGuard peer
#: key (``x_preshared_key``) alongside ``x_private_key``.
#:
#: Substring matching is the whole mechanism, and it cuts both ways. ``psk``
#: catches ``wpa_psk`` but does **not** catch ``x_ipsec_pre_shared_key`` or
#: ``x_preshared_key``, because neither contains the literal three letters —
#: hence the two explicit spellings below. In the other direction, a bare
#: ``radius`` pattern is deliberately absent: it would swallow
#: ``radiusprofile_id`` and RADIUS profile names, which are references and
#: labels, not secrets, and redacting them would break the tools that resolve
#: them. Add a pattern only when it names a value, never a reference.
SENSITIVE_KEY_PATTERNS: frozenset[str] = frozenset(
    {
        "passphrase",
        "x_passphrase",
        "api_key",
        "password",
        "secret",
        "token",
        "psk",
        "pre_shared_key",
        "preshared_key",
        "privkey",
        "private_key",
    }
)

#: Sentinel written in place of a redacted value on **output** paths.
#: Deliberately human-readable: a caller seeing this should understand the
#: value was withheld on purpose, not that the field is empty or unset.
REDACTED_OUTPUT = "[REDACTED]"

#: Sentinel used on the audit-log path. Kept distinct for backward
#: compatibility with existing audit records and their tests.
REDACTED = "***"


def is_sensitive(key: str) -> bool:
    """True when ``key`` names a field whose value must never be emitted."""
    lowered = key.lower()
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


__all__ = [
    "REDACTED",
    "REDACTED_OUTPUT",
    "SENSITIVE_KEY_PATTERNS",
    "is_sensitive",
    "redact",
    "scrub",
]
