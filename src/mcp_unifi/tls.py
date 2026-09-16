"""Certificate pinning for self-signed UniFi consoles.

Why this exists
---------------
UniFi consoles ship a self-signed certificate. Probed live against a
UCG-Fiber on 2026-09-16: subject and issuer are both ``CN=unifi.local``, and
the Subject Alternative Name lists ``unifi.local``, ``localhost`` and the
loopback addresses only, never the LAN address the server actually connects
to. So ordinary TLS verification cannot succeed against such a console even
with the certificate trusted: hostname matching fails before the chain is
considered. That is why ``verify_ssl`` defaults to ``false`` (ADR 0003) and
why the accepted cost there is a LAN man-in-the-middle on the API key.

Pinning removes the trade-off instead of picking a side of it. The operator
fetches the console's certificate once, out of band, with
``mcp-unifi-pin-cert`` and records it beside the controllers YAML. From then
on that certificate is the **only** trust anchor for that controller and the
pin is the identity: chain verification is required, hostname matching is
off because the pin already answers the question a hostname would. A
console presenting any other certificate fails the handshake, closed.

What this deliberately does not do
----------------------------------
* The server never fetches and trusts a certificate itself. Trust-on-first-use
  inside a long-running process is a silent decision; the bootstrap is an
  explicit command an operator runs and can compare against the console.
* There is no fallback. A pinned controller whose certificate changed (a
  firmware update can regenerate it) fails every request with a message that
  names the re-pin command. ADR 0003 rejects silent downgrade outright.
"""

from __future__ import annotations

import hashlib
import socket
import ssl
from pathlib import Path

#: Marker OpenSSL puts in every verification failure message.
_VERIFY_FAILED = "CERTIFICATE_VERIFY_FAILED"

#: The operator command that records a console certificate. Named in error
#: messages so a rotated certificate is a one-line fix, not a search.
PIN_COMMAND = "mcp-unifi-pin-cert"


def fingerprint_sha256(der: bytes) -> str:
    """Return the SHA-256 fingerprint of a DER certificate as lowercase hex."""
    return hashlib.sha256(der).hexdigest()


def format_fingerprint(hex_digest: str) -> str:
    """Render a hex digest as the colon-separated form OpenSSL prints."""
    upper = hex_digest.upper()
    return ":".join(upper[i : i + 2] for i in range(0, len(upper), 2))


def normalise_fingerprint(value: str) -> str:
    """Accept either fingerprint form and return lowercase hex without colons."""
    return value.replace(":", "").strip().lower()


def load_pinned_cert(path: Path, label: str) -> bytes:
    """Read a PEM certificate and return its DER bytes.

    Every failure is a ``ValueError`` naming ``label`` and the path: a pin
    that cannot be read must fail startup, because a controller silently
    running without the pin it was configured with is the outcome pinning
    exists to prevent.
    """
    if not path.is_file():
        raise ValueError(f"{label}: {path} does not exist or is not a regular file")
    try:
        pem = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"{label}: {path} cannot be read ({type(exc).__name__})") from exc
    if not pem.strip():
        raise ValueError(f"{label}: {path} is empty")
    try:
        return ssl.PEM_cert_to_DER_cert(pem)
    except ValueError as exc:
        raise ValueError(f"{label}: {path} is not a PEM certificate") from exc


def build_pinned_context(path: Path, label: str = "pinned_cert") -> ssl.SSLContext:
    """Build a client TLS context whose only trust anchor is the pinned certificate.

    ``verify_mode`` is ``CERT_REQUIRED`` and the system trust store is not
    loaded, so the console must present the pinned certificate, or one it
    signs. ``VERIFY_X509_PARTIAL_CHAIN`` lets the pinned leaf act as the
    anchor even when it is not marked as a CA, which a self-signed console
    certificate is not. ``check_hostname`` is off: the certificate's SAN does
    not carry the LAN address (see the module docstring) and the pin is a
    stronger identity claim than a name match against a self-issued name.
    """
    load_pinned_cert(path, label)  # fail early, with the same message shape
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    ctx.load_verify_locations(cafile=str(path))
    return ctx


def fetch_server_certificate(host: str, port: int, timeout: float = 10.0) -> bytes:
    """Fetch the leaf certificate a server presents, without verifying it.

    For the bootstrap command only. Verification is off here by definition:
    this is the one moment the operator looks at the certificate and decides
    to trust it, and the fingerprint printed alongside is what they compare.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with (
        socket.create_connection((host, port), timeout=timeout) as raw,
        ctx.wrap_socket(raw, server_hostname=host) as tls,
    ):
        der = tls.getpeercert(binary_form=True)
    if not der:
        raise ValueError(f"{host}:{port} presented no certificate")
    return der


def is_verification_failure(exc: BaseException) -> bool:
    """True when ``exc`` or anything in its cause chain is a TLS verification failure."""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, ssl.SSLCertVerificationError) or _VERIFY_FAILED in str(current):
            return True
        current = current.__cause__ or current.__context__
    return False


#: Short form for surfaces with a length budget (probe results are cut at 200
#: characters). Same instruction, fewer words.
SHORT_VERIFY_HINT = (
    "TLS verification failed: the console's certificate does not match the pin. "
    f"Check its fingerprint and re-pin with {PIN_COMMAND} --force."
)


def verification_failure_message(service: str, url: str) -> str:
    """The error an operator sees when a controller's certificate does not match.

    Names the re-pin command rather than suggesting ``verify_ssl: false``,
    because the two outcomes of a mismatch are a rotated console certificate
    (re-pin after checking the new fingerprint) and an interception (do not
    connect). Lowering verification serves neither.
    """
    return (
        f"{service} TLS verification failed for {url}. If this controller is pinned and "
        f"the console's certificate changed (a firmware update can regenerate it), check "
        f"the new fingerprint on the console and re-pin with `{PIN_COMMAND} <host> --out "
        f"<pinned_cert path> --force`. If it is not pinned, the certificate does not "
        f"match the system trust store. Do not lower verify_ssl to get past this."
    )


__all__ = [
    "PIN_COMMAND",
    "SHORT_VERIFY_HINT",
    "build_pinned_context",
    "fetch_server_certificate",
    "fingerprint_sha256",
    "format_fingerprint",
    "is_verification_failure",
    "load_pinned_cert",
    "normalise_fingerprint",
    "verification_failure_message",
]
