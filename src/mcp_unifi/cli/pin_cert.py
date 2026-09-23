"""Record a UniFi console's certificate so the server can pin it.

Usage::

    mcp-unifi-pin-cert 192.168.1.1 --out /etc/mcp-unifi/pins/home.pem
    mcp-unifi-pin-cert 192.168.1.1 --out home.pem --expect-fingerprint 4F:DA:DB:...
    mcp-unifi-pin-cert 192.168.1.1 --out home.pem --force     # console cert rotated

This is the whole bootstrap for certificate pinning, and it is deliberately
a command an operator runs rather than something the server does on its
first connection. Trust-on-first-use inside a long-running process is a
silent decision made by whichever process happened to start first; this
command prints the fingerprint so the operator can compare it against the
console before the file is written, and refuses to replace an existing pin
unless told to.

Exit codes: ``0`` written, ``1`` refused (file exists without ``--force``, or
the fingerprint did not match ``--expect-fingerprint``), ``2`` the console
could not be reached or presented no certificate. Nothing is written on a
non-zero exit.
"""

from __future__ import annotations

import argparse
import ssl
import sys
from collections.abc import Sequence
from pathlib import Path

from mcp_unifi.tls import (
    fetch_server_certificate,
    fingerprint_sha256,
    format_fingerprint,
    normalise_fingerprint,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-unifi-pin-cert",
        description=(
            "Fetch a UniFi console's TLS certificate, print its SHA-256 fingerprint, "
            "and write it as PEM for the controller's pinned_cert setting."
        ),
    )
    parser.add_argument("host", help="Console IP or hostname (what the server connects to).")
    parser.add_argument("--port", type=int, default=443, help="TLS port (default 443).")
    parser.add_argument(
        "--out", type=Path, required=True, help="Where to write the PEM. Refuses to overwrite."
    )
    parser.add_argument("--force", action="store_true", help="Replace an existing file at --out.")
    parser.add_argument(
        "--expect-fingerprint",
        default="",
        help=(
            "SHA-256 fingerprint you read off the console, hex with or without colons. "
            "The file is written only if the presented certificate matches."
        ),
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="Connect timeout in seconds.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    out: Path = args.out

    if out.exists() and not args.force:
        print(
            f"refusing to overwrite {out}; pass --force if the console's certificate "
            f"has changed and you have checked the new fingerprint",
            file=sys.stderr,
        )
        return 1

    try:
        der = fetch_server_certificate(args.host, args.port, timeout=args.timeout)
    except (OSError, ValueError) as exc:  # ssl.SSLError is an OSError
        print(f"could not fetch a certificate from {args.host}:{args.port}: {exc}", file=sys.stderr)
        return 2

    digest = fingerprint_sha256(der)
    print(f"host:        {args.host}:{args.port}")
    print(f"sha256:      {format_fingerprint(digest)}")
    print(f"der bytes:   {len(der)}")

    if args.expect_fingerprint:
        expected = normalise_fingerprint(args.expect_fingerprint)
        if expected != digest:
            print(
                "fingerprint mismatch: the console presented a certificate that does not "
                "match --expect-fingerprint. Nothing written. If you are not expecting a "
                "new certificate, do not trust this connection.",
                file=sys.stderr,
            )
            return 1

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(ssl.DER_cert_to_PEM_cert(der), encoding="utf-8")
    print(f"written:     {out}")
    print(f"next:        set pinned_cert: {out} on this controller (or UNIFI_PINNED_CERT)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
