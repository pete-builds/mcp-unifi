"""Certificate pinning: the pin is the only trust anchor, and it fails closed.

The server under test is a real TLS listener on loopback holding a
self-signed certificate shaped like the one a UniFi console presents
(probed live 2026-09-16: subject and issuer ``CN=unifi.local``, SAN without
the LAN address). That shape matters: it is why plain verification can never
pass against a console and why the pin has to be the identity.
"""

from __future__ import annotations

import http.server
import json
import logging
import ssl
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from mcp_unifi import tls
from mcp_unifi.cli import pin_cert
from mcp_unifi.clients.retry import request_with_retry
from mcp_unifi.clients.unifi import UniFiClient, UniFiError
from mcp_unifi.config import ControllerConfig, Settings
from mcp_unifi.server import build_server

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_cryptography_is_available_to_mint_test_certificates() -> None:
    """These tests mint an ephemeral certificate with ``cryptography``.

    It arrives transitively (fastmcp's auth stack) rather than as a declared
    dev dependency, so if it ever disappears this test names the fix instead
    of the suite silently skipping every pinning test.
    """
    try:
        import cryptography  # noqa: F401
    except ImportError:  # pragma: no cover
        pytest.fail(
            "cryptography is no longer importable; add it to requirements-dev.in and "
            "recompile the lock so the pinning tests keep running"
        )


def _self_signed(cn: str = "unifi.local") -> tuple[bytes, bytes]:
    """A self-signed certificate shaped like a UniFi console's, plus its key.

    No IP entry in the SAN on purpose: the real console lists ``unifi.local``,
    ``localhost`` and loopback names only, so a connection to the LAN
    address can never satisfy hostname matching.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn), x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def _self_signed_ca(cn: str = "UniFi Root CA") -> tuple[bytes, bytes]:
    """Like :func:`_self_signed` but marked CA:TRUE with keyCertSign.

    A pin an operator might plausibly record from a console that fronts its
    own internal CA. Against a trust-anchor-only design this pin would vouch
    for every leaf it signed; the exact-match check is what stops that.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def _signed_by(
    parent_cert_pem: bytes, parent_key_pem: bytes, cn: str = "impostor.local"
) -> tuple[bytes, bytes]:
    """A certificate issued by the pinned certificate's key.

    The attack "hostname checking off, partial chain on" invites: if the
    pinned certificate were accepted as an issuer, anything it signed would
    pass. The child carries its own subject name; with the parent's name
    OpenSSL would treat it as self-signed and refuse it before ever walking
    the chain, which would leave the check under test unexercised.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    parent = x509.load_pem_x509_certificate(parent_cert_pem)
    parent_key = serialization.load_pem_private_key(parent_key_pem, password=None)
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    from cryptography.x509.oid import NameOID

    child = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(parent.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(parent_key, hashes.SHA256())  # type: ignore[arg-type]
    )
    return (
        child.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = json.dumps({"meta": {"rc": "ok"}, "data": []}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_: Any) -> None:  # silence stderr chatter
        return


class _QuietServer(http.server.ThreadingHTTPServer):
    def handle_error(self, request: Any, client_address: Any) -> None:
        # A rejected handshake is the point of half these tests; the stdlib
        # server would print a traceback for each one.
        return


class Console:
    """A loopback TLS server presenting one self-signed certificate."""

    def __init__(
        self,
        tmp_path: Path,
        name: str = "console",
        material: tuple[bytes, bytes] | None = None,
    ) -> None:
        cert_pem, key_pem = material or _self_signed()
        self.cert_path = tmp_path / f"{name}.pem"
        self.cert_path.write_bytes(cert_pem)
        key_path = tmp_path / f"{name}.key"
        key_path.write_bytes(key_pem)
        self.der = ssl.PEM_cert_to_DER_cert(cert_pem.decode())
        self.fingerprint = tls.fingerprint_sha256(self.der)
        self._server = _QuietServer(("127.0.0.1", 0), _Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(self.cert_path), keyfile=str(key_path))
        self._server.socket = ctx.wrap_socket(self._server.socket, server_side=True)
        self.host, self.port = self._server.server_address[:2]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture
def console(tmp_path: Path) -> Iterator[Console]:
    c = Console(tmp_path)
    try:
        yield c
    finally:
        c.close()


@pytest.fixture
def other_pin(tmp_path: Path) -> Path:
    """A different self-signed certificate with the same subject, as a wrong pin."""
    cert_pem, _ = _self_signed()
    path = tmp_path / "other.pem"
    path.write_bytes(cert_pem)
    return path


def _url(console: Console) -> str:
    return f"https://{console.host}:{console.port}/"


# ---------------------------------------------------------------------------
# The pin is the only thing that lets a console connection verify
# ---------------------------------------------------------------------------


async def test_pinned_context_accepts_the_pinned_console(console: Console) -> None:
    ctx = tls.build_pinned_context(console.cert_path)
    async with httpx.AsyncClient(verify=ctx) as client:
        resp = await client.get(_url(console))
    assert resp.status_code == 200


async def test_system_trust_rejects_the_same_console(console: Console) -> None:
    """Control: without the pin, the same server fails verification.

    This is the case ADR 0003 describes, reproduced: a self-signed console
    certificate is not in any trust store, and its SAN does not carry the
    address we dial. The pin is what makes the previous test pass.
    """
    async with httpx.AsyncClient(verify=True) as client:
        with pytest.raises(httpx.ConnectError) as exc:
            await client.get(_url(console))
    assert tls.is_verification_failure(exc.value)


async def test_wrong_pin_is_rejected(console: Console, other_pin: Path) -> None:
    """A certificate with the identical subject but a different key fails closed."""
    ctx = tls.build_pinned_context(other_pin)
    async with httpx.AsyncClient(verify=ctx) as client:
        with pytest.raises(httpx.ConnectError) as exc:
            await client.get(_url(console))
    assert tls.is_verification_failure(exc.value)


async def test_certificate_signed_by_the_pin_is_rejected(tmp_path: Path) -> None:
    """The pin is an identity, not a CA.

    ``VERIFY_X509_PARTIAL_CHAIN`` lets the pinned leaf be the anchor; it must
    not let it be an issuer. The console's certificate carries no CA flag,
    so a certificate signed by its key fails twice over: OpenSSL refuses a
    non-CA issuer, and the exact-match check refuses anything that is not
    the pin. Pinned by test rather than trusted from memory, because this is
    the case the "hostname off" design is asked about first.
    """
    parent_cert, parent_key = _self_signed()
    pin = tmp_path / "parent.pem"
    pin.write_bytes(parent_cert)
    impostor = Console(tmp_path, name="child", material=_signed_by(parent_cert, parent_key))
    try:
        ctx = tls.build_pinned_context(pin)
        async with httpx.AsyncClient(verify=ctx) as client:
            with pytest.raises(httpx.ConnectError) as exc:
                await client.get(_url(impostor))
        assert tls.is_verification_failure(exc.value)
    finally:
        impostor.close()


async def test_ca_capable_pin_cannot_vouch_for_a_leaf_it_signed(tmp_path: Path) -> None:
    """The exact-match check, isolated from OpenSSL's non-CA issuer rule.

    Here the pin IS a CA, so chain validation alone would accept the leaf it
    signed. Only the byte-for-byte comparison after the handshake refuses
    it. This is the test that goes red if that comparison is removed.
    """
    parent_cert, parent_key = _self_signed_ca()
    pin = tmp_path / "ca-pin.pem"
    pin.write_bytes(parent_cert)
    impostor = Console(tmp_path, name="ca-child", material=_signed_by(parent_cert, parent_key))
    try:
        ctx = tls.build_pinned_context(pin)
        async with httpx.AsyncClient(verify=ctx) as client:
            with pytest.raises(httpx.ConnectError) as exc:
                await client.get(_url(impostor))
        assert tls.is_verification_failure(exc.value)
        assert "not the pinned certificate" in str(exc.value)
    finally:
        impostor.close()


async def test_ca_capable_pin_still_accepts_itself(tmp_path: Path) -> None:
    """Control for the test above: the same CA pin, presented directly, passes."""
    material = _self_signed_ca()
    pin = tmp_path / "ca-self.pem"
    pin.write_bytes(material[0])
    server = Console(tmp_path, name="ca-self", material=material)
    try:
        async with httpx.AsyncClient(verify=tls.build_pinned_context(pin)) as client:
            resp = await client.get(_url(server))
        assert resp.status_code == 200
    finally:
        server.close()


def test_multi_certificate_bundle_is_rejected(tmp_path: Path, console: Console) -> None:
    """A bundle would trust every certificate in it while reporting one fingerprint."""
    other_cert, _ = _self_signed()
    bundle = tmp_path / "bundle.pem"
    bundle.write_bytes(console.cert_path.read_bytes() + other_cert)
    with pytest.raises(ValueError, match=r"exactly one certificate \(found 2\)"):
        tls.load_pinned_cert(bundle, "pin")
    with pytest.raises(ValidationError, match="exactly one certificate"):
        ControllerConfig(name="home", host="h", api_key=SecretStr("k"), pinned_cert=bundle)


def test_pinned_context_shape(console: Console) -> None:
    ctx = tls.build_pinned_context(console.cert_path)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is False
    assert ctx.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN
    # Only the pin is loaded: no system roots.
    assert ctx.cert_store_stats()["x509"] == 1


# ---------------------------------------------------------------------------
# Loading a pin: every failure names the label and the path, never contents
# ---------------------------------------------------------------------------


def test_load_missing_pin(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match=r"pin: .*does not exist"):
        tls.load_pinned_cert(tmp_path / "absent.pem", "pin")


def test_load_empty_pin(tmp_path: Path) -> None:
    p = tmp_path / "empty.pem"
    p.write_text("\n\n")
    with pytest.raises(ValueError, match="is empty"):
        tls.load_pinned_cert(p, "pin")


def test_load_garbage_pin(tmp_path: Path) -> None:
    p = tmp_path / "garbage.pem"
    p.write_text("not a certificate")
    with pytest.raises(ValueError, match=r"exactly one certificate \(found 0\)"):
        tls.load_pinned_cert(p, "pin")


def test_load_malformed_pem_body(tmp_path: Path) -> None:
    p = tmp_path / "malformed.pem"
    p.write_text("-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----\n")
    with pytest.raises(ValueError, match="not a PEM certificate"):
        tls.load_pinned_cert(p, "pin")


def test_load_directory_pin(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a regular file"):
        tls.load_pinned_cert(tmp_path, "pin")


def test_fingerprint_forms_round_trip(console: Console) -> None:
    pretty = tls.format_fingerprint(console.fingerprint)
    assert pretty.count(":") == 31
    assert tls.normalise_fingerprint(pretty) == console.fingerprint
    assert tls.normalise_fingerprint(console.fingerprint.upper()) == console.fingerprint


# ---------------------------------------------------------------------------
# Config: pinned_cert turns verification on and contradictions fail startup
# ---------------------------------------------------------------------------


def test_pinned_controller_verifies_by_default(console: Console) -> None:
    c = ControllerConfig(
        name="home", host="192.168.1.1", api_key=SecretStr("k"), pinned_cert=console.cert_path
    )
    assert c.verify_ssl is True
    assert isinstance(c.tls_verify, ssl.SSLContext)
    assert c.pinned_cert_sha256 == console.fingerprint


def test_unpinned_controller_passes_the_plain_flag() -> None:
    c = ControllerConfig(name="lan", host="h", api_key=SecretStr("k"))
    assert c.tls_verify is False
    assert c.pinned_cert_sha256 is None
    assert ControllerConfig(name="x", host="h", api_key=SecretStr("k"), verify_ssl=True).tls_verify


def test_pin_with_verify_off_is_a_contradiction(console: Console) -> None:
    with pytest.raises(ValidationError, match="pinned_cert is set but verify_ssl is false"):
        ControllerConfig(
            name="home",
            host="h",
            api_key=SecretStr("k"),
            pinned_cert=console.cert_path,
            verify_ssl=False,
        )


def test_missing_pin_fails_startup_naming_the_controller(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="controller 'home' pinned_cert"):
        ControllerConfig(
            name="home", host="h", api_key=SecretStr("k"), pinned_cert=tmp_path / "absent.pem"
        )


def test_legacy_env_pin_promotes(monkeypatch: pytest.MonkeyPatch, console: Console) -> None:
    for var in (
        "STUB_MODE",
        "UNIFI_HOST",
        "UNIFI_API_KEY",
        "UNIFI_VERIFY_SSL",
        "UNIFI_PINNED_CERT",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("STUB_MODE", "false")
    monkeypatch.setenv("UNIFI_HOST", "192.168.1.1")
    monkeypatch.setenv("UNIFI_API_KEY", "k")
    monkeypatch.setenv("UNIFI_PINNED_CERT", str(console.cert_path))
    c = Settings().controllers[0]
    assert c.pinned_cert == console.cert_path
    assert c.verify_ssl is True


def test_safe_repr_reports_pin_path_and_fingerprint(console: Console) -> None:
    s = Settings(
        stub_mode=False,
        controllers=[
            ControllerConfig(
                name="home", host="h", api_key=SecretStr("k"), pinned_cert=console.cert_path
            )
        ],
    )
    (ctrl,) = s.safe_repr()["controllers"]  # type: ignore[misc]
    assert ctrl["pinned_cert"] == str(console.cert_path)
    assert ctrl["pinned_cert_sha256"] == console.fingerprint
    assert ctrl["verify_ssl"] is True


def test_pinned_controller_does_not_warn_about_tls(
    console: Console, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING)
    s = Settings(
        stub_mode=False,
        mcp_transport="stdio",
        controllers=[
            ControllerConfig(
                name="home", host="h", api_key=SecretStr("k"), pinned_cert=console.cert_path
            )
        ],
    )
    build_server(s)
    msgs = [r.getMessage() for r in caplog.records if r.name == "mcp_unifi.config"]
    assert len(msgs) == 1  # the inline API key still warns
    assert "TLS verification off" not in msgs[0]
    assert "API key supplied as a value" in msgs[0]


def test_unpinned_warning_names_the_pin_command(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING)
    s = Settings(stub_mode=False, unifi_host="h", unifi_api_key="k", mcp_transport="stdio")
    build_server(s)
    (msg,) = [r.getMessage() for r in caplog.records if r.name == "mcp_unifi.config"]
    assert tls.PIN_COMMAND in msg


# ---------------------------------------------------------------------------
# The real client end to end, and what a mismatch looks like to an operator
# ---------------------------------------------------------------------------


async def test_unifi_client_reads_through_a_pinned_connection(console: Console) -> None:
    client = UniFiClient(
        host=console.host,
        port=console.port,
        api_key="k",
        verify_ssl=tls.build_pinned_context(console.cert_path),
    )
    try:
        assert await client.list_devices() == []
    finally:
        await client.aclose()


async def test_unifi_client_mismatch_names_the_repin_command(
    console: Console, other_pin: Path
) -> None:
    client = UniFiClient(
        host=console.host,
        port=console.port,
        api_key="k",
        verify_ssl=tls.build_pinned_context(other_pin),
    )
    try:
        with pytest.raises(UniFiError) as exc:
            await client.list_devices()
    finally:
        await client.aclose()
    msg = str(exc.value)
    assert tls.PIN_COMMAND in msg
    assert "verify_ssl" in msg  # says not to lower it
    assert "k" not in msg.split("--out")[0].split(console.host)[0]  # no key in the message


class _RaisingClient:
    def __init__(self, exc: Exception) -> None:
        self.exc = exc
        self.calls = 0

    async def request(self, *_: Any, **__: Any) -> httpx.Response:
        self.calls += 1
        raise self.exc


async def test_verification_failure_is_not_retried() -> None:
    fake = _RaisingClient(httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] self-signed"))
    with pytest.raises(UniFiError, match="TLS verification failed"):
        await request_with_retry(
            fake,  # type: ignore[arg-type]
            "GET",
            "https://gateway.test/x",
            logger=logging.getLogger("t"),
            service="UniFi",
            error_cls=UniFiError,
        )
    assert fake.calls == 1


async def test_ordinary_connect_error_is_still_retried_once() -> None:
    """Control for the test above: the retry path did not change for other errors."""
    fake = _RaisingClient(httpx.ConnectError("connection refused"))
    with pytest.raises(UniFiError, match="connection failed"):
        await request_with_retry(
            fake,  # type: ignore[arg-type]
            "GET",
            "https://gateway.test/x",
            logger=logging.getLogger("t"),
            service="UniFi",
            error_cls=UniFiError,
        )
    assert fake.calls == 2


# ---------------------------------------------------------------------------
# The bootstrap command
# ---------------------------------------------------------------------------


def test_pin_cert_writes_the_presented_certificate(
    console: Console, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "pins" / "home.pem"
    rc = pin_cert.main([console.host, "--port", str(console.port), "--out", str(out)])
    assert rc == 0
    assert ssl.PEM_cert_to_DER_cert(out.read_text()) == console.der
    printed = capsys.readouterr().out
    assert tls.format_fingerprint(console.fingerprint) in printed
    assert "pinned_cert" in printed


def test_pin_cert_refuses_to_overwrite_without_force(console: Console, tmp_path: Path) -> None:
    out = tmp_path / "home.pem"
    out.write_text("existing")
    rc = pin_cert.main([console.host, "--port", str(console.port), "--out", str(out)])
    assert rc == 1
    assert out.read_text() == "existing"
    rc = pin_cert.main([console.host, "--port", str(console.port), "--out", str(out), "--force"])
    assert rc == 0
    assert ssl.PEM_cert_to_DER_cert(out.read_text()) == console.der


def test_pin_cert_honours_expected_fingerprint(console: Console, tmp_path: Path) -> None:
    out = tmp_path / "home.pem"
    wrong = "00" * 32
    rc = pin_cert.main(
        [
            console.host,
            "--port",
            str(console.port),
            "--out",
            str(out),
            "--expect-fingerprint",
            wrong,
        ]
    )
    assert rc == 1
    assert not out.exists()
    pretty = tls.format_fingerprint(console.fingerprint)
    rc = pin_cert.main(
        [
            console.host,
            "--port",
            str(console.port),
            "--out",
            str(out),
            "--expect-fingerprint",
            pretty,
        ]
    )
    assert rc == 0
    assert out.exists()


def test_pin_cert_unreachable_console_writes_nothing(tmp_path: Path) -> None:
    out = tmp_path / "home.pem"
    rc = pin_cert.main(["127.0.0.1", "--port", "9", "--out", str(out), "--timeout", "1"])
    assert rc == 2
    assert not out.exists()


# ---------------------------------------------------------------------------
# The shipped env template must boot with the pin line uncommented
# ---------------------------------------------------------------------------


def _env_example_active_lines() -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in (REPO_ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip()
    return out


def test_env_example_boots_with_the_pin_uncommented(
    monkeypatch: pytest.MonkeyPatch, console: Console
) -> None:
    """Copy the template, fill the two blanks, uncomment the pin: it must start.

    The template shipped ``UNIFI_VERIFY_SSL=false`` as an active line while
    telling the reader to uncomment ``UNIFI_PINNED_CERT``, which the
    contradiction check refuses. Found by an outside review of #158.
    """
    active = _env_example_active_lines()
    assert "UNIFI_VERIFY_SSL" not in active, "template sets verify_ssl explicitly"
    for key in set(active) | {"UNIFI_PINNED_CERT", "UNIFI_VERIFY_SSL", "UNIFI_API_KEY_FILE"}:
        monkeypatch.delenv(key, raising=False)
    for key, value in active.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("STUB_MODE", "false")
    monkeypatch.setenv("UNIFI_API_KEY", "template-key")
    monkeypatch.setenv("UNIFI_PINNED_CERT", str(console.cert_path))
    monkeypatch.setenv("MCP_UNIFI_AUTH_TOKENS", "t:template-token")
    s = Settings()
    assert s.controllers[0].pinned_cert == console.cert_path
    assert s.controllers[0].verify_ssl is True


# ---------------------------------------------------------------------------
# Docs guard
# ---------------------------------------------------------------------------


def test_pinning_is_documented() -> None:
    docs = (
        REPO_ROOT / "README.md",
        REPO_ROOT / "docs/site/src/content/docs/reference/configuration.md",
        REPO_ROOT / "docs/site/src/content/docs/guides/multi-site.md",
        REPO_ROOT / "docs/site/src/content/docs/guides/security.md",
    )
    for doc in docs:
        text = doc.read_text(encoding="utf-8")
        missing = [w for w in ("pinned_cert", "mcp-unifi-pin-cert") if w not in text]
        assert not missing, f"{doc.relative_to(REPO_ROOT)} does not mention {missing}"
    assert "`UNIFI_PINNED_CERT`" in docs[0].read_text(encoding="utf-8")
    assert "`UNIFI_PINNED_CERT`" in docs[1].read_text(encoding="utf-8")
