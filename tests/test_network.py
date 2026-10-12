"""Real local TLS/HTTP attacks; only DNS and socket routing are redirected.

The public-IP policy, hostname/certificate verification, HEAD implementation,
and redirect logic run unchanged. No requests reach external services.
"""

from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import socket
import ssl
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ExtendedKeyUsageOID
import pytest

from onjeon import analyzer


@pytest.fixture(autouse=True)
def isolated_tls_environment(monkeypatch):
    monkeypatch.delenv("ONJEON_ENV", raising=False)
    monkeypatch.delenv("ONJEON_TLS_CRL_BUNDLE", raising=False)


@pytest.fixture
def tls_server(tmp_path, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "inspection.example.org")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("inspection.example.org")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            requests.append((self.command, self.path, self.headers.get("Host")))
            if self.path == "/slow":
                time.sleep(0.3)
            self.send_response(302 if self.path in ("/private", "/start") else 200)
            if self.path == "/private":
                self.send_header("Location", "https://internal.example.org/private")
            elif self.path == "/start":
                self.send_header("Location", "/download/app.apk")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    original_connect, original_dns = socket.create_connection, socket.getaddrinfo
    connections = []

    def route(address, *args, **kwargs):
        connections.append(address)
        assert address == ("93.184.215.14", 443)
        return original_connect(("127.0.0.1", server.server_port), *args, **kwargs)

    def dns(host, port, *args, **kwargs):
        if host == "127.0.0.1":
            return original_dns(host, port, *args, **kwargs)
        ip = "127.0.0.1" if host == "internal.example.org" else "93.184.215.14"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))]

    monkeypatch.setattr(analyzer.socket, "create_connection", route)
    monkeypatch.setattr(analyzer.socket, "getaddrinfo", dns)
    try:
        yield cert_path, requests, connections
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def trust_fixture_certificate(monkeypatch, path):
    context = ssl.create_default_context(cafile=str(path))
    monkeypatch.setattr(analyzer.ssl, "create_default_context", lambda: context)


def test_actual_self_signed_tls_is_rejected(tls_server):
    _, requests, connections = tls_server
    result = analyzer.analyze_url("https://inspection.example.org/", [])
    assert result["reason"] == "tls_invalid"
    assert not requests
    assert len(connections) == 1


def test_actual_hostname_mismatch_is_rejected_even_with_trusted_certificate(tls_server, monkeypatch):
    cert, requests, connections = tls_server
    trust_fixture_certificate(monkeypatch, cert)
    result = analyzer.analyze_url("https://different.example.org/", [])
    assert result["reason"] == "tls_invalid"
    assert not requests
    assert len(connections) == 1


def test_actual_head_and_redirect_cannot_reach_internal_host(tls_server, monkeypatch):
    cert, requests, connections = tls_server
    trust_fixture_certificate(monkeypatch, cert)
    result = analyzer.analyze_url("https://inspection.example.org/private", [])
    assert result["reason"] == "non_public_address"
    assert requests == [("HEAD", "/private", "inspection.example.org")]
    assert len(connections) == 1


def test_actual_redirect_inspects_install_target_without_returning_link(tls_server, monkeypatch):
    cert, requests, _ = tls_server
    trust_fixture_certificate(monkeypatch, cert)
    result = analyzer.analyze_url("https://inspection.example.org/start", [])
    assert result["status"] == "warning" and result["redirects"] == 1
    assert "install_file" in result["signals"] and "destination" not in result
    assert [request[1] for request in requests] == ["/start", "/download/app.apk"]


def test_actual_slow_headers_obey_probe_timeout(tls_server, monkeypatch):
    cert, _, _ = tls_server
    trust_fixture_certificate(monkeypatch, cert)
    started = time.monotonic()
    with pytest.raises((OSError, http.client.HTTPException)):
        analyzer._head("https://inspection.example.org/slow", "inspection.example.org", "93.184.215.14", timeout=0.1)
    assert time.monotonic() - started < 0.7


@pytest.fixture
def crl_tls_server(tmp_path, monkeypatch, request):
    """A root -> intermediate -> server chain with independently signed CRLs."""
    mode = request.param
    now = datetime.now(timezone.utc)
    keys = [rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(3)]
    names = [x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])
             for value in ("Local CRL root", "Local CRL intermediate", "inspection.example.org")]
    certs = []
    for index in range(3):
        ca = index < 2
        issuer = max(0, index - 1)
        expiry = now - timedelta(minutes=1) if mode == "expired_cert" and index == 2 else now + timedelta(days=1)
        builder = (x509.CertificateBuilder().subject_name(names[index]).issuer_name(names[issuer])
                   .public_key(keys[index].public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(days=1)).not_valid_after(expiry)
                   .add_extension(x509.BasicConstraints(ca=ca, path_length=(1 - index) if ca else None), True)
                   .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                               key_encipherment=not ca, data_encipherment=False,
                                               key_agreement=False, key_cert_sign=ca, crl_sign=ca,
                                               encipher_only=False, decipher_only=False), True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(keys[index].public_key()), False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(keys[issuer].public_key()), False))
        if index == 2:
            builder = (builder.add_extension(x509.SubjectAlternativeName([x509.DNSName("inspection.example.org")]), False)
                       .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False))
        certs.append(builder.sign(keys[issuer], hashes.SHA256()))

    crls = []
    for issuer in range(2):
        if mode == "missing_root_crl" and issuer == 0 or mode == "missing_intermediate_crl" and issuer == 1:
            continue
        last_update = now + timedelta(minutes=1) if mode == "future_crl" else now - timedelta(hours=1)
        next_update = now - timedelta(minutes=1) if mode == "expired_crl" else now + timedelta(hours=1)
        builder = (x509.CertificateRevocationListBuilder().issuer_name(names[issuer])
                   .last_update(last_update).next_update(next_update)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(keys[issuer].public_key()), False)
                   .add_extension(x509.CRLNumber(1), False))
        if mode == "revoked_leaf" and issuer == 1 or mode == "revoked_intermediate" and issuer == 0:
            builder = builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder().serial_number(certs[issuer + 1].serial_number)
                .revocation_date(now - timedelta(minutes=1)).build())
        signing_key = keys[2] if mode == "bad_signature" and issuer == 1 else keys[issuer]
        crls.append(builder.sign(signing_key, hashes.SHA256()))

    root_path, chain_path, key_path, crl_path = [tmp_path / name for name in ("root.pem", "chain.pem", "key.pem", "crls.pem")]
    root_path.write_bytes(certs[0].public_bytes(serialization.Encoding.PEM))
    chain_path.write_bytes(b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in reversed(certs[1:])))
    key_path.write_bytes(keys[2].private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))
    crl_path.write_bytes(b"".join(crl.public_bytes(serialization.Encoding.PEM) for crl in crls))
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            seen.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(chain_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    worker.start()
    original_context, original_connect, original_dns = ssl.create_default_context, socket.create_connection, socket.getaddrinfo
    monkeypatch.setattr(analyzer.ssl, "create_default_context",
                        lambda: original_context() if mode == "untrusted_ca" else original_context(cafile=str(root_path)))
    monkeypatch.setenv("ONJEON_ENV", "production")
    monkeypatch.setenv("ONJEON_TLS_CRL_BUNDLE", str(crl_path))
    connections = []

    def route(address, *args, **kwargs):
        assert address == ("93.184.215.14", 443)
        connections.append(address)
        return original_connect(("127.0.0.1", server.server_port), *args, **kwargs)

    def dns(host, port, *args, **kwargs):
        if host == "127.0.0.1":
            return original_dns(host, port, *args, **kwargs)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 443))]

    monkeypatch.setattr(analyzer.socket, "create_connection", route)
    monkeypatch.setattr(analyzer.socket, "getaddrinfo", dns)

    def publish_replacement(revoked=False, expired=False):
        replacement = (x509.CertificateRevocationListBuilder().issuer_name(names[1])
                       .last_update(now - timedelta(hours=1))
                       .next_update(now - timedelta(minutes=1) if expired else now + timedelta(hours=1))
                       .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(keys[1].public_key()), False)
                       .add_extension(x509.CRLNumber(2), False))
        if revoked:
            replacement = replacement.add_revoked_certificate(
                x509.RevokedCertificateBuilder().serial_number(certs[2].serial_number)
                .revocation_date(now - timedelta(minutes=1)).build())
        crl_path.write_bytes(crls[0].public_bytes(serialization.Encoding.PEM)
                             + replacement.sign(keys[1], hashes.SHA256()).public_bytes(serialization.Encoding.PEM))

    try:
        yield mode, seen, connections, publish_replacement
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


@pytest.mark.parametrize("crl_tls_server", ["valid", "revoked_leaf", "revoked_intermediate", "expired_crl", "future_crl",
                                          "missing_root_crl", "missing_intermediate_crl", "bad_signature",
                                          "expired_cert", "wrong_hostname", "untrusted_ca"], indirect=True)
def test_actual_tls_chain_and_crl_validation(crl_tls_server):
    mode, seen, connections, _ = crl_tls_server
    host = "different.example.org" if mode == "wrong_hostname" else "inspection.example.org"
    result = analyzer.analyze_url(f"https://{host}/", [])
    if mode == "valid":
        assert result["reason"] == "unsigned_qr" and result["status"] == "warning"
        assert seen == ["/"] and len(connections) == 1
    else:
        assert result["reason"] == "tls_invalid" and result["status"] == "blocked"
        assert seen == []
        assert len(connections) == (0 if mode in ("expired_crl", "future_crl") else 1)


@pytest.mark.parametrize("crl_tls_server", ["valid"], indirect=True)
@pytest.mark.parametrize("replacement", ["revoked", "expired"])
def test_crl_refresh_is_enforced_on_the_next_actual_probe(crl_tls_server, replacement):
    _, seen, connections, publish = crl_tls_server
    assert analyzer.analyze_url("https://inspection.example.org/", [])["reason"] == "unsigned_qr"
    publish(revoked=replacement == "revoked", expired=replacement == "expired")
    result = analyzer.analyze_url("https://inspection.example.org/", [])
    assert result["reason"] == "tls_invalid" and result["status"] == "blocked"
    assert seen == ["/"]
    assert len(connections) == (2 if replacement == "revoked" else 1)
