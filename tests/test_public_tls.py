"""Real synthetic TLS connections exercise the public readiness probe."""
import json
import ssl
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from scripts import check_public_tls as probe


SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(self)", "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'",
}
READY = json.dumps({"status": "ok", "url_analysis": {"available": True}}).encode()


@pytest.fixture
def tls_server(tmp_path):
    servers = []

    def start(body=READY, status=200, headers=None, validity_days=10):
        directory = tmp_path / str(len(servers))
        directory.mkdir()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.now(timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=validity_days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
        certfile = directory / "test-ca.pem"
        keyfile = directory / "test-key.pem"
        certfile.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        requests = []

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                requests.append(self.path)
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Type", "application/json")
                for header, value in (SECURITY_HEADERS if headers is None else headers).items():
                    self.send_header(header, value)
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (OSError, ssl.SSLError):
                    pass

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile, keyfile)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
        thread.start()
        servers.append((server, thread))
        return server.server_port, certfile, requests

    yield start
    for server, thread in servers:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_real_valid_tls_and_health_custom_ca_cannot_certify_public_readiness(tls_server):
    port, ca, requests = tls_server()
    result = probe.check_public_tls("localhost", cafile=ca, _port=port)
    assert result["checks_passed"] and result["tls_verified"]
    assert result["tls_protocol"] in {"TLSv1.2", "TLSv1.3"}
    assert result["analysis_ready"] and result["qr_service_health_ready"]
    assert not result["all_ready"] and not result["public_ca_verified"]
    assert requests == ["/health"]
    assert result["failure_codes"] == ["custom_ca_is_synthetic_test_only"]


def test_real_untrusted_chain_and_wrong_hostname_rejected_before_health(tls_server):
    port, ca, requests = tls_server()
    for kwargs in [{}, {"cafile": ca}]:
        host = "localhost" if not kwargs else "127.0.0.1"
        result = probe.check_public_tls(host, _port=port, **kwargs)
        assert not result["all_ready"] and not result["tls_verified"]
        assert "tls_validation_failed" in result["failure_codes"]
    assert requests == []


def test_valid_but_near_expiry_leaf_is_not_ready(tls_server):
    port, ca, _ = tls_server(validity_days=1)
    result = probe.check_public_tls("localhost", cafile=ca, _port=port)
    assert result["tls_verified"] and result["analysis_ready"]
    assert not result["leaf_valid_for_at_least_three_days"] and not result["checks_passed"]
    assert "certificate_expires_within_three_days" in result["failure_codes"]


@pytest.mark.parametrize("body,status,headers,expected", [
    (READY, 302, {**SECURITY_HEADERS, "Location": "https://uncontacted.invalid/health"}, "health_http_status_not_200"),
    (b"x" * 65537, 200, SECURITY_HEADERS, "health_response_too_large"),
    (b"not json", 200, SECURITY_HEADERS, "invalid_health_json"),
    (b'{"status":"ok"}', 200, SECURITY_HEADERS, "invalid_health_schema"),
    (READY, 200, {}, "security_headers_missing_or_invalid"),
], ids=["redirect", "oversized", "invalid-json", "missing-analysis", "missing-headers"])
def test_redirect_oversized_invalid_and_unprotected_health_are_rejected(tls_server, body, status, headers, expected):
    port, ca, requests = tls_server(body=body, status=status, headers=headers)
    result = probe.check_public_tls("localhost", cafile=ca, _port=port)
    assert not result["checks_passed"] and expected in result["failure_codes"]
    assert requests == ["/health"]


def test_degraded_analysis_can_report_health_availability_but_never_all_ready(tls_server):
    body = b'{"status":"degraded","url_analysis":{"available":false}}'
    port, ca, _ = tls_server(body=body)
    strict = probe.check_public_tls("localhost", cafile=ca, _port=port)
    permitted = probe.check_public_tls("localhost", cafile=ca, _port=port, allow_analysis_degraded=True)
    assert not strict["qr_service_health_ready"]
    assert permitted["qr_service_health_ready"] and not permitted["analysis_ready"]
    assert not permitted["all_ready"] and not permitted["checks_passed"]


def test_ambiguous_security_headers_and_ambiguous_health_json_rejected():
    headers = list(SECURITY_HEADERS.items()) + [("Strict-Transport-Security", "max-age=0")]
    assert not probe.security_headers(headers)["hsts"]
    with pytest.raises(ValueError, match="invalid_health_json"):
        probe._health_result(b'{"status":"ok","status":"degraded","url_analysis":{"available":true}}', False)


@pytest.mark.parametrize("host", ["https://example.com", "example.com/path", "example.com:443", " example.com", "example..com"])
def test_invalid_hostname_rejected_without_connection(host, monkeypatch):
    monkeypatch.setattr(probe.http.client, "HTTPSConnection", lambda *_a, **_k: pytest.fail("must not connect"))
    result = probe.check_public_tls(host)
    assert result["failure_codes"] == ["invalid_hostname"] and not result["tls_verified"]
