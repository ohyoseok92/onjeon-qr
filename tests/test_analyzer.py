from onjeon import analyzer
import base64
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

import pytest


def crl_bytes(last_update, next_update):
    key = ed25519.Ed25519PrivateKey.generate()
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Local CRL fixture")])
    crl = (x509.CertificateRevocationListBuilder().issuer_name(issuer)
           .last_update(last_update).next_update(next_update).sign(key, None))
    return crl.public_bytes(serialization.Encoding.PEM)


def test_production_requires_crl_before_creating_tls_context(monkeypatch):
    monkeypatch.setenv("ONJEON_ENV", "production")
    monkeypatch.delenv("ONJEON_TLS_CRL_BUNDLE", raising=False)
    monkeypatch.setattr(analyzer.ssl, "create_default_context", lambda: pytest.fail("missing configuration must fail first"))
    with pytest.raises(ssl.SSLCertVerificationError, match="Production requires a TLS CRL bundle"):
        analyzer.build_tls_context()
    with pytest.raises(ssl.SSLCertVerificationError, match="Production requires a TLS CRL bundle"):
        analyzer.tls_configuration_status()


@pytest.mark.parametrize("content", [b"", b"garbage", b"-----BEGIN X509 CRL-----\ninvalid\n-----END X509 CRL-----\n",
                                    b"-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n",
                                    b"x" * (analyzer.MAX_CRL_BUNDLE_BYTES + 1)],
                         ids=["empty", "junk", "malformed-crl", "certificate-in-crl-bundle", "oversized"])
def test_crl_bundle_rejects_invalid_or_oversized_configuration_without_network(tmp_path, monkeypatch, content):
    path = tmp_path / "private-configuration-path.pem"
    path.write_bytes(content)
    monkeypatch.setenv("ONJEON_TLS_CRL_BUNDLE", str(path))
    monkeypatch.setattr(analyzer, "_resolve_public", lambda *args, **kwargs: "93.184.215.14")
    monkeypatch.setattr(analyzer.socket, "create_connection", lambda *args, **kwargs: pytest.fail("invalid CRL must prevent connection"))
    with pytest.raises(ssl.SSLCertVerificationError) as caught:
        analyzer.build_tls_context()
    assert str(path) not in str(caught.value)
    assert caught.value.args == ("Invalid TLS CRL configuration",)
    with pytest.raises(ssl.SSLCertVerificationError, match="Invalid TLS CRL configuration"):
        analyzer.tls_configuration_status()
    result = analyzer.analyze_url("https://inspection.example.org/", [])
    assert result["status"] == "blocked" and result["reason"] == "tls_invalid"


def test_crl_bundle_missing_path_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("ONJEON_TLS_CRL_BUNDLE", str(tmp_path / "missing.pem"))
    with pytest.raises(ssl.SSLCertVerificationError, match="Invalid TLS CRL configuration"):
        analyzer.build_tls_context()
    with pytest.raises(ssl.SSLCertVerificationError, match="Invalid TLS CRL configuration"):
        analyzer.tls_configuration_status()


def test_production_forbids_tls_key_logging_before_file_is_created(tmp_path, monkeypatch):
    target = tmp_path / "tls-secrets.log"
    monkeypatch.setenv("ONJEON_ENV", "production")
    monkeypatch.setenv("ONJEON_TLS_CRL_BUNDLE", "configured.pem")
    monkeypatch.setenv("SSLKEYLOGFILE", str(target))
    with pytest.raises(ssl.SSLCertVerificationError, match="Production forbids TLS key logging"):
        analyzer.build_tls_context()
    with pytest.raises(ssl.SSLCertVerificationError, match="Production forbids TLS key logging"):
        analyzer.tls_configuration_status()
    assert not target.exists()


@pytest.mark.parametrize("reason,last_hours,next_hours", [
    ("crl_expired", -2, -1), ("crl_not_yet_valid", 1, 2),
])
def test_crl_time_problem_degrades_status_but_request_stays_closed_and_refresh_recovers(
    tmp_path, monkeypatch, reason, last_hours, next_hours,
):
    now = datetime.now(timezone.utc)
    path = tmp_path / "crls.pem"
    path.write_bytes(crl_bytes(now + timedelta(hours=last_hours), now + timedelta(hours=next_hours)))
    monkeypatch.setenv("ONJEON_ENV", "production")
    monkeypatch.setenv("ONJEON_TLS_CRL_BUNDLE", str(path))
    monkeypatch.setattr(analyzer, "_resolve_public", lambda *args, **kwargs: "93.184.215.14")
    monkeypatch.setattr(analyzer.socket, "create_connection", lambda *args, **kwargs: pytest.fail("stale CRL must prevent connection"))

    assert analyzer.tls_configuration_status() == {"available": False, "reason": reason}
    with pytest.raises(ssl.SSLCertVerificationError, match="Invalid TLS CRL configuration"):
        analyzer.build_tls_context()
    result = analyzer.analyze_url("https://inspection.example.org/", [])
    assert result["status"] == "blocked" and result["reason"] == "tls_invalid"
    assert "destination" not in result

    path.write_bytes(crl_bytes(now - timedelta(hours=1), now + timedelta(hours=1)))
    assert analyzer.tls_configuration_status() == {"available": True, "reason": "ready"}
    context = analyzer.build_tls_context()
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.verify_flags & ssl.VERIFY_CRL_CHECK_CHAIN


@pytest.mark.parametrize("suffix", [
    b"-----BEGIN X509 CRL-----\ninvalid\n-----END X509 CRL-----\n",
    b"-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n",
])
def test_expired_crl_cannot_hide_malformed_or_trust_anchor_blocks(tmp_path, monkeypatch, suffix):
    now = datetime.now(timezone.utc)
    path = tmp_path / "crls.pem"
    path.write_bytes(crl_bytes(now - timedelta(hours=2), now - timedelta(hours=1)) + suffix)
    monkeypatch.setenv("ONJEON_TLS_CRL_BUNDLE", str(path))
    with pytest.raises(ssl.SSLCertVerificationError, match="Invalid TLS CRL configuration"):
        analyzer.tls_configuration_status()


@pytest.mark.parametrize("next_hours", [-1, -2], ids=["equal-dates", "reversed-dates"])
def test_malformed_crl_validity_window_refuses_startup(tmp_path, monkeypatch, next_hours):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    last_update, next_update = now - timedelta(hours=1), now + timedelta(hours=1)
    crl = x509.load_pem_x509_crl(crl_bytes(last_update, next_update))
    # Mutate DER date fields to represent a malformed operator bundle. The
    # signature is deliberately no longer valid; the date structure alone must
    # refuse startup before any TLS handshake could test that signature.
    der = crl.public_bytes(serialization.Encoding.DER)
    der = der.replace(next_update.strftime("%y%m%d%H%M%SZ").encode(),
                      (now + timedelta(hours=next_hours)).strftime("%y%m%d%H%M%SZ").encode())
    path = tmp_path / "crls.pem"
    path.write_bytes(b"-----BEGIN X509 CRL-----\n" + base64.b64encode(der) + b"\n-----END X509 CRL-----\n")
    monkeypatch.setenv("ONJEON_TLS_CRL_BUNDLE", str(path))
    with pytest.raises(ssl.SSLCertVerificationError, match="Invalid TLS CRL configuration"):
        analyzer.tls_configuration_status()
    with pytest.raises(ssl.SSLCertVerificationError, match="Invalid TLS CRL configuration"):
        analyzer.build_tls_context()


def test_unsigned_url_never_becomes_trusted(monkeypatch):
    monkeypatch.setattr(analyzer, "_resolve_public", lambda host, **kwargs: "93.184.215.14")
    monkeypatch.setattr(analyzer, "_head", lambda url, host, address, **kwargs: (200, None))
    result = analyzer.analyze_url("https://city.example.org/notice", ["city.example.org"])
    assert result["status"] == "warning"
    assert "official_domain_unverified" in result["signals"]
    assert "destination" not in result


def test_unsigned_url_redirect_and_install_signals(monkeypatch):
    monkeypatch.setattr(analyzer, "_resolve_public", lambda host, **kwargs: "93.184.215.14")
    seen = []

    def head(url, host, address, **kwargs):
        seen.append(host)
        return (302, "https://other.example.net/app.apk") if len(seen) == 1 else (200, None)

    monkeypatch.setattr(analyzer, "_head", head)
    result = analyzer.analyze_url("https://city.example.org/start", ["city.example.org"])
    assert result["status"] == "warning"
    assert result["redirects"] == 1
    assert "left_official_domain" in result["signals"]
    assert "install_file" in result["signals"]
    assert seen == ["city.example.org", "other.example.net"]


def test_private_address_and_downgrade_are_blocked(monkeypatch):
    monkeypatch.setattr(analyzer.socket, "getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", ("127.0.0.1", 443))])
    assert analyzer.analyze_url("https://foo.example.org/", [])["reason"] == "non_public_address"
    monkeypatch.setattr(analyzer, "_resolve_public", lambda host, **kwargs: "93.184.215.14")
    monkeypatch.setattr(analyzer, "_head", lambda url, host, address, **kwargs: (302, "http://foo.example.org/"))
    assert analyzer.analyze_url("https://foo.example.org/", [])["reason"] == "unsafe_redirect"


def test_unsupported_url_does_not_trigger_network(monkeypatch):
    monkeypatch.setattr(analyzer, "_resolve_public", lambda host, **kwargs: (_ for _ in ()).throw(AssertionError("called")))
    for url in ("file:///etc/passwd", "https://127.0.0.1/", "https://user@example.org/", "https://example.org\\@evil.org/"):
        assert analyzer.analyze_url(url, [])["status"] == "blocked"


def test_redirect_limit_is_a_warning(monkeypatch):
    monkeypatch.setattr(analyzer, "_resolve_public", lambda host, **kwargs: "93.184.215.14")

    def head(url, host, address, **kwargs):
        number = int(url.rsplit("/", 1)[-1])
        return 302, f"https://foo.example.org/{number + 1}"

    monkeypatch.setattr(analyzer, "_head", head)
    result = analyzer.analyze_url("https://foo.example.org/0", [])
    assert result["status"] == "warning"
    assert result["reason"] == "redirect_limit"


def test_ipv4_is_preferred_after_all_addresses_are_checked(monkeypatch):
    monkeypatch.setattr(
        analyzer.socket, "getaddrinfo",
        lambda *args, **kwargs: [(10, 1, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 443)), (2, 1, 6, "", ("93.184.215.14", 443))],
    )
    assert analyzer._resolve_public("example.org") == "93.184.215.14"


def test_unicode_path_is_percent_encoded(monkeypatch):
    paths = []

    class FakeResponse:
        status = 200

        def getheader(self, key):
            return None

    class FakeConnection:
        sock = None

        def __init__(self, host, address, timeout=4):
            pass

        def connect(self):
            pass

        def request(self, method, path, headers):
            paths.append(path)

        def getresponse(self):
            return FakeResponse()

        def close(self):
            pass

    monkeypatch.setattr(analyzer, "_PinnedHTTPSConnection", FakeConnection)
    assert analyzer._head("https://example.org/공지", "example.org", "93.184.215.14") == (200, None)
    assert paths == ["/%EA%B3%B5%EC%A7%80"]


def test_bad_certificate_is_blocked(monkeypatch):
    monkeypatch.setattr(analyzer, "_resolve_public", lambda host, **kwargs: "93.184.215.14")
    monkeypatch.setattr(analyzer, "_head", lambda url, host, address, **kwargs: (_ for _ in ()).throw(ssl.SSLCertVerificationError("bad cert")))
    assert analyzer.analyze_url("https://example.org/", [])["reason"] == "tls_invalid"


def test_full_analyzer_returns_busy_without_network(monkeypatch):
    monkeypatch.setattr(analyzer, "_resolve_public", lambda host, **kwargs: (_ for _ in ()).throw(AssertionError("network called")))
    for _ in range(4):
        analyzer.ANALYSIS_SLOTS.acquire()
    try:
        assert analyzer.analyze_url("https://example.org/", [])["reason"] == "analyzer_busy"
    finally:
        for _ in range(4):
            analyzer.ANALYSIS_SLOTS.release()


@pytest.mark.parametrize("address", ["224.0.0.1", "ff02::1", "::ffff:127.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::"])
def test_multicast_and_translation_addresses_are_blocked(monkeypatch, address):
    monkeypatch.setattr(analyzer.socket, "getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", (address, 443))])
    assert analyzer.analyze_url("https://example.org/", [])["reason"] == "non_public_address"


@pytest.mark.parametrize("address,mixed_public", [
    ("fec0::1", False), ("feff:ffff::1", False), ("fec0::1", True),
])
def test_site_local_ipv6_is_blocked_before_connection_even_with_public_dns(monkeypatch, address, mixed_public):
    answers = [(10, 1, 6, "", (address, 443))]
    if mixed_public:
        answers.append((2, 1, 6, "", ("93.184.215.14", 443)))
    monkeypatch.setattr(analyzer.socket, "getaddrinfo", lambda *args, **kwargs: answers)
    monkeypatch.setattr(analyzer, "_head", lambda *args, **kwargs: pytest.fail("site-local destination must not connect"))
    result = analyzer.analyze_url("https://example.org/", [])
    assert result["status"] == "blocked" and result["reason"] == "non_public_address"
    assert "destination" not in result


def test_timed_out_dns_queries_cannot_accumulate(monkeypatch):
    release = threading.Event()
    started = []

    def stalled(*args, **kwargs):
        started.append(1)
        release.wait(2)
        return [(2, 1, 6, "", ("93.184.215.14", 443))]

    with ThreadPoolExecutor(max_workers=4) as executor:
        monkeypatch.setattr(analyzer, "DNS_EXECUTOR", executor)
        monkeypatch.setattr(analyzer, "DNS_SLOTS", threading.BoundedSemaphore(4))
        monkeypatch.setattr(analyzer.socket, "getaddrinfo", stalled)
        try:
            for _ in range(4):
                with pytest.raises(OSError, match="timed out"):
                    analyzer._resolve_public("example.org", timeout=0.02)
            with pytest.raises(OSError, match="busy"):
                analyzer._resolve_public("example.org", timeout=0.02)
            assert len(started) == 4
        finally:
            release.set()


def test_malformed_redirect_is_blocked(monkeypatch):
    monkeypatch.setattr(analyzer, "_resolve_public", lambda host, **kwargs: "93.184.215.14")
    monkeypatch.setattr(analyzer, "_head", lambda url, host, address, **kwargs: (302, "https://["))
    assert analyzer.analyze_url("https://example.org/", [])["reason"] == "unsafe_redirect"


@pytest.mark.parametrize("suffix", ["/path\x7f", "/path\u202eapk", "/path\u200b", "/path\ud800"])
def test_hidden_and_control_characters_do_not_trigger_network(monkeypatch, suffix):
    monkeypatch.setattr(analyzer, "_resolve_public", lambda host, **kwargs: (_ for _ in ()).throw(AssertionError("network called")))
    assert analyzer.analyze_url("https://example.org" + suffix, [])["reason"] == "unsupported_url"


def test_redirect_hop_is_checked_for_encoded_install_and_similar_domain(monkeypatch):
    monkeypatch.setattr(analyzer, "_resolve_public", lambda host, **kwargs: "93.184.215.14")
    monkeypatch.setattr(analyzer, "_head", lambda url, host, address, **kwargs: (302, "https://citv.example.org/download/app.%61pk") if host == "short.example.net" else (200, None))
    result = analyzer.analyze_url("https://short.example.net/start", ["city.example.org"])
    assert result["status"] == "warning"
    assert result["redirects"] == 1
    assert {"install_file", "lookalike_domain"}.issubset(result["signals"])
    assert "destination" not in result


def test_idn_domain_is_reported_after_redirect(monkeypatch):
    monkeypatch.setattr(analyzer, "_resolve_public", lambda host, **kwargs: "93.184.215.14")
    monkeypatch.setattr(analyzer, "_head", lambda url, host, address, **kwargs: (302, "https://xn--e1awd7f.com/") if host == "short.example.net" else (200, None))
    result = analyzer.analyze_url("https://short.example.net/", [])
    assert result["status"] == "warning" and "idn_domain" in result["signals"]


def test_mixed_public_private_dns_cannot_select_the_public_answer(monkeypatch):
    monkeypatch.setattr(analyzer.socket, "getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", ("93.184.215.14", 443)), (10, 1, 6, "", ("::1", 443))])
    monkeypatch.setattr(analyzer, "_head", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("network called")))
    assert analyzer.analyze_url("https://example.org/", [])["reason"] == "non_public_address"
