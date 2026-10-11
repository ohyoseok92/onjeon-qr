"""Public-only operational monitor rejects health and certificate scope changes."""
import json
import ssl
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from scripts import check_operational_health as monitor

NOW = datetime(2026, 10, 11, 15, tzinfo=timezone.utc)
LOCATION = "http://synthetic.c.lencr.org/66.crl"


@pytest.fixture
def profile():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Health Synthetic Issuer")])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
          .serial_number(1).not_valid_before(NOW - timedelta(days=10)).not_valid_after(NOW + timedelta(days=365))
          .add_extension(x509.BasicConstraints(True, None), True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False).sign(key, hashes.SHA256()))

    def issued(location=LOCATION, expires=NOW + timedelta(days=20), signer=None):
        return (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, monitor.HOST)]))
                .issuer_name(name).public_key(ec.generate_private_key(ec.SECP256R1()).public_key()).serial_number(200)
                .not_valid_before(NOW - timedelta(days=1)).not_valid_after(expires)
                .add_extension(x509.BasicConstraints(False, None), True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(monitor.HOST)]), False)
                .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
                    [x509.UniformResourceIdentifier(location)], None, None, None)]), False)
                .sign(signer or key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))

    def revocations(expires=NOW + timedelta(days=2), revoked=False):
        builder = (x509.CertificateRevocationListBuilder().issuer_name(name)
                   .last_update(NOW - timedelta(minutes=1)).next_update(expires)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
                   .add_extension(x509.CRLNumber(10), False)
                   .add_extension(x509.IssuingDistributionPoint([x509.UniformResourceIdentifier(LOCATION)],
                       None, True, False, None, False, False), True))
        if revoked:
            builder = builder.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(200)
                .revocation_date(NOW - timedelta(days=1)).build())
        return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)

    return {"health": {"status": "ok", "url_analysis": {"available": True, "reason": "ready"}},
            "peer_der": issued(), "config": {"urls": [LOCATION], "distribution_points": [LOCATION],
                "issuer_pins": [ca.fingerprint(hashes.SHA256()).hex()], "approve_ca_only_crls": False},
            "ca_bundle": ca.public_bytes(serialization.Encoding.PEM), "bundle": revocations(),
            "issued": issued, "revocations": revocations}


def evaluate(profile, **changes):
    options = {name: profile[name] for name in ("health", "peer_der", "config", "bundle", "ca_bundle")}
    return monitor.evaluate(**{**options, **changes}, now=NOW)


def test_current_peer_certificate_and_registered_scope_are_ready(profile):
    assert evaluate(profile)["ready"] is True
    assert evaluate(profile)["certificate_remaining_seconds"] == 20 * 86400
    assert evaluate(profile, peer_der=profile["issued"](LOCATION.replace("http:", "https:")))["ready"] is True


@pytest.mark.parametrize("health", [{}, {"status": "degraded", "url_analysis": {"available": False}},
                                     {"status": "ok"}, {"status": "ok", "url_analysis": {"available": 1}}])
def test_missing_or_degraded_health_fails(profile, health):
    with pytest.raises(ValueError, match="unavailable or degraded"):
        evaluate(profile, health=health)


def test_certificate_and_crl_expiry_margins_fail(profile):
    with pytest.raises(ValueError, match="renewal"):
        evaluate(profile, peer_der=profile["issued"](expires=NOW + timedelta(days=2)))
    with pytest.raises(ValueError, match="CRL refresh"):
        evaluate(profile, bundle=profile["revocations"](expires=NOW + timedelta(hours=1)))


def test_unregistered_certificate_shard_or_issuer_rotation_fails(profile):
    with pytest.raises(ValueError, match="not registered"):
        evaluate(profile, peer_der=profile["issued"](location=LOCATION.replace("66.crl", "67.crl")))
    with pytest.raises(ValueError, match="issuer rotation"):
        evaluate(profile, peer_der=profile["issued"](signer=ec.generate_private_key(ec.SECP256R1())))


def test_registered_but_uncovered_shard_and_revoked_leaf_fail(profile):
    config = {**profile["config"], "urls": [LOCATION, LOCATION.replace("66.crl", "67.crl")]}
    with pytest.raises(ValueError, match="coverage"):
        evaluate(profile, config=config, peer_der=profile["issued"](location=LOCATION.replace("66.crl", "67.crl")))
    with pytest.raises(ValueError, match="revoked"):
        evaluate(profile, bundle=profile["revocations"](revoked=True))


def test_old_local_certificate_is_detected_using_live_peer(profile):
    old = x509.load_der_x509_certificate(profile["issued"]()).public_bytes(serialization.Encoding.PEM)
    with pytest.raises(ValueError, match="differs"):
        evaluate(profile, local_certificate=old)


@pytest.mark.parametrize("response_status", [200, 302, 503])
def test_public_request_is_fixed_bounded_and_ignores_proxy(monkeypatch, profile, response_status):
    calls = []

    class Response:
        status = response_status

        def read(self, size):
            assert size == monitor.MAX_HEALTH_BYTES + 1
            return json.dumps(profile["health"]).encode()

    class Connection:
        sock = None

        def __init__(self, host, port, *, timeout, context):
            assert (host, port, timeout) == ("qr.ohs92.com", 443, 5)
            assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
            assert context.minimum_version == ssl.TLSVersion.TLSv1_2
            self.sock = self

        def connect(self):
            calls.append("connect")

        def getpeercert(self, *, binary_form):
            assert binary_form
            return profile["peer_der"]

        def request(self, method, path, *, headers):
            assert method == "GET" and path == "/health"
            assert "Authorization" not in headers
            calls.append("request")

        def getresponse(self):
            return Response()

        def close(self):
            calls.append("close")

    monkeypatch.delenv("SSLKEYLOGFILE", raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setattr(monitor.http.client, "HTTPSConnection", Connection)
    if response_status == 200:
        health, peer = monitor.fetch_health()
        assert health == profile["health"] and peer == profile["peer_der"]
    else:
        with pytest.raises(ValueError, match="Public health request failed"):
            monitor.fetch_health()
    assert calls == ["connect", "request", "close"]
    monkeypatch.setenv("SSLKEYLOGFILE", "/tmp/forbidden-log")
    with pytest.raises(ValueError, match="key logging"):
        monitor.fetch_health()
    assert calls == ["connect", "request", "close"]
