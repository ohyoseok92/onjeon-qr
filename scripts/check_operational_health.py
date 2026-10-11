"""Check the fixed public service and its registered certificate/CRL scope.

Uses the actual TLS peer certificate, public configuration only, system CA trust,
no proxies, no redirects, no authorization and no private checkpoint/key mounts.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes

if __package__:
    from . import crl_operations as ops
else:
    import crl_operations as ops

HOST = "qr.ohs92.com"
HEALTH_PATH = "/health"
MAX_HEALTH_BYTES = 4096
CERTIFICATE_MARGIN_SECONDS = 3 * 86400
CRL_MARGIN_SECONDS = 2 * 3600


def fetch_health() -> tuple[dict, bytes]:
    if os.getenv("SSLKEYLOGFILE"):
        raise ValueError("TLS key logging is forbidden")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_default_certs()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    connection = http.client.HTTPSConnection(HOST, 443, timeout=5, context=context)
    try:
        connection.connect()
        certificate = connection.sock.getpeercert(binary_form=True)
        connection.request("GET", HEALTH_PATH, headers={"Accept": "application/json", "User-Agent": "Onjeon-Operations/1"})
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError("Public health request failed")
        body = response.read(MAX_HEALTH_BYTES + 1)
        if len(body) > MAX_HEALTH_BYTES:
            raise ValueError("Health response exceeds size limit")
        return json.loads(body), certificate
    finally:
        connection.close()


def _location(uri: str) -> tuple[str, str]:
    parsed = urlsplit(uri)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password
            or parsed.port or parsed.query or parsed.fragment or not parsed.path):
        raise ValueError("Invalid registered CRL location")
    return parsed.hostname.lower(), parsed.path


def _signed_by(certificate: x509.Certificate, issuers: dict[str, x509.Certificate]) -> str:
    matches = []
    for pin, issuer in issuers.items():
        if not issuer.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
            continue
        try:
            certificate.verify_directly_issued_by(issuer)
            matches.append(pin)
        except (InvalidSignature, ValueError):
            pass
    if len(matches) != 1:
        raise ValueError("Certificate issuer rotation is outside the pinned scope")
    return matches[0]


def _not_revoked(certificate: x509.Certificate, records: list[dict]) -> None:
    if not records or any(str(certificate.serial_number) in record["revoked_serials"] for record in records):
        raise ValueError("Certificate is revoked or lacks registered CRL coverage")


def evaluate(health: dict, peer_der: bytes, config: dict, bundle: bytes, ca_bundle: bytes, *,
             now: datetime | None = None, local_certificate: bytes | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    if health.get("status") != "ok" or health.get("url_analysis", {}).get("available") is not True:
        raise ValueError("Public service is unavailable or degraded")
    if not isinstance(config.get("urls"), list) or not config["urls"]:
        raise ValueError("Registered CRL sources are missing")
    registered = {_location(uri) for uri in config["urls"]}
    validated = ops.validate_bundle(bundle, ca_bundle, config["issuer_pins"], now=now,
        approved_distribution_points=config.get("distribution_points", []),
        approve_ca_only_crls=config.get("approve_ca_only_crls", False))
    records = list(validated["records"].values())
    remaining = min((datetime.fromisoformat(record["next_update"]) - now).total_seconds() for record in records)
    if remaining < CRL_MARGIN_SECONDS:
        raise ValueError("CRL refresh is required")
    certificates = [x509.load_pem_x509_certificate(block) for block in ops._blocks(ca_bundle, ops.CERT_RE)]
    issuers = {certificate.fingerprint(hashes.SHA256()).hex(): certificate for certificate in certificates}
    # Check registered intermediate certificates too. Public system CA trust on
    # the live handshake remains mandatory and is not replaced by these pins.
    for certificate in certificates:
        if certificate.subject == certificate.issuer:
            certificate.verify_directly_issued_by(certificate)
            continue
        pin = _signed_by(certificate, issuers)
        _not_revoked(certificate, [record for record in records if record["issuer_pin"] == pin
                                  and record["certificate_kind"] in {"all", "ca"}])
    peer = x509.load_der_x509_certificate(peer_der)
    if peer.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("Peer certificate is not a leaf")
    if not peer.not_valid_before_utc <= now < peer.not_valid_after_utc:
        raise ValueError("Peer certificate is outside its validity window")
    certificate_remaining = (peer.not_valid_after_utc - now).total_seconds()
    if certificate_remaining < CERTIFICATE_MARGIN_SECONDS:
        raise ValueError("Certificate renewal is required")
    if local_certificate is not None:
        local = x509.load_pem_x509_certificate(local_certificate)
        if local.fingerprint(hashes.SHA256()) != peer.fingerprint(hashes.SHA256()):
            raise ValueError("Published certificate differs from monitored local certificate")
    issuer_pin = _signed_by(peer, issuers)
    leaf_records = [record for record in records if record["issuer_pin"] == issuer_pin
                    and record["certificate_kind"] in {"all", "user"}]
    full_records = [record for record in leaf_records if record["certificate_kind"] == "all"]
    if full_records:
        _not_revoked(peer, full_records)
    else:
        points = peer.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        covered = []
        for point in points:
            if (point.relative_name is not None or point.reasons is not None or point.crl_issuer is not None
                    or point.full_name is None or len(point.full_name) != 1
                    or not isinstance(point.full_name[0], x509.UniformResourceIdentifier)):
                raise ValueError("Unsupported live certificate distribution point")
            location = _location(point.full_name[0].value)
            if location not in registered:
                raise ValueError("Live certificate CRL location is not registered")
            covered.extend(record for record in leaf_records
                           if _location(record["distribution_point"]) == location)
        _not_revoked(peer, covered)
    return {"ready": True, "reason": "ready", "public_tls_system_ca_verified": True,
            "certificate_remaining_seconds": int(certificate_remaining),
            "crl_remaining_seconds": int(remaining), "registered_issuer_count": len(issuers),
            "certificate_sha256": peer.fingerprint(hashes.SHA256()).hex(),
            "bundle_sha256": hashlib.sha256(bundle).hexdigest()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--issuers", type=Path, required=True)
    parser.add_argument("--certificate", type=Path)
    args = parser.parse_args()
    try:
        config_data = ops._read(args.config)
        if len(config_data) > 16384:
            raise ValueError("Operator configuration exceeds limit")
        config = json.loads(config_data)
        health, peer = fetch_health()
        result = evaluate(health, peer, config, ops._read(args.bundle), ops._read(args.issuers),
                          local_certificate=ops._read(args.certificate) if args.certificate else None)
        print(json.dumps(result, sort_keys=True))
    except Exception:
        # Operational alerts must not expose raw response/configuration content.
        print(json.dumps({"ready": False, "reason": "operational_health_failed"}))
        sys.exit(1)


if __name__ == "__main__":
    main()
