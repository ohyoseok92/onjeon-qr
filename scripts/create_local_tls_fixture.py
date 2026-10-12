"""Create a short-lived local CA/certificate/CRL inside the protected profile.

This test CA is never installed in the OS and is unsuitable for public hosting.
Its private signing key is not retained. Existing files are never overwritten.
"""
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from secure_profile import PROFILE, load_profile, private_write, protect_directory, verify_private


def create_fixture() -> dict:
    load_profile()
    destination = PROFILE / "tls-local"
    destination.mkdir(mode=0o700, exist_ok=False)
    protect_directory(destination)
    values = dict(line.split("=", 1) for line in (PROFILE / "application/production.env").read_text().splitlines())
    now = datetime.now(timezone.utc)
    authority = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Onjeon Local Test CA")])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(authority.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
          .not_valid_after(now + timedelta(days=3))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(authority.public_key()), critical=False)
          .sign(authority, hashes.SHA256()))
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(name).public_key(server.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(authority.public_key()), critical=False)
            .sign(authority, hashes.SHA256()))
    crl = (x509.CertificateRevocationListBuilder().issuer_name(name).last_update(now - timedelta(minutes=1))
           .next_update(now + timedelta(days=2))
           .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(authority.public_key()), critical=False)
           .sign(authority, hashes.SHA256()))
    private_write(destination / "server.key", server.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                  serialization.BestAvailableEncryption(values["ONJEON_KEY_PASSWORD"].encode("ascii"))))
    for filename, artifact in (("ca.crt", ca), ("server.crt", cert), ("revocations.pem", crl)):
        private_write(destination / filename, artifact.public_bytes(serialization.Encoding.PEM))
    return {"created": True, "test_only": True, "ca_not_installed_in_os": True,
            "private_ca_key_retained": False, "encrypted_server_key": True,
            "certificate_expires_utc": cert.not_valid_after_utc.isoformat(), "acl": verify_private(destination)}


if __name__ == "__main__":
    import json
    print(json.dumps(create_fixture(), indent=2))
