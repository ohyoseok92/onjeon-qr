"""Actual signed CRLs exercise the offline operations publisher."""
import os
import sqlite3
import hmac
import json
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from scripts import crl_operations as operations

NOW = datetime(2026, 10, 11, 12, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def ca():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic CRL Operations CA")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(NOW - timedelta(days=30)).not_valid_after(NOW + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    return key, cert


def crl(ca, number=1, *, serials=(), start=None, end=None, bad_signature=False, delta=False,
        omit_number=False, omit_aki=False, scoped=False, idp=None, idp_critical=True, remove_reason=False):
    key, cert = ca
    builder = (x509.CertificateRevocationListBuilder().issuer_name(cert.subject)
               .last_update(start or NOW - timedelta(minutes=1)).next_update(end or NOW + timedelta(days=7)))
    if not omit_number:
        builder = builder.add_extension(x509.CRLNumber(number), critical=False)
    if not omit_aki:
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
    if delta:
        builder = builder.add_extension(x509.DeltaCRLIndicator(0), critical=True)
    if scoped:
        builder = builder.add_extension(x509.IssuingDistributionPoint(None, None, True, False, None, False, False), critical=True)
    if idp is not None:
        builder = builder.add_extension(idp, critical=idp_critical)
    for serial in serials:
        entry_builder = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(NOW - timedelta(days=1))
        if remove_reason:
            entry_builder = entry_builder.add_extension(x509.CRLReason(x509.ReasonFlags.remove_from_crl), critical=False)
        entry = entry_builder.build()
        builder = builder.add_revoked_certificate(entry)
    return builder.sign(ec.generate_private_key(ec.SECP256R1()) if bad_signature else key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def layout(tmp_path, ca):
    publish = tmp_path / "published"
    publish.mkdir(mode=0o700)
    operations.protect_directory(publish)
    issuers = tmp_path / "issuer-ca.pem"
    issuers.write_bytes(ca[1].public_bytes(serialization.Encoding.PEM))
    candidate = tmp_path / "candidate.pem"
    candidate.write_bytes(crl(ca, serials=(10,)))
    return {"custody": tmp_path / "custody", "bundle_path": publish / "crls.pem",
            "candidate": candidate, "issuers": issuers, "pins": [ca[1].fingerprint(hashes.SHA256()).hex()]}


def install(layout):
    return operations.initialize(**layout, approve_initial_installation=True, now=NOW)


def replace(layout, data):
    layout["candidate"].write_bytes(data)
    return operations.update(**{name: layout[name] for name in ("custody", "bundle_path", "candidate", "issuers")}, now=NOW)


def status(layout, **options):
    return operations.check(**{name: layout[name] for name in ("custody", "bundle_path", "issuers")}, now=NOW, **options)


def test_initial_approval_and_external_pin_are_required(layout):
    with pytest.raises(ValueError, match="approval"):
        operations.initialize(**layout, now=NOW)
    wrong = {**layout, "pins": ["0" * 64]}
    with pytest.raises(ValueError, match="trusted pins"):
        operations.initialize(**wrong, approve_initial_installation=True, now=NOW)
    assert not layout["custody"].exists()
    assert not layout["bundle_path"].exists()


def test_publish_update_and_restart_retain_generation(layout, ca):
    assert install(layout)["generation"] == 1
    assert status(layout)["ready"] is True
    updated = crl(ca, 2, serials=(10, 11))
    assert replace(layout, updated)["generation"] == 2
    assert status(layout)["generation"] == 2
    assert replace(layout, updated)["status"] == "unchanged"
    assert status(layout)["generation"] == 2


@pytest.mark.parametrize("options", [{"bad_signature": True}, {"delta": True}, {"omit_number": True},
                                       {"omit_aki": True}, {"scoped": True},
                                       {"end": NOW}, {"start": NOW + timedelta(minutes=1)}])
def test_invalid_crls_do_not_change_bundle_or_checkpoint(layout, ca, options):
    install(layout)
    before = layout["bundle_path"].read_bytes()
    with pytest.raises((ValueError, x509.ExtensionNotFound)):
        replace(layout, crl(ca, 2, serials=(10,), **options))
    assert layout["bundle_path"].read_bytes() == before
    assert status(layout)["generation"] == 1


@pytest.mark.parametrize("number,serials,start", [(0, (10,), None), (1, (10, 20), None),
                                                 (2, (10,), NOW - timedelta(days=1))])
def test_rollback_and_equivocation_rejected(layout, ca, number, serials, start):
    install(layout)
    before = layout["bundle_path"].read_bytes()
    with pytest.raises(ValueError):
        replace(layout, crl(ca, number, serials=serials, start=start))
    assert layout["bundle_path"].read_bytes() == before
    assert status(layout)["generation"] == 1


def test_authoritative_higher_number_crl_allows_issuer_serial_pruning(layout, ca):
    install(layout)
    previous = layout["bundle_path"].read_bytes()
    fresh = crl(ca, 2, serials=(), start=NOW)
    assert replace(layout, fresh)["generation"] == 2
    assert status(layout)["ready"] is True
    with pytest.raises(ValueError, match="rollback"):
        replace(layout, previous)
    assert layout["bundle_path"].read_bytes() == fresh


def test_failed_atomic_replace_remains_pending_and_recovers(layout, ca, monkeypatch):
    install(layout)
    before = layout["bundle_path"].read_bytes()
    candidate = crl(ca, 2, serials=(10, 20))
    real_replace = operations.os.replace

    def fail(*args):
        raise OSError("Synthetic replacement failure")

    monkeypatch.setattr(operations.os, "replace", fail)
    with pytest.raises(OSError):
        replace(layout, candidate)
    assert layout["bundle_path"].read_bytes() == before
    with pytest.raises(ValueError, match="pending"):
        status(layout)
    with pytest.raises(ValueError, match="Pending"):
        replace(layout, candidate)
    monkeypatch.setattr(operations.os, "replace", real_replace)
    result = operations.recover(**{name: layout[name] for name in ("custody", "bundle_path", "issuers")}, now=NOW)
    assert result["generation"] == 2
    assert layout["bundle_path"].read_bytes() == candidate
    assert status(layout)["ready"] is True


def test_failure_after_replace_before_commit_recovers_without_rollback(layout, ca, monkeypatch):
    install(layout)
    save = operations._save

    def fail_active(connection, key, state):
        if state["phase"] == "active":
            raise OSError("Synthetic post-replacement interruption")
        save(connection, key, state)

    monkeypatch.setattr(operations, "_save", fail_active)
    candidate = crl(ca, 2, serials=(10, 20))
    with pytest.raises(OSError):
        replace(layout, candidate)
    assert layout["bundle_path"].read_bytes() == candidate
    with pytest.raises(ValueError, match="pending"):
        status(layout)
    monkeypatch.setattr(operations, "_save", save)
    result = operations.recover(**{name: layout[name] for name in ("custody", "bundle_path", "issuers")}, now=NOW)
    assert result["generation"] == 2
    assert status(layout)["ready"] is True


def test_checkpoint_tampering_and_deletion_fail_closed(layout):
    install(layout)
    database = layout["custody"] / "checkpoint.sqlite3"
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("UPDATE state SET body=?", (b'{}',))
        connection.commit()
    with pytest.raises(ValueError, match="authentication"):
        status(layout)
    database.unlink()
    with pytest.raises((ValueError, FileNotFoundError)):
        status(layout)
    assert not database.exists()


def test_active_file_rollback_is_detected_and_not_reenrolled(layout, ca):
    install(layout)
    old = layout["bundle_path"].read_bytes()
    replace(layout, crl(ca, 2, serials=(10, 20)))
    layout["bundle_path"].write_bytes(old)
    with pytest.raises(ValueError, match="rollback"):
        status(layout)
    with pytest.raises(ValueError, match="differs"):
        replace(layout, crl(ca, 3, serials=(10, 20)))
    with pytest.raises(ValueError, match="already exists"):
        install(layout)


def test_expiry_margin_and_expired_status(layout):
    install(layout)
    assert status(layout, minimum_remaining_seconds=8 * 86400)["reason"] == "refresh_required"
    expired = operations.check(**{name: layout[name] for name in ("custody", "bundle_path", "issuers")},
                               now=NOW + timedelta(days=8))
    assert expired["reason"] == "expired"
    assert expired["ready"] is False


def test_trust_injection_and_missing_issuer_coverage_rejected(ca):
    certificate = ca[1].public_bytes(serialization.Encoding.PEM)
    pin = ca[1].fingerprint(hashes.SHA256()).hex()
    for bundle in (crl(ca) + certificate, b"", crl(ca) + b"arbitrary", b"x" * (operations.MAX_BYTES + 1)):
        with pytest.raises(ValueError):
            operations.validate_bundle(bundle, certificate, [pin], now=NOW)
    other = ec.generate_private_key(ec.SECP256R1())
    other_cert = (x509.CertificateBuilder().subject_name(ca[1].subject).issuer_name(ca[1].subject)
                  .public_key(other.public_key()).serial_number(2)
                  .not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=20))
                  .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
                  .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
                  .add_extension(x509.SubjectKeyIdentifier.from_public_key(other.public_key()), False)
                  .sign(other, hashes.SHA256()))
    with pytest.raises(ValueError, match="every pinned issuer"):
        operations.validate_bundle(crl(ca), certificate + other_cert.public_bytes(serialization.Encoding.PEM),
                                   [pin, other_cert.fingerprint(hashes.SHA256()).hex()], now=NOW)


def test_destination_is_bound_to_checkpoint(layout):
    install(layout)
    other = layout["bundle_path"].with_name("different.pem")
    with pytest.raises(ValueError, match="different destination"):
        operations.check(layout["custody"], other, layout["issuers"], now=NOW)


def test_concurrent_publish_allocates_one_generation(layout, ca):
    install(layout)
    layout["candidate"].write_bytes(crl(ca, 2, serials=(10, 20)))

    def publish():
        try:
            return operations.update(**{name: layout[name] for name in ("custody", "bundle_path", "candidate", "issuers")}, now=NOW)
        except ValueError as error:
            assert "Pending publication" in str(error)
            return {"status": "pending"}

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: publish(), range(2)))
    assert sum(result["status"] == "published" for result in results) == 1
    assert status(layout)["generation"] == 2
    assert status(layout)["ready"] is True


@pytest.mark.skipif(os.name == "nt", reason="POSIX-only mode check; Windows ACL exercised by core operations")
def test_insecure_checkpoint_permissions_are_rejected(layout):
    install(layout)
    key = layout["custody"] / "checkpoint-key.bin"
    key.chmod(0o644)
    with pytest.raises(ValueError, match="permissions"):
        status(layout)
    key.chmod(0o600)
    assert status(layout)["ready"] is True


SHARD_A = "http://synthetic.example.org/001.crl"
SHARD_B = "http://synthetic.example.org/002.crl"


def shard_idp(uri=SHARD_A, **options):
    return x509.IssuingDistributionPoint(
        options.pop("full_name", [x509.UniformResourceIdentifier(uri)]),
        options.pop("relative_name", None), options.pop("only_contains_user_certs", True),
        options.pop("only_contains_ca_certs", False), options.pop("only_some_reasons", None),
        options.pop("indirect_crl", False), options.pop("only_contains_attribute_certs", False))


def leaf(ca, distribution_point=SHARD_A, *, wrong_signer=False):
    key, certificate = ca
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "issued.example.org")])
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(certificate.subject)
               .public_key(ec.generate_private_key(ec.SECP256R1()).public_key())
               .serial_number(200).not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=30))
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True))
    if distribution_point is not None:
        builder = builder.add_extension(x509.CRLDistributionPoints([
            x509.DistributionPoint([x509.UniformResourceIdentifier(distribution_point)], None, None, None)]), critical=False)
    return builder.sign(ec.generate_private_key(ec.SECP256R1()) if wrong_signer else key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


def test_explicit_shard_approval_and_leaf_distribution_point(ca):
    certificate = ca[1].public_bytes(serialization.Encoding.PEM)
    pin = ca[1].fingerprint(hashes.SHA256()).hex()
    bundle = crl(ca, idp=shard_idp())
    with pytest.raises(ValueError, match="independently approved"):
        operations.validate_bundle(bundle, certificate, [pin], now=NOW)
    result = operations.validate_bundle(bundle, certificate, [pin], now=NOW,
                                        approved_distribution_points=[SHARD_A], issued_certificates=[leaf(ca)])
    assert len(result["records"]) == 1
    assert next(iter(result["records"].values()))["distribution_point"] == SHARD_A
    assert result["approved_distribution_points"] == [SHARD_A]
    for issued in (leaf(ca, SHARD_B), leaf(ca, wrong_signer=True), leaf(ca, None)):
        with pytest.raises((ValueError, x509.ExtensionNotFound)):
            operations.validate_bundle(bundle, certificate, [pin], now=NOW,
                                        approved_distribution_points=[SHARD_A], issued_certificates=[issued])


@pytest.mark.parametrize("options", [
    {"indirect_crl": True}, {"only_some_reasons": frozenset([x509.ReasonFlags.key_compromise])},
    {"only_contains_user_certs": False},
    {"only_contains_user_certs": False, "only_contains_ca_certs": True},
    {"only_contains_user_certs": False, "only_contains_attribute_certs": True},
    {"full_name": [x509.UniformResourceIdentifier(SHARD_A), x509.UniformResourceIdentifier(SHARD_B)]},
    {"full_name": [x509.DNSName("synthetic.example.org")]},
])
def test_unsupported_shard_scope_rejected(ca, options):
    certificate = ca[1].public_bytes(serialization.Encoding.PEM)
    pin = ca[1].fingerprint(hashes.SHA256()).hex()
    with pytest.raises(ValueError, match="direct user-certificate"):
        operations.validate_bundle(crl(ca, idp=shard_idp(**options)), certificate, [pin], now=NOW,
                                    approved_distribution_points=[SHARD_A])


def test_noncritical_shard_and_missing_approved_scope_rejected(ca):
    certificate = ca[1].public_bytes(serialization.Encoding.PEM)
    pin = ca[1].fingerprint(hashes.SHA256()).hex()
    with pytest.raises(ValueError, match="direct user-certificate"):
        operations.validate_bundle(crl(ca, idp=shard_idp(), idp_critical=False), certificate, [pin], now=NOW,
                                    approved_distribution_points=[SHARD_A])
    with pytest.raises(ValueError, match="every approved distribution point"):
        operations.validate_bundle(crl(ca, idp=shard_idp()), certificate, [pin], now=NOW,
                                    approved_distribution_points=[SHARD_A, SHARD_B])


def test_same_issuer_multiple_shards_keep_independent_numbers(layout, ca):
    a1 = crl(ca, 100, serials=(10,), idp=shard_idp())
    b1 = crl(ca, 5, serials=(20,), idp=shard_idp(SHARD_B))
    layout["candidate"].write_bytes(a1 + b1)
    issued = layout["candidate"].with_name("issued.pem")
    issued.write_bytes(leaf(ca))
    operations.initialize(**layout, approve_initial_installation=True, now=NOW,
                          approved_distribution_points=[SHARD_A, SHARD_B], issued_certificates=[issued])
    a2 = crl(ca, 101, serials=(10, 11), idp=shard_idp())
    assert replace(layout, a2 + b1)["generation"] == 2
    b2 = crl(ca, 6, serials=(20, 21), idp=shard_idp(SHARD_B))
    assert replace(layout, a2 + b2)["generation"] == 3
    with pytest.raises(ValueError, match="rollback"):
        replace(layout, a2 + b1)
    with pytest.raises(ValueError, match="cannot change"):
        replace(layout, a2 + b2 + crl(ca))
    assert status(layout)["generation"] == 3
    assert status(layout)["ready"] is True


def test_ca_only_complete_crl_requires_separate_approval_and_does_not_cover_leaf(ca):
    certificate = ca[1].public_bytes(serialization.Encoding.PEM)
    pin = ca[1].fingerprint(hashes.SHA256()).hex()
    idp = x509.IssuingDistributionPoint(None, None, False, True, None, False, False)
    bundle = crl(ca, idp=idp)
    with pytest.raises(ValueError):
        operations.validate_bundle(bundle, certificate, [pin], now=NOW)
    result = operations.validate_bundle(bundle, certificate, [pin], now=NOW, approve_ca_only_crls=True)
    assert result["records"][pin + ":ca-only"]["certificate_kind"] == "ca"
    assert result["approve_ca_only_crls"] is True
    with pytest.raises(ValueError, match="not covered"):
        operations.validate_bundle(bundle, certificate, [pin], now=NOW, approve_ca_only_crls=True,
                                    issued_certificates=[leaf(ca)])


def test_ca_only_approval_persists_without_enabling_scope_replacement(layout, ca):
    idp = x509.IssuingDistributionPoint(None, None, False, True, None, False, False)
    layout["candidate"].write_bytes(crl(ca, serials=(10,), idp=idp))
    operations.initialize(**layout, approve_initial_installation=True, approve_ca_only_crls=True, now=NOW)
    assert replace(layout, crl(ca, 2, serials=(10, 20), idp=idp))["generation"] == 2
    assert status(layout)["ready"] is True
    with pytest.raises(ValueError, match="identity set cannot change"):
        replace(layout, crl(ca, 3, serials=(10, 20)))


def test_explicit_remove_from_crl_entry_still_rejected(layout, ca):
    install(layout)
    with pytest.raises(ValueError, match="Removal from CRL"):
        replace(layout, crl(ca, 2, serials=(10,), remove_reason=True))
    assert status(layout)["generation"] == 1


def test_authenticated_v1_history_survives_scope_format_upgrade(layout, ca):
    install(layout)
    database = layout["custody"] / "checkpoint.sqlite3"
    key = (layout["custody"] / "checkpoint-key.bin").read_bytes()
    with closing(sqlite3.connect(database)) as connection:
        state = json.loads(connection.execute("SELECT body FROM state").fetchone()[0])
        state["version"] = 1
        state.pop("approved_distribution_points")
        state.pop("approve_ca_only_crls")
        for record in state["records"].values():
            for name in ("issuer_pin", "distribution_point", "certificate_kind"):
                record.pop(name)
        body = operations._encode(state)
        connection.execute("UPDATE state SET body=?,mac=?", (body, hmac.digest(key, operations.DOMAIN + body, "sha256")))
        connection.commit()
    assert status(layout)["generation"] == 1
    assert replace(layout, crl(ca, 2, serials=(10, 20)))["generation"] == 2
    assert status(layout)["ready"] is True
