"""Adversarial tests for externally pinned release verification."""
import base64
import hashlib
import json
import zipfile

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import release_gate as gate
from scripts.secure_profile import canonical, fingerprint


def signed_bundle(tmp_path, files=None, manifest=None, key=None):
    files = files or {"src/onjeon/example.py": b"print('synthetic')\n"}
    archive = tmp_path / "release.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
        for name, value in files.items():
            output.writestr(name, value)
        if manifest is None:
            manifest = "".join(f"{hashlib.sha256(value).hexdigest()}  {name}\n" for name, value in files.items())
        output.writestr("MANIFEST.sha256", manifest)
    key = key or Ed25519PrivateKey.generate()
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    payload = {"format": "onjeon-release-v1", "artifact_name": archive.name,
               "sha256": digest, "bytes": archive.stat().st_size}
    document = {"algorithm": "Ed25519", "payload": payload,
                "public_key_pem": key.public_key().public_bytes(serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii"),
                "public_key_fingerprint_sha256": fingerprint(key.public_key()),
                "signature_base64": base64.b64encode(key.sign(canonical(payload))).decode("ascii")}
    signature = tmp_path / "signature.json"
    signature.write_text(json.dumps(document), encoding="utf-8")
    return archive, signature, document["public_key_fingerprint_sha256"], digest


def test_complete_bundle_requires_external_inputs_and_matches_current_source(tmp_path):
    bundle = signed_bundle(tmp_path)
    source = tmp_path / "source"
    target = source / "src/onjeon/example.py"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"print('synthetic')\n")
    result = gate.verify_bundle(*bundle, source_root=source)
    assert result["verified"] and result["manifest_files"] == 1
    assert result["matches_current_source"] and not result["publisher_identity_verified"]
    target.write_bytes(b"changed\n")
    with pytest.raises(ValueError, match="current source"):
        gate.verify_bundle(*bundle, source_root=source)
    for index in [2, 3]:
        missing = list(bundle)
        missing[index] = ""
        with pytest.raises(ValueError, match="externally trusted"):
            gate.verify_bundle(*missing)


def test_valid_attacker_signature_and_valid_old_release_are_rejected(tmp_path):
    trusted = Ed25519PrivateKey.generate()
    old = signed_bundle(tmp_path, key=trusted)
    # A correctly signed old ZIP is rejected by the separately approved current digest.
    with pytest.raises(ValueError, match="independently approved"):
        gate.verify_bundle(old[0], old[1], old[2], "a" * 64)
    attacker = signed_bundle(tmp_path)
    with pytest.raises(ValueError, match="external trust anchor"):
        gate.verify_bundle(attacker[0], attacker[1], old[2], attacker[3])


@pytest.mark.parametrize("name", ["../outside.py", "src\\outside.py", "C:/outside.py", ".secrets/x", "src/../outside.py"])
def test_even_signed_archive_rejects_unsafe_paths(tmp_path, name):
    with pytest.raises(ValueError, match="archive path"):
        gate.verify_bundle(*signed_bundle(tmp_path, {name: b"synthetic"}))


@pytest.mark.parametrize("manifest", ["", "0" * 64 + "  src/onjeon/example.py\n", "malformed\n",
    ("0" * 64 + "  src/onjeon/example.py\n") * 2])
def test_even_signed_archive_rejects_incomplete_wrong_or_ambiguous_manifest(tmp_path, manifest):
    with pytest.raises(ValueError):
        gate.verify_bundle(*signed_bundle(tmp_path, manifest=manifest))


def test_duplicate_signature_json_properties_fail_closed(tmp_path):
    archive, signature, anchor, digest = signed_bundle(tmp_path)
    document = signature.read_text(encoding="utf-8")
    signature.write_text(document[:-1] + ', "algorithm":"Ed25519"}', encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate signature"):
        gate.verify_bundle(archive, signature, anchor, digest)


def test_size_limits_apply_before_expanding_even_signed_input(tmp_path, monkeypatch):
    bundle = signed_bundle(tmp_path)
    monkeypatch.setattr(gate, "MAX_UNPACKED_BYTES", 1)
    with pytest.raises(ValueError, match="Expanded archive"):
        gate.verify_bundle(*bundle)
    monkeypatch.setattr(gate, "MAX_ZIP_BYTES", 1)
    with pytest.raises(ValueError, match="size limit"):
        gate.verify_bundle(*bundle)
