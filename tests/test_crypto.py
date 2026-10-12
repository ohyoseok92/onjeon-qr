import pytest

from onjeon.crypto import b64url_encode, canonical_bytes, create_private_key, load_private_key, make_qr, parse_qr


def test_key_encryption_and_password_validation(tmp_path, monkeypatch):
    monkeypatch.setenv("ONJEON_KEY_PASSWORD", "key-passphrase-" * 4)
    path = tmp_path / "keys" / "v1.pem"
    public = create_private_key(path)
    assert b"BEGIN ENCRYPTED PRIVATE KEY" in path.read_bytes()
    assert b64url_encode(load_private_key(path).public_key().public_bytes_raw()) == public
    monkeypatch.setenv("ONJEON_KEY_PASSWORD", "different-passphrase-" * 4)
    with pytest.raises(ValueError):
        load_private_key(path)
    monkeypatch.setenv("ONJEON_KEY_PASSWORD", "short")
    with pytest.raises(ValueError):
        create_private_key(tmp_path / "must-not-exist.pem")
    assert not (tmp_path / "must-not-exist.pem").exists()


def test_configured_password_cannot_silently_use_plaintext_key(tmp_path, monkeypatch):
    monkeypatch.delenv("ONJEON_KEY_PASSWORD", raising=False)
    path = tmp_path / "v1.pem"
    create_private_key(path)
    monkeypatch.setenv("ONJEON_KEY_PASSWORD", "key-passphrase-" * 4)
    with pytest.raises(ValueError):
        load_private_key(path)


def test_boolean_protocol_version_is_rejected(tmp_path, monkeypatch):
    monkeypatch.delenv("ONJEON_KEY_PASSWORD", raising=False)
    path = tmp_path / "v1.pem"
    create_private_key(path)
    payload = {"version": True, "qr_id": "id", "institution_id": "city", "key_version": "v1",
               "destination": "https://city.example.org/", "purpose": "test", "issued_at": 1, "expires_at": 2}
    key = load_private_key(path)
    with pytest.raises(ValueError, match="fields"):
        parse_qr(make_qr(payload, key))
