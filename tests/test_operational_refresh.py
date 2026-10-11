"""Registered CRL downloads plus real signed publication and persistent history."""
import io
import json
import sqlite3
import subprocess
import urllib.request
from datetime import datetime
from email.message import Message
from urllib.response import addinfourl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from scripts import refresh_operational_crls as refresh
from scripts.secure_profile import private_write
from test_crl_operations import NOW, ca, crl, layout  # Reuse the real signed CA fixture.


URL = "http://e7.c.lencr.org/123.crl"


@pytest.mark.parametrize("url", [
    "http://unapproved.example.org/123.crl", "http://e7.c.lencr.org.evil.example/123.crl",
    "http://user@e7.c.lencr.org/123.crl", "http://user:password@e7.c.lencr.org/123.crl",
    "http://e7.c.lencr.org:80/123.crl", "http://e7.c.lencr.org:bad/123.crl",
    "http://e7.c.lencr.org/123.crl?source=other", "http://e7.c.lencr.org/123.crl#fragment",
    "ftp://e7.c.lencr.org/123.crl", "http://e7.c.lencr.org/../123.crl",
])
def test_unapproved_urls_are_rejected_before_any_network_operation(url, monkeypatch):
    monkeypatch.setattr(refresh.urllib.request, "build_opener", lambda *_a: pytest.fail("must not open network"))
    with pytest.raises(ValueError):
        refresh.fetch(url)


def fake_transport(monkeypatch, *, data, status=200, location=None):
    """Use the real urllib redirect processor with a synthetic HTTP transport."""
    real_build_opener = urllib.request.build_opener
    requests = []

    class Transport(urllib.request.HTTPHandler):
        def http_open(self, request):
            requests.append((request.full_url, request.timeout))
            headers = Message()
            if location:
                headers["Location"] = location
            response = addinfourl(io.BytesIO(data), headers, request.full_url, status)
            response.msg = "Synthetic"
            return response

    monkeypatch.setattr(refresh.urllib.request, "build_opener",
                        lambda *handlers: real_build_opener(*handlers, Transport()))
    return requests


def test_real_redirect_handler_denies_redirect_to_another_host(monkeypatch):
    requests = fake_transport(monkeypatch, data=b"", status=302,
                              location="http://unapproved.example.org/123.crl")
    with pytest.raises(ValueError, match="redirects"):
        refresh.fetch(URL)
    assert requests == [(URL, 15)]


def test_bounded_fetch_rejects_oversize(monkeypatch):
    requests = fake_transport(monkeypatch, data=b"x" * (refresh.ops.MAX_BYTES + 1))
    with pytest.raises(ValueError, match="size limit"):
        refresh.fetch(URL)
    assert requests == [(URL, 15)]


def test_non_success_http_status_is_not_parsed_or_published(monkeypatch):
    requests = fake_transport(monkeypatch, data=b"synthetic failure", status=404)
    with pytest.raises(urllib.error.HTTPError):
        refresh.fetch(URL)
    assert requests == [(URL, 15)]


def test_bounded_der_download_is_normalized_to_a_signed_pem_crl(monkeypatch, ca):
    source = x509.load_pem_x509_crl(crl(ca))
    requests = fake_transport(monkeypatch, data=source.public_bytes(serialization.Encoding.DER))
    result = x509.load_pem_x509_crl(refresh.fetch(URL))
    assert result.is_signature_valid(ca[1].public_key())
    assert requests == [(URL, 15)]


@pytest.fixture
def registration(layout, monkeypatch):
    class FixedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW if tz else NOW.replace(tzinfo=None)

    monkeypatch.setattr(refresh.ops, "datetime", FixedDatetime)
    config = layout["bundle_path"].parent / "registered-sources.json"
    value = {"urls": [URL], "issuer_pins": layout["pins"]}
    private_write(config, json.dumps(value).encode())
    arguments = {"config_file": config, "custody": layout["custody"],
                 "bundle": layout["bundle_path"], "issuers": layout["issuers"]}
    return arguments


def no_temporary_files(registration):
    parent = registration["bundle"].parent
    assert not list(parent.glob(".incoming-*"))
    assert not list(parent.glob(".crl-stage-*"))


def install(registration, ca, monkeypatch):
    monkeypatch.setattr(refresh, "fetch", lambda _url: crl(ca, serials=(10,)))
    return refresh.refresh(**registration, initialize=True, approved_initial_installation=True)


def test_explicit_initial_approval_updates_and_persistent_rollback_rejection(registration, ca, monkeypatch):
    monkeypatch.setattr(refresh, "fetch", lambda _url: crl(ca, serials=(10,)))
    with pytest.raises(ValueError, match="approval"):
        refresh.refresh(**registration, initialize=True)
    assert not registration["custody"].exists() and not registration["bundle"].exists()
    no_temporary_files(registration)
    assert install(registration, ca, monkeypatch)["generation"] == 1
    current = crl(ca, 2, serials=(10, 11))
    monkeypatch.setattr(refresh, "fetch", lambda _url: current)
    result = refresh.refresh(**registration)
    assert result["generation"] == 2 and result["ready"]
    database = registration["custody"] / "checkpoint.sqlite3"
    committed_history = database.read_bytes()
    monkeypatch.setattr(refresh, "fetch", lambda _url: crl(ca, serials=(10,)))
    with pytest.raises(ValueError, match="rollback"):
        refresh.refresh(**registration)
    assert registration["bundle"].read_bytes() == current
    assert database.read_bytes() == committed_history
    no_temporary_files(registration)


def test_failed_second_fetch_preserves_bundle_checkpoint_and_clears_staging(registration, ca, monkeypatch):
    install(registration, ca, monkeypatch)
    old = registration["bundle"].read_bytes()
    database = registration["custody"] / "checkpoint.sqlite3"
    history = database.read_bytes()
    config = registration["config_file"]
    values = json.loads(config.read_text())
    values["urls"].append("http://e7.c.lencr.org/124.crl")
    config.write_text(json.dumps(values), encoding="utf-8")
    requests = []

    def fetch(url):
        requests.append(url)
        if len(requests) == 2:
            raise OSError("Synthetic download interruption")
        return crl(ca, 2, serials=(10, 11))

    monkeypatch.setattr(refresh, "fetch", fetch)
    with pytest.raises(OSError):
        refresh.refresh(**registration)
    assert requests == values["urls"]
    assert registration["bundle"].read_bytes() == old and database.read_bytes() == history
    no_temporary_files(registration)


def test_downloaded_wrong_signature_preserves_bundle_and_authenticated_history(registration, ca, monkeypatch):
    install(registration, ca, monkeypatch)
    old = registration["bundle"].read_bytes()
    database = registration["custody"] / "checkpoint.sqlite3"
    history = database.read_bytes()
    monkeypatch.setattr(refresh, "fetch", lambda _url: crl(ca, 2, bad_signature=True))
    with pytest.raises(ValueError, match="signature"):
        refresh.refresh(**registration)
    assert registration["bundle"].read_bytes() == old and database.read_bytes() == history
    no_temporary_files(registration)


@pytest.mark.parametrize("failure", ["tampered", "missing"])
def test_checkpoint_failure_does_not_publish_or_silently_reinitialize(registration, ca, monkeypatch, failure):
    install(registration, ca, monkeypatch)
    old = registration["bundle"].read_bytes()
    database = registration["custody"] / "checkpoint.sqlite3"
    if failure == "tampered":
        with sqlite3.connect(database) as connection:
            connection.execute("UPDATE state SET body=?", (b'{}',))
        tampered_history = database.read_bytes()
    else:
        database.unlink()
    monkeypatch.setattr(refresh, "fetch", lambda _url: crl(ca, 2, serials=(10, 11)))
    with pytest.raises((ValueError, FileNotFoundError, subprocess.CalledProcessError)):
        refresh.refresh(**registration)
    assert registration["bundle"].read_bytes() == old
    if failure == "tampered":
        assert database.read_bytes() == tampered_history
    else:
        assert not database.exists()
    no_temporary_files(registration)
