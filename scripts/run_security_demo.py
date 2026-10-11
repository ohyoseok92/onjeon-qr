"""Run an isolated, fictional loopback target for the submitted ZAP plan.

Build frontend/dist first. No credentials or production data are printed/read.
The public QR fixture contains no authentication token or private key.
"""
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from onjeon.api import Settings, create_app
from onjeon.crypto import create_private_key


def main() -> None:
    previous = {key: os.environ.get(key) for key in ("ONJEON_ENV", "ONJEON_KEY_PASSWORD", "ONJEON_TLS_CRL_BUNDLE")}
    try:
        with TemporaryDirectory(prefix="onjeon-security-") as directory:
            root = Path(directory)
            os.environ["ONJEON_ENV"] = "production"
            os.environ["ONJEON_KEY_PASSWORD"] = secrets.token_urlsafe(48)
            now = datetime.now(timezone.utc)
            crl_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            crl_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic demo CRL issuer")])
            crl = (x509.CertificateRevocationListBuilder().issuer_name(crl_name).last_update(now - timedelta(minutes=1))
                   .next_update(now + timedelta(days=1)).sign(crl_key, hashes.SHA256()))
            crl_path = root / "synthetic-crl.pem"
            crl_path.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
            os.environ["ONJEON_TLS_CRL_BUNDLE"] = str(crl_path)
            settings = Settings(root / "state.sqlite3", root / "keys", secrets.token_urlsafe(48))
            key = create_private_key(settings.key_directory / "qa-city" / "v1.pem")
            app = create_app(settings)
            with TestClient(app) as client:
                registration = client.post("/admin/institutions", headers={"Authorization": "Bearer " + settings.admin_token}, json={
                    "institution_id": "qa-city", "name": "가상 시청 (시연 전용)",
                    "official_domains": ["demo.example.org"], "key_version": "v1", "public_key": key,
                })
                registration.raise_for_status()
                issuance = client.post("/institutions/qa-city/qrs", headers={"Authorization": "Bearer " + registration.json()["issuer_token"]}, json={
                    "destination": "https://demo.example.org/notice", "purpose": "시연 안내",
                    "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
                })
                issuance.raise_for_status()
            output = Path("demo-output")
            output.mkdir(exist_ok=True)
            (output / "security-demo-qr.json").write_text(json.dumps({"qr_text": issuance.json()["qr_text"]}), encoding="utf-8")
            print("Fictional security target: http://127.0.0.1:8001 (temporary data)", flush=True)
            uvicorn.run(app, host="127.0.0.1", port=8001, access_log=False, proxy_headers=False)
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


if __name__ == "__main__":
    main()
