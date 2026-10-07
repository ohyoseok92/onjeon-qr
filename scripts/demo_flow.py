"""Run a self-contained local demo with a fictional institution."""

import base64
import secrets
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from onjeon.api import Settings, create_app
from onjeon.crypto import create_private_key


def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        settings = Settings(root / "demo.sqlite3", root / "keys", secrets.token_urlsafe(32))
        public_key = create_private_key(settings.key_directory / "demo-city-v1.pem")
        client = TestClient(create_app(settings))
        registered = client.post(
            "/admin/institutions",
            headers={"Authorization": "Bearer " + settings.admin_token},
            json={
                "institution_id": "demo-city",
                "name": "가상 시청",
                "official_domains": ["city.example.org"],
                "key_version": "v1",
                "public_key": public_key,
            },
        )
        registered.raise_for_status()
        issuer_token = registered.json()["issuer_token"]
        issued = client.post(
            "/institutions/demo-city/qrs",
            headers={"Authorization": "Bearer " + issuer_token},
            json={
                "destination": "https://city.example.org/parking",
                "purpose": "주차요금 안내 데모",
                "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
                "include_png": True,
            },
        )
        issued.raise_for_status()
        qr = issued.json()
        output = Path("demo-output")
        output.mkdir(exist_ok=True)
        image_path = output / "signed-qr-demo.png"
        image_path.write_bytes(base64.b64decode(qr["qr_png_base64"]))
        before = client.post("/verify", json={"qr_text": qr["qr_text"]}).json()
        revoked = client.post(
            f"/institutions/demo-city/qrs/{qr['qr_id']}/revoke",
            headers={"Authorization": "Bearer " + issuer_token},
        )
        revoked.raise_for_status()
        after = client.post("/verify", json={"qr_text": qr["qr_text"]}).json()
        print(f"Before revocation: {before['status']} ({before['reason']})")
        print(f"After revocation: {after['status']} ({after['reason']})")
        print(f"Demo QR image: {image_path.resolve()}")


if __name__ == "__main__":
    main()
