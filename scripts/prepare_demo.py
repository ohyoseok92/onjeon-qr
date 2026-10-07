"""Seed one fictional institution for a persistent local browser demonstration."""

import base64
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from onjeon.api import Settings, create_app
from onjeon.crypto import create_private_key


def main() -> None:
    settings = Settings.from_environment()
    institution_id = "demo-" + secrets.token_hex(4)
    key_version = "v1"
    public_key = create_private_key(settings.key_directory / institution_id / f"{key_version}.pem")
    client = TestClient(create_app(settings))
    registered = client.post(
        "/admin/institutions",
        headers={"Authorization": "Bearer " + settings.admin_token},
        json={
            "institution_id": institution_id,
            "name": "가상 시청 (시연 전용)",
            "official_domains": ["demo.example.org"],
            "key_version": key_version,
            "public_key": public_key,
        },
    )
    registered.raise_for_status()
    token = registered.json()["issuer_token"]
    issued = client.post(
        f"/institutions/{institution_id}/qrs",
        headers={"Authorization": "Bearer " + token},
        json={
            "destination": "https://demo.example.org/notice",
            "purpose": "가상 시청 안내 시연",
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
            "include_png": True,
        },
    )
    issued.raise_for_status()
    output = Path("demo-output")
    output.mkdir(exist_ok=True)
    image = output / f"{institution_id}.png"
    image.write_bytes(base64.b64decode(issued.json()["qr_png_base64"]))
    print(f"기관 ID: {institution_id}")
    print(f"발급 토큰(이번 출력만 표시): {token}")
    print(f"QR 이미지: {image.resolve()}")
    print(f"QR 원문: {issued.json()['qr_text']}")
    print("실제 기관이나 운영 주소가 아닙니다. 목적지 링크는 열지 마세요.")


if __name__ == "__main__":
    main()
