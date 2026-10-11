"""TLS entry point for the isolated local Docker profile; never logs credentials."""
import os
from pathlib import Path

import uvicorn


def load_configuration() -> None:
    path = Path(os.environ.get("ONJEON_ENV_FILE", "/run/app-secrets/production.env"))
    if path.stat().st_size > 16384:
        raise RuntimeError("Invalid secret configuration")
    values = dict(line.split("=", 1) for line in path.read_text(encoding="ascii").splitlines() if line)
    if set(values) != {"ONJEON_ENV", "ONJEON_ADMIN_TOKEN", "ONJEON_KEY_PASSWORD"} or values["ONJEON_ENV"] != "production":
        raise RuntimeError("Invalid secret configuration")
    os.environ.update(values)


def main() -> None:
    load_configuration()
    uvicorn.run("onjeon.api:create_default_app", factory=True, host="0.0.0.0", port=8443,
                proxy_headers=False, access_log=False,
                ssl_certfile="/run/tls/server.crt", ssl_keyfile="/run/tls/server.key",
                ssl_keyfile_password=os.environ["ONJEON_KEY_PASSWORD"])


if __name__ == "__main__":
    main()
