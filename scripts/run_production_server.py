"""File-based secrets for an origin published only on the host loopback.

The public TLS endpoint is the dedicated Nginx virtual host. Do not publish this
container's HTTP port on a public interface or trust forwarded identity headers.
"""
import sys

import uvicorn

sys.path.insert(0, "/app/scripts")
from run_tls_server import load_configuration


def main() -> None:
    load_configuration()
    uvicorn.run("onjeon.api:create_default_app", factory=True, host="0.0.0.0", port=8000,
                proxy_headers=False, access_log=False)


if __name__ == "__main__":
    main()
