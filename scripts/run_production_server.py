"""File-based secrets for an origin published only on the host loopback.

Only the dedicated Docker bridge gateway may supply sanitized Nginx forwarding
headers. Never publish this container's HTTP port on a public interface.
"""
import ipaddress
import os
import sys

import uvicorn

sys.path.insert(0, "/app/scripts")
from run_tls_server import load_configuration


def main() -> None:
    load_configuration()
    trusted_proxy = os.environ.get("ONJEON_TRUSTED_PROXY_IP", "")
    try:
        # Uvicorn accepts networks and '*'; require one exact gateway instead.
        trusted_proxy = str(ipaddress.ip_address(trusted_proxy))
    except ValueError as exc:
        raise RuntimeError("ONJEON_TRUSTED_PROXY_IP must be one Docker gateway IP") from exc
    uvicorn.run("onjeon.api:create_default_app", factory=True, host="0.0.0.0", port=8000,
                proxy_headers=True, forwarded_allow_ips=trusted_proxy, access_log=False)


if __name__ == "__main__":
    main()
