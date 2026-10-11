"""Probe only an operator-specified host's HTTPS /health on public port 443.

Uses system CA and hostname verification; never follows redirects or downloads
certificate distribution points. --cafile is exclusively a synthetic test mode
and can never produce all_ready=true or public_ca_verified=true.
"""
from __future__ import annotations

import argparse
import http.client
import json
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509

MAX_HEALTH_BYTES = 65536
TIMEOUT_SECONDS = 10.0
MIN_EXPIRY_SECONDS = 3 * 24 * 60 * 60


def normalize_hostname(hostname: str) -> str:
    if not isinstance(hostname, str) or not hostname or hostname != hostname.strip():
        raise ValueError("invalid_hostname")
    try:
        hostname = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("invalid_hostname") from None
    if len(hostname) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                                  for label in hostname.split(".")):
        raise ValueError("invalid_hostname")
    return hostname


def security_headers(headers: list[tuple[str, str]]) -> dict[str, bool]:
    values: dict[str, list[str]] = {}
    for name, value in headers:
        values.setdefault(name.lower(), []).append(value)

    def one(name: str) -> str:
        actual = values.get(name, [])
        return actual[0].strip() if len(actual) == 1 else ""

    hsts = [part.strip().lower() for part in one("strict-transport-security").split(";")]
    ages = [part[8:] for part in hsts if part.startswith("max-age=")]
    hsts_ready = (len(ages) == 1 and bool(re.fullmatch(r"[0-9]{1,12}", ages[0]))
                  and int(ages[0]) >= 31536000 and "includesubdomains" in hsts)
    csp = {}
    for part in one("content-security-policy").split(";"):
        tokens = part.split()
        if not tokens:
            continue
        if tokens[0].lower() in csp:
            csp = {}
            break
        csp[tokens[0].lower()] = tokens[1:]
    return {
        "hsts": hsts_ready,
        "nosniff": one("x-content-type-options").lower() == "nosniff",
        "referrer_policy": one("referrer-policy").lower() == "no-referrer",
        "permissions_policy": one("permissions-policy").lower() == "camera=(self)",
        "cache_no_store": "no-store" in [part.strip().lower() for part in one("cache-control").split(",")],
        "content_security_policy": all(csp.get(name) == values for name, values in {
            "default-src": ["'self'"], "object-src": ["'none'"], "base-uri": ["'none'"],
            "frame-ancestors": ["'none'"], "form-action": ["'self'"], "connect-src": ["'self'"],
        }.items()),
    }


def _health_result(body: bytes, allow_analysis_degraded: bool) -> tuple[bool, bool]:
    """Health availability is not an issuance/verification functional smoke test."""
    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError("invalid_health_json")
            result[name] = value
        return result

    try:
        value = json.loads(body, object_pairs_hook=unique)
    except (ValueError, UnicodeError):
        raise ValueError("invalid_health_json") from None
    if not isinstance(value, dict) or not isinstance(value.get("url_analysis"), dict):
        raise ValueError("invalid_health_schema")
    status = value.get("status")
    available = value["url_analysis"].get("available")
    if status == "ok" and available is True:
        return True, True
    if status == "degraded" and available is False:
        return allow_analysis_degraded, False
    raise ValueError("invalid_health_schema")


def check_public_tls(hostname: str, *, cafile: Path | None = None,
                     allow_analysis_degraded: bool = False, _port: int = 443) -> dict:
    """_port exists for local synthetic tests; the CLI always connects to 443."""
    result = {"hostname": None, "port": _port, "all_ready": False,
              "trust_mode": "system_ca" if cafile is None else "synthetic_test_custom_ca",
              "public_ca_verified": False, "tls_verified": False, "tls_protocol": None,
              "leaf_valid_for_at_least_three_days": False, "health_reachable": False,
              "qr_service_health_ready": False, "analysis_ready": False,
              "security_headers": {}, "checks_passed": False, "failure_codes": []}
    connection = None
    try:
        hostname = normalize_hostname(hostname)
        result["hostname"] = hostname
        # Build explicitly so SSLKEYLOGFILE never enables TLS secret logging.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        if cafile is None:
            context.load_default_certs(ssl.Purpose.SERVER_AUTH)
        else:
            context.load_verify_locations(cafile=str(cafile))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        connection = http.client.HTTPSConnection(hostname, _port, context=context, timeout=TIMEOUT_SECONDS)
        deadline = time.monotonic() + TIMEOUT_SECONDS
        connection.connect()
        if connection.sock is None:
            raise ValueError("probe_validation_failed")
        peer = connection.sock
        result["tls_protocol"] = peer.version()
        result["tls_verified"] = True
        result["public_ca_verified"] = cafile is None
        certificate = x509.load_der_x509_certificate(peer.getpeercert(binary_form=True))
        remaining = (certificate.not_valid_after_utc - datetime.now(timezone.utc)).total_seconds()
        result["leaf_valid_for_at_least_three_days"] = remaining >= MIN_EXPIRY_SECONDS
        if remaining < MIN_EXPIRY_SECONDS:
            result["failure_codes"].append("certificate_expires_within_three_days")
        connection.request("GET", "/health", headers={"Accept": "application/json", "Accept-Encoding": "identity"})
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError("health_http_status_not_200")
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise ValueError("unsupported_health_encoding")
        result["security_headers"] = security_headers(response.getheaders())
        data = bytearray()
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError()
            peer.settimeout(left)
            chunk = response.read1(min(16384, MAX_HEALTH_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > MAX_HEALTH_BYTES:
                raise ValueError("health_response_too_large")
        result["health_reachable"] = True
        service, analysis = _health_result(bytes(data), allow_analysis_degraded)
        result["qr_service_health_ready"] = service
        result["analysis_ready"] = analysis
        if not analysis:
            result["failure_codes"].append("analysis_unavailable")
        if not all(result["security_headers"].values()):
            result["failure_codes"].append("security_headers_missing_or_invalid")
        result["checks_passed"] = (result["tls_verified"] and result["leaf_valid_for_at_least_three_days"]
                                   and service and analysis and all(result["security_headers"].values()))
        result["all_ready"] = result["checks_passed"] and cafile is None and _port == 443
        if cafile is not None:
            result["failure_codes"].append("custom_ca_is_synthetic_test_only")
    except ssl.SSLError:
        result["failure_codes"].append("tls_validation_failed")
    except (TimeoutError, socket.timeout):
        result["failure_codes"].append("connection_or_read_timeout")
    except ValueError as error:
        allowed = {"invalid_hostname", "health_http_status_not_200", "unsupported_health_encoding",
                   "health_response_too_large", "invalid_health_json", "invalid_health_schema"}
        result["failure_codes"].append(str(error) if str(error) in allowed else "probe_validation_failed")
    except (OSError, http.client.HTTPException):
        result["failure_codes"].append("connection_or_protocol_failed")
    finally:
        if connection is not None:
            connection.close()
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--cafile", type=Path, help="Synthetic test CA only; never certifies public readiness")
    parser.add_argument("--allow-analysis-degraded", action="store_true", help="Report health-based QR availability; all_ready remains false")
    args = parser.parse_args()
    result = check_public_tls(args.hostname, cafile=args.cafile, allow_analysis_degraded=args.allow_analysis_degraded)
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    raise SystemExit(0 if result["all_ready"] else 1)


if __name__ == "__main__":
    main()
