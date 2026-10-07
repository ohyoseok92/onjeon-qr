"""Conservative, read-only inspection of an unsigned QR URL.

The network probe sends HEAD only. Every redirect is resolved again, and the
TLS connection is pinned to a checked public IP to avoid DNS rebinding.
"""

import http.client
import ipaddress
import re
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from difflib import SequenceMatcher
from urllib.parse import quote, urljoin, urlsplit


HOST_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")
INSTALL_RE = re.compile(r"\.(?:apk|exe|msi|dmg|pkg|ipa)(?:\Z|[/?#])", re.IGNORECASE)
MAX_REDIRECTS = 3
ANALYSIS_SLOTS = threading.BoundedSemaphore(4)
DNS_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="onjeon-dns")


def _parse_url(value: str) -> tuple[str, str] | None:
    if len(value) > 2048 or any(ord(c) < 33 or c.isspace() or c == "\\" for c in value):
        return None
    try:
        parts = urlsplit(value)
        host = parts.hostname
        if (
            parts.scheme.lower() not in ("http", "https")
            or not host
            or parts.username is not None
            or parts.password is not None
            or parts.port not in (None, 80, 443)
            or (parts.scheme.lower() == "https" and parts.port == 80)
            or (parts.scheme.lower() == "http" and parts.port == 443)
            or not host.isascii()
            or not HOST_RE.fullmatch(host.lower())
        ):
            return None
        return parts.scheme.lower(), host.lower()
    except ValueError:
        return None


def _resolve_public(host: str) -> str:
    future = DNS_EXECUTOR.submit(socket.getaddrinfo, host, 443, type=socket.SOCK_STREAM)
    try:
        answers = future.result(timeout=2)
    except FutureTimeout as exc:
        future.cancel()
        raise OSError("DNS lookup timed out") from exc
    addresses = {item[4][0] for item in answers}
    if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
        raise ValueError("non_public_address")
    return sorted(addresses, key=lambda ip: (ipaddress.ip_address(ip).version, ip))[0]


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str):
        super().__init__(host, port=443, timeout=3, context=ssl.create_default_context())
        self.address = address

    def connect(self) -> None:
        raw = socket.create_connection((self.address, 443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def _head(url: str, host: str, address: str) -> tuple[int, str | None]:
    parts = urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    path = quote(path, safe="/%:@!$&'()*+,;=-._~?")
    connection = _PinnedHTTPSConnection(host, address)
    def abort() -> None:
        if connection.sock is not None:
            try:
                connection.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()

    timer: threading.Timer | None = None
    try:
        connection.connect()
        timer = threading.Timer(4, abort)
        timer.daemon = True
        timer.start()
        connection.request("HEAD", path, headers={"User-Agent": "OnjeonQR-Inspector/1.0", "Accept": "*/*"})
        response = connection.getresponse()
        return response.status, response.getheader("Location")
    finally:
        if timer is not None:
            timer.cancel()
        connection.close()


def _official(host: str, domains: list[str]) -> bool:
    return host in domains


def analyze_url(value: str, official_domains: list[str]) -> dict:
    """Return warnings, never an institution-authenticated or safe verdict."""
    if not ANALYSIS_SLOTS.acquire(blocking=False):
        return {"status": "warning", "reason": "analyzer_busy", "signals": ["analyzer_busy"]}
    try:
        return _analyze_url(value, official_domains)
    finally:
        ANALYSIS_SLOTS.release()


def _analyze_url(value: str, official_domains: list[str]) -> dict:
    deadline = time.monotonic() + 10
    parsed = _parse_url(value)
    if parsed is None:
        return {"status": "blocked", "reason": "unsupported_url", "signals": ["unsupported_url"]}

    scheme, host = parsed
    signals: list[str] = ["unsigned_qr"]
    if scheme != "https":
        return {"status": "blocked", "reason": "insecure_scheme", "signals": signals + ["insecure_scheme"], "host": host}
    if INSTALL_RE.search(value):
        signals.append("install_file")
    if host.startswith("xn--") or ".xn--" in host:
        signals.append("idn_domain")
    if not _official(host, official_domains):
        for domain in official_domains:
            if SequenceMatcher(None, host, domain).ratio() >= 0.82:
                signals.append("lookalike_domain")
                break
    else:
        signals.append("official_domain_unverified")

    current = value
    redirects = 0
    visited = set()
    for _ in range(MAX_REDIRECTS + 1):
        if time.monotonic() >= deadline:
            return {"status": "warning", "reason": "analysis_timeout", "signals": signals + ["analysis_timeout"], "host": host, "redirects": redirects}
        if current in visited:
            return {"status": "blocked", "reason": "redirect_loop", "signals": signals, "host": host, "redirects": redirects}
        visited.add(current)
        current_parsed = _parse_url(current)
        if current_parsed is None or current_parsed[0] != "https":
            return {"status": "blocked", "reason": "unsafe_redirect", "signals": signals + ["unsafe_redirect"], "host": host, "redirects": redirects}
        current_host = current_parsed[1]
        try:
            address = _resolve_public(current_host)
        except ValueError:
            return {"status": "blocked", "reason": "non_public_address", "signals": signals + ["non_public_address"], "host": host, "redirects": redirects}
        except (OSError, socket.gaierror):
            return {"status": "warning", "reason": "network_unavailable", "signals": signals + ["network_unavailable"], "host": host, "redirects": redirects}
        try:
            status, location = _head(current, current_host, address)
        except ssl.SSLCertVerificationError:
            return {"status": "blocked", "reason": "tls_invalid", "signals": signals + ["tls_invalid"], "host": host, "redirects": redirects}
        except (OSError, ssl.SSLError, http.client.HTTPException, UnicodeError, ValueError):
            return {"status": "warning", "reason": "network_unavailable", "signals": signals + ["network_unavailable"], "host": host, "redirects": redirects}
        if status not in (301, 302, 303, 307, 308):
            if status in (405, 501):
                signals.append("head_not_supported")
            break
        if not location:
            return {"status": "warning", "reason": "redirect_unknown", "signals": signals + ["redirect_unknown"], "host": host, "redirects": redirects}
        redirects += 1
        if redirects > MAX_REDIRECTS:
            return {"status": "warning", "reason": "redirect_limit", "signals": signals + ["redirect_limit"], "host": host, "redirects": redirects}
        next_url = urljoin(current, location)
        next_parsed = _parse_url(next_url)
        if next_parsed is None or next_parsed[0] != "https":
            return {"status": "blocked", "reason": "unsafe_redirect", "signals": signals + ["unsafe_redirect"], "host": host, "redirects": redirects}
        if not _official(next_parsed[1], official_domains) and _official(current_host, official_domains):
            signals.append("left_official_domain")
        if INSTALL_RE.search(next_url):
            signals.append("install_file")
        current = next_url

    return {"status": "warning", "reason": "unsigned_qr", "signals": list(dict.fromkeys(signals)), "host": host, "redirects": redirects}
