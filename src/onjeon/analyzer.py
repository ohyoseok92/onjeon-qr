"""Conservative, read-only inspection of an unsigned QR URL.

The network probe sends HEAD only. Every redirect is resolved again, and the
TLS connection is pinned to a checked public IP to avoid DNS rebinding.
"""

import http.client
import ipaddress
import os
import re
import socket
import ssl
import threading
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path
from urllib.parse import quote, unquote, urljoin, urlsplit

from cryptography import x509


HOST_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")
INSTALL_RE = re.compile(r"\.(?:apk|exe|msi|dmg|pkg|ipa)(?:\Z|[/?#])", re.IGNORECASE)
MAX_REDIRECTS = 3
ANALYSIS_SLOTS = threading.BoundedSemaphore(4)
DNS_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="onjeon-dns")
DNS_SLOTS = threading.BoundedSemaphore(4)
TRANSLATION_NETWORKS = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))
MAX_CRL_BUNDLE_BYTES = 4 * 1024 * 1024
CRL_PEM_RE = re.compile(rb"-----BEGIN X509 CRL-----[A-Za-z0-9+/=\s]+-----END X509 CRL-----")


def build_tls_context() -> ssl.SSLContext:
    """Load operator-managed CRLs; never fetch an attacker-provided CRL URL.

    Default CA, hostname and validity checks remain enabled. Production requires
    complete issuer CRLs; missing/invalid CRLs deny the handshake rather than
    silently falling back to ordinary TLS. Refresh the read-only bundle before
    its nextUpdate. OpenSSL verifies issuer trust, signatures and the full chain.
    """
    context, _ = _tls_configuration()
    return context


def tls_configuration_status() -> dict[str, bool | str]:
    """Inspect startup/readiness without weakening request-time TLS checks.

    Only a well-formed CRL's validity window may degrade URL inspection while
    leaving local signed-QR operations available. Missing, malformed or changed
    configuration still raises. No permissive TLS context escapes this function.
    """
    _, reason = _tls_configuration(allow_stale_crl=True)
    return {"available": reason == "ready", "reason": reason}


def _tls_configuration(*, allow_stale_crl: bool = False) -> tuple[ssl.SSLContext, str]:
    bundle_name = os.getenv("ONJEON_TLS_CRL_BUNDLE", "")
    production = os.getenv("ONJEON_ENV") == "production"
    if not bundle_name and production:
        raise ssl.SSLCertVerificationError("Production requires a TLS CRL bundle")
    if production and os.getenv("SSLKEYLOGFILE"):
        raise ssl.SSLCertVerificationError("Production forbids TLS key logging")
    context = ssl.create_default_context()
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if not bundle_name:
        return context, "ready"
    reason = "ready"
    try:
        bundle = Path(bundle_name)
        if not bundle.is_file():
            raise ValueError("invalid bundle")
        with bundle.open("rb") as source:
            data = source.read(MAX_CRL_BUNDLE_BYTES + 1)
        if len(data) > MAX_CRL_BUNDLE_BYTES:
            raise ValueError("oversized bundle")
        blocks = CRL_PEM_RE.findall(data)
        # A CRL update must not install new trust anchors or private keys.
        if not blocks or CRL_PEM_RE.sub(b"", data).strip():
            raise ValueError("invalid bundle")
        now = datetime.now(timezone.utc)
        for block in blocks:
            crl = x509.load_pem_x509_crl(block)
            last_update, next_update = crl.last_update_utc, crl.next_update_utc
            if next_update is None or next_update <= last_update:
                raise ValueError("invalid validity window")
            if next_update <= now:
                reason = "crl_expired"
            elif last_update > now and reason == "ready":
                reason = "crl_not_yet_valid"
            # Validate every block even after finding a stale CRL. A later
            # malformed block must still refuse startup rather than degrade it.
        context.load_verify_locations(cafile=str(bundle))
        # Detect a replacement during validation/loading. Operators must also
        # restrict write permissions and publish this configuration atomically.
        with bundle.open("rb") as source:
            if source.read(MAX_CRL_BUNDLE_BYTES + 1) != data:
                raise ValueError("bundle changed")
        context.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN
    except (OSError, ValueError, ssl.SSLError):
        raise ssl.SSLCertVerificationError("Invalid TLS CRL configuration") from None
    if reason != "ready" and not allow_stale_crl:
        raise ssl.SSLCertVerificationError("Invalid TLS CRL configuration")
    return context, reason


def _parse_url(value: str) -> tuple[str, str] | None:
    if len(value) > 2048 or any(c.isspace() or c == "\\" or unicodedata.category(c) in ("Cc", "Cf", "Cs") for c in value):
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


def _is_public_address(value: str) -> bool:
    address = ipaddress.ip_address(value)
    if not address.is_global or address.is_multicast or address.is_reserved:
        return False
    if address.version == 6 and (
        address.is_site_local or address.ipv4_mapped is not None or address.sixtofour is not None
        or address.teredo is not None or any(address in network for network in TRANSLATION_NETWORKS)
    ):
        return False
    return True


def _resolve_public(host: str, timeout: float = 2) -> str:
    # A timed-out system resolver can keep running. Hold its slot until it
    # actually finishes so repeated timeouts cannot grow the executor queue.
    if not DNS_SLOTS.acquire(blocking=False):
        raise OSError("DNS resolver busy")
    try:
        future = DNS_EXECUTOR.submit(socket.getaddrinfo, host, 443, type=socket.SOCK_STREAM)
    except Exception:
        DNS_SLOTS.release()
        raise
    future.add_done_callback(lambda _: DNS_SLOTS.release())
    try:
        answers = future.result(timeout=timeout)
    except FutureTimeout as exc:
        future.cancel()
        raise OSError("DNS lookup timed out") from exc
    addresses = {item[4][0] for item in answers}
    if not addresses or any(not _is_public_address(ip) for ip in addresses):
        raise ValueError("non_public_address")
    return sorted(addresses, key=lambda ip: (ipaddress.ip_address(ip).version, ip))[0]


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, timeout: float = 4):
        super().__init__(host, port=443, timeout=min(3, timeout), context=build_tls_context())
        self.address = address
        self.deadline = time.monotonic() + timeout

    def connect(self) -> None:
        raw = socket.create_connection((self.address, 443), timeout=self.timeout)
        self.sock = raw
        try:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("HTTPS probe timed out")
            raw.settimeout(min(self.timeout, remaining))
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def _head(url: str, host: str, address: str, timeout: float = 4) -> tuple[int, str | None]:
    parts = urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    path = quote(path, safe="/%:@!$&'()*+,;=-._~?")
    connection = _PinnedHTTPSConnection(host, address, timeout)
    def abort() -> None:
        if connection.sock is not None:
            try:
                connection.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()

    timer: threading.Timer | None = None
    try:
        timer = threading.Timer(timeout, abort)
        timer.daemon = True
        timer.start()
        connection.connect()
        connection.request("HEAD", path, headers={"User-Agent": "OnjeonQR-Inspector/1.0", "Accept": "*/*"})
        response = connection.getresponse()
        return response.status, response.getheader("Location")
    finally:
        if timer is not None:
            timer.cancel()
        connection.close()


def _official(host: str, domains: list[str]) -> bool:
    return host in domains


def _risk_signals(url: str, host: str, official_domains: list[str]) -> list[str]:
    """Inspect every hop, including encoded installation filenames."""
    signals = []
    if INSTALL_RE.search(url) or INSTALL_RE.search(unquote(urlsplit(url).path)):
        signals.append("install_file")
    if host.startswith("xn--") or ".xn--" in host:
        signals.append("idn_domain")
    if _official(host, official_domains):
        signals.append("official_domain_unverified")
    elif any(SequenceMatcher(None, host, domain).ratio() >= 0.82 for domain in official_domains):
        signals.append("lookalike_domain")
    return signals


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
    signals.extend(_risk_signals(value, host, official_domains))

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
            address = _resolve_public(current_host, timeout=min(2, max(0.01, deadline - time.monotonic())))
        except ValueError:
            return {"status": "blocked", "reason": "non_public_address", "signals": signals + ["non_public_address"], "host": host, "redirects": redirects}
        except (OSError, socket.gaierror):
            return {"status": "warning", "reason": "network_unavailable", "signals": signals + ["network_unavailable"], "host": host, "redirects": redirects}
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return {"status": "warning", "reason": "analysis_timeout", "signals": signals + ["analysis_timeout"], "host": host, "redirects": redirects}
            status, location = _head(current, current_host, address, timeout=min(4, remaining))
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
        try:
            next_url = urljoin(current, location)
        except (ValueError, UnicodeError):
            return {"status": "blocked", "reason": "unsafe_redirect", "signals": signals + ["unsafe_redirect"], "host": host, "redirects": redirects}
        next_parsed = _parse_url(next_url)
        if next_parsed is None or next_parsed[0] != "https":
            return {"status": "blocked", "reason": "unsafe_redirect", "signals": signals + ["unsafe_redirect"], "host": host, "redirects": redirects}
        if not _official(next_parsed[1], official_domains) and _official(current_host, official_domains):
            signals.append("left_official_domain")
        for signal in _risk_signals(next_url, next_parsed[1], official_domains):
            if signal not in signals:
                signals.append(signal)
        current = next_url

    return {"status": "warning", "reason": "unsigned_qr", "signals": list(dict.fromkeys(signals)), "host": host, "redirects": redirects}
