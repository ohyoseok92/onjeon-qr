"""Fetch explicitly registered public CRLs, then verify and atomically publish.

This operator command is never called from request processing. Its bounded source
URLs are operator approved, not learned from an untrusted submitted certificate.
HTTP CRLs contain public signed data; authenticity comes from pinned issuer keys,
validity checks and the persistent authenticated antirollback checkpoint.
"""
import argparse
import json
import re
import secrets
import ssl
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization

if __package__:
    from . import crl_operations as ops
    from .secure_profile import private_write, verify_private
else:
    import crl_operations as ops
    from secure_profile import private_write, verify_private


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("CRL redirects require separate operator approval")


def fetch(url: str) -> bytes:
    parsed = urlsplit(url)
    if (parsed.scheme not in {'http', 'https'} or parsed.username or parsed.password
            or parsed.port or parsed.query or parsed.fragment
            or not re.fullmatch(r'[a-z0-9]+\.c\.lencr\.org', parsed.hostname or '')
            or not re.fullmatch(r'/(?:[0-9]+\.crl)?', parsed.path)):
        raise ValueError("Only explicitly registered Let's Encrypt CRL locations are supported")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_default_certs()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                        urllib.request.HTTPSHandler(context=context))
    with opener.open(url, timeout=15) as response:
        if response.status != 200:
            raise ValueError("CRL download failed")
        data = response.read(ops.MAX_BYTES + 1)
    if len(data) > ops.MAX_BYTES:
        raise ValueError("CRL download exceeds size limit")
    crl = x509.load_pem_x509_crl(data) if data.startswith(b'-----BEGIN') else x509.load_der_x509_crl(data)
    return crl.public_bytes(serialization.Encoding.PEM)


def refresh(config_file: Path, custody: Path, bundle: Path, issuers: Path,
            *, initialize: bool = False, approved_initial_installation: bool = False) -> dict:
    verify_private(config_file)
    if config_file.is_symlink() or config_file.stat().st_size > 16384:
        raise ValueError("Invalid operator source registration")
    config = json.loads(config_file.read_text(encoding='utf-8'))
    urls = config['urls']
    if not isinstance(urls, list) or not 1 <= len(urls) <= 16 or len(set(urls)) != len(urls):
        raise ValueError("Invalid registered CRL sources")
    verify_private(bundle.parent)
    data = b''.join(fetch(url) for url in urls)
    if len(data) > ops.MAX_BYTES:
        raise ValueError("CRL bundle exceeds size limit")
    candidate = bundle.parent / ('.incoming-' + secrets.token_hex(16))
    private_write(candidate, data)
    try:
        if initialize:
            result = ops.initialize(custody, bundle, candidate, issuers, config['issuer_pins'],
                    approve_initial_installation=approved_initial_installation,
                    approved_distribution_points=config.get('distribution_points', []),
                    approve_ca_only_crls=config.get('approve_ca_only_crls', False))
        else:
            result = ops.update(custody, bundle, candidate, issuers)
        status = ops.check(custody, bundle, issuers, minimum_remaining_seconds=7200)
        return {**result, **status, 'registered_source_count': len(urls)}
    finally:
        candidate.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--custody', type=Path, required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--issuers', type=Path, required=True)
    parser.add_argument('--initialize', action='store_true')
    parser.add_argument('--approve-initial-installation', action='store_true')
    args = parser.parse_args()
    try:
        result = refresh(args.config, args.custody, args.bundle, args.issuers,
                         initialize=args.initialize, approved_initial_installation=args.approve_initial_installation)
        print(json.dumps(result, sort_keys=True))
        if not result['ready']:
            sys.exit(2)
    except Exception:
        print(json.dumps({'ready': False, 'reason': 'registered_crl_refresh_failed'}))
        sys.exit(1)


if __name__ == '__main__':
    main()
