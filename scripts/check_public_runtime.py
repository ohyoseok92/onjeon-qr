"""Exercise the owner's dedicated public deployment without printing credentials."""
import argparse
import json
import secrets
import shlex
import ssl
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

if __package__:
    from .secure_profile import private_write, verify_private
else:
    from secure_profile import private_write, verify_private


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hostname', required=True, choices=['qr.ohs92.com'])
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--ssh-host', required=True)
    parser.add_argument('--identity', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    environment = args.profile / 'application/production.env'
    verify_private(environment)
    values = dict(line.split('=', 1) for line in environment.read_text().splitlines())
    institution = 'ops-' + secrets.token_hex(6)
    code = ("import os;from pathlib import Path;from onjeon.crypto import create_private_key;"
            "v=dict(x.split('=',1) for x in Path('/run/app-secrets/production.env').read_text().splitlines());"
            "os.environ.update(v);print(create_private_key(Path('/app/.secrets/" + institution + "/v1.pem')))")
    remote = 'docker exec onjeon-production-app-1 python -c ' + shlex.quote(code)
    result = subprocess.run(['ssh', '-i', str(args.identity), '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
                             args.ssh_host, remote], check=True, capture_output=True, text=True, timeout=45)
    public = result.stdout.strip()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_default_certs()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    report = {'checked_at_utc': datetime.now(timezone.utc).isoformat(), 'hostname': args.hostname}
    def require(condition: bool) -> None:
        if not condition:
            raise RuntimeError('Public runtime verification failed')
    with httpx.Client(base_url='https://' + args.hostname, verify=context, trust_env=False,
                      follow_redirects=False, timeout=15) as client:
        def request(method, path, payload=None, token=None):
            headers = {'Authorization': 'Bearer ' + token} if token else {}
            r = client.request(method, path, json=payload, headers=headers)
            r.raise_for_status()
            return r.json()
        unauthorized = client.get('/admin/security-events')
        require(unauthorized.status_code == 401)
        registration = request('POST', '/admin/institutions', {
            'institution_id': institution, 'name': 'Operational verification fixture',
            'official_domains': [args.hostname], 'key_version': 'v1', 'public_key': public}, values['ONJEON_ADMIN_TOKEN'])
        issuer = registration['issuer_token']
        issued = request('POST', '/institutions/' + institution + '/qrs', {
            'destination': 'https://' + args.hostname + '/', 'purpose': 'Public deployment smoke test',
            'expires_at': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()}, issuer)
        require(request('POST', '/verify', {'qr_text': issued['qr_text']})['status'] == 'trusted')
        request('POST', '/institutions/' + institution + '/qrs/' + issued['qr_id'] + '/revoke', {}, issuer)
        revoked = request('POST', '/verify', {'qr_text': issued['qr_text']})
        require(revoked['status'] == 'blocked')
        analyzed = request('POST', '/analyze', {'qr_text': 'https://' + args.hostname + '/'})
        report.update(admin_unauthorized_rejected=True, public_issue_verify_revoke=True,
                      qr_revocation_reason=revoked['reason'], actual_public_analysis_status=analyzed['status'],
                      actual_public_analysis_reason=analyzed['reason'])
        # Leave this one synthetic institution disabled rather than authorized.
        request('POST', '/admin/institutions/' + institution + '/disable', {}, values['ONJEON_ADMIN_TOKEN'])
        report['synthetic_institution_disabled'] = True
        private_write(args.profile / 'application' / (institution + '-qr.json'),
                      json.dumps({'qr_text': issued['qr_text'], 'institution_id': institution}).encode())
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Public runtime verification failed; inspect private diagnostics without printing credentials')
