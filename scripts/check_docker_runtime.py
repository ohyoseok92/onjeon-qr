"""Exercise the isolated TLS Docker profile and report only non-secret evidence."""
import hashlib
import http.client
import json
import os
import secrets
import socket
import ssl
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from secure_profile import PROFILE, ROOT, load_profile, private_write, protect_directory, verify_private

COMPOSE = ["docker", "compose", "-f", "compose.security.yaml"]
PORT = 8443


class LoopbackHTTPSConnection(http.client.HTTPSConnection):
    def connect(self) -> None:
        # Keep the certificate hostname while avoiding a slow IPv6 localhost
        # retry against this deliberately IPv4-only published test port.
        self.sock = self._context.wrap_socket(socket.create_connection(("127.0.0.1", PORT), self.timeout),
                                              server_hostname="localhost")


def command(arguments: list[str], timeout: int = 60) -> str:
    result = subprocess.run(arguments, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError("Docker command failed; inspect local diagnostics without exposing credentials")
    return result.stdout.strip()


def request(method: str, path: str, payload: dict | None = None, token: str | None = None,
            extra_headers: dict | None = None) -> tuple[int, dict | str, dict]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    headers.update(extra_headers or {})
    context = ssl.create_default_context(cafile=str(PROFILE / "tls-local/ca.crt"))
    connection = LoopbackHTTPSConnection("localhost", PORT, timeout=15, context=context)
    try:
        connection.request(method, path, body=json.dumps(payload) if payload is not None else None, headers=headers)
        response = connection.getresponse()
        data = response.read()
        try:
            decoded = json.loads(data)
        except (ValueError, UnicodeDecodeError):
            decoded = data.decode("utf-8")
        return response.status, decoded, dict(response.getheaders())
    finally:
        connection.close()


def require(condition: bool, name: str) -> None:
    if not condition:
        raise RuntimeError("Runtime verification failed: " + name)


def main() -> None:
    if os.environ.get("SSLKEYLOGFILE"):
        raise RuntimeError("TLS key logging must be disabled for this check")
    load_profile()
    values = dict(line.split("=", 1) for line in (PROFILE / "application/production.env").read_text().splitlines())
    admin = values["ONJEON_ADMIN_TOKEN"]
    cid = command(COMPOSE + ["ps", "-q", "app"])
    require(bool(cid), "container running")
    inspect = json.loads(command(["docker", "inspect", cid]))[0]
    host, config = inspect["HostConfig"], inspect["Config"]
    require(config["User"] == "10001:10001" and host["ReadonlyRootfs"], "non-root and read-only root")
    require("ALL" in host["CapDrop"] and "no-new-privileges:true" in host["SecurityOpt"], "capability controls")
    require(host["Memory"] == 512 * 1024 * 1024 and host["PidsLimit"] == 128, "resource limits")
    require(host["PortBindings"] == {"8443/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8443"}]}, "exact loopback TLS binding")
    secret_mounts = [mount for mount in inspect["Mounts"] if mount["Type"] == "bind"]
    require({mount["Destination"] for mount in secret_mounts} == {
        "/run/app-secrets/production.env", "/run/tls/server.key", "/run/tls/server.crt",
        "/run/tls/ca.crt", "/run/tls/revocations.pem"} and all(not mount["RW"] for mount in secret_mounts), "all secret binds read-only")
    require("ONJEON_ADMIN_TOKEN" not in "\n".join(config["Env"]), "secret absent from container environment configuration")
    checks = {"engine_version": command(["docker", "version", "--format", "{{.Server.Version}}"]),
              "image_id": inspect["Image"], "test_ca_not_installed_in_os": True,
              "container_user": config["User"], "read_only_root": True, "capabilities_dropped": "ALL",
              "no_new_privileges": True, "loopback_port": PORT, "memory_limit_mib": 512, "pids_limit": 128,
              "read_only_secret_bind_count": len(secret_mounts), "secrets_absent_from_inspect_environment": True}
    for context, hostname, name in ((ssl.create_default_context(), "localhost", "untrusted_ca_rejected"),
                                    (ssl.create_default_context(cafile=str(PROFILE / "tls-local/ca.crt")), "wrong.example", "wrong_hostname_rejected")):
        try:
            with socket.create_connection(("127.0.0.1", PORT), timeout=3) as raw:
                context.wrap_socket(raw, server_hostname=hostname).close()
        except ssl.SSLCertVerificationError:
            checks[name] = True
        else:
            require(False, name)
    with socket.create_connection(("127.0.0.1", PORT), timeout=3) as raw:
        with ssl.create_default_context(cafile=str(PROFILE / "tls-local/ca.crt")).wrap_socket(raw, server_hostname="localhost") as connection:
            checks["negotiated_tls"] = connection.version()
    status, _, headers = request("GET", "/health")
    require(status == 200 and "max-age" in headers.get("strict-transport-security", ""), "HTTPS health and HSTS")
    require(request("GET", "/")[0] == 200 and request("GET", "/docs")[0] == 404, "frontend and production docs")
    require(request("GET", "/admin/security-events")[0] == 401, "admin authentication")
    institution = "docker-" + secrets.token_hex(4)
    key_code = ("import os;from pathlib import Path;from onjeon.crypto import create_private_key;"
                "v=dict(x.split('=',1) for x in Path('/run/app-secrets/production.env').read_text().splitlines());"
                "os.environ.update(v);print(create_private_key(Path('/app/.secrets/" + institution + "/v1.pem')))" )
    public = command(["docker", "exec", cid, "python", "-c", key_code])
    status, registration, _ = request("POST", "/admin/institutions", {
        "institution_id": institution, "name": "Docker test institution", "official_domains": ["demo.example.org"],
        "key_version": "v1", "public_key": public}, admin)
    require(status == 201, "registration")
    issuer = registration["issuer_token"]
    status, issued, _ = request("POST", "/institutions/" + institution + "/qrs", {
        "destination": "https://demo.example.org/notice", "purpose": "Docker TLS verification",
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()}, issuer)
    require(status == 201, "issuance")
    require(request("POST", "/verify", {"qr_text": issued["qr_text"]})[1]["status"] == "trusted", "trusted QR")
    require(request("POST", "/institutions/" + institution + "/qrs/" + issued["qr_id"] + "/revoke", {}, issuer)[0] == 200, "revoke")
    require(request("POST", "/verify", {"qr_text": issued["qr_text"]})[1]["status"] == "blocked", "revoked QR")
    checks["https_issue_verify_revoke"] = True
    # Begin away from the fixed UTC minute boundary so a normal window rollover
    # cannot be mistaken for a restart bypass.
    remainder = time.time() % 60
    if remainder > 15:
        time.sleep(60 - remainder + 0.2)
    quota_window = int(time.time()) // 60
    for index in range(10):
        require(request("POST", "/analyze", {"qr_text": "http://127.0.0.1/"},
                        extra_headers={"X-Forwarded-For": "192.0.2." + str(index + 1)})[0] == 200, "analysis limit setup")
    require(request("POST", "/analyze", {"qr_text": "http://127.0.0.1/"})[0] == 429, "analysis limit")
    command(COMPOSE + ["restart", "app"])
    for _ in range(30):
        try:
            if request("GET", "/health")[0] == 200:
                break
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.5)
    require(int(time.time()) // 60 == quota_window, "restart test stays inside one quota window")
    require(request("POST", "/analyze", {"qr_text": "http://127.0.0.1/"}, extra_headers={"X-Forwarded-For": "198.51.100.1"})[0] == 429, "limit survives restart and spoofed forwarding header")
    require(request("POST", "/verify", {"qr_text": issued["qr_text"]})[1]["status"] == "blocked", "revocation survives restart")
    checks["restart_preserves_revocation_and_rate_limit"] = True
    runtime_code = """import os,json,stat
from pathlib import Path
paths=[Path('/app/data'),Path('/app/.secrets'),Path('/app/data/onjeon.sqlite3'),Path('/app/data/.rate-limit-hmac')]
result={'uid':os.getuid(),'gid':os.getgid(),'files':{str(p):{'mode':oct(stat.S_IMODE(p.stat().st_mode)),'uid':p.stat().st_uid} for p in paths}}
result['proc_controls']=[x for x in Path('/proc/self/status').read_text().splitlines() if x.startswith(('CapEff:','NoNewPrivs:'))]
for label,path in [('root_write_denied','/app/forbidden-write'),('secret_mount_write_denied','/run/app-secrets/production.env')]:
 try:
  flags=os.O_WRONLY if label=='secret_mount_write_denied' else os.O_WRONLY|os.O_CREAT|os.O_EXCL
  fd=os.open(path,flags,0o600);os.close(fd);result[label]=False
 except OSError:result[label]=True
keys=list(Path('/app/.secrets').rglob('*.pem'))
result['issuer_keys_encrypted']=bool(keys) and all(p.read_bytes().startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----') and stat.S_IMODE(p.stat().st_mode)==0o600 for p in keys)
print(json.dumps(result))
"""
    runtime = json.loads(command(["docker", "exec", cid, "python", "-c", runtime_code]))
    require(runtime["uid"] == 10001 and runtime["root_write_denied"] and runtime["secret_mount_write_denied"] and runtime["issuer_keys_encrypted"], "actual runtime permissions")
    require(runtime["proc_controls"] == ["CapEff:\t0000000000000000", "NoNewPrivs:\t1"], "effective capabilities and privilege control")
    require(all(value["mode"] == ("0o700" if name in ("/app/data", "/app/.secrets") else "0o600") and value["uid"] == 10001 for name, value in runtime["files"].items()), "private directory and file permissions")
    checks["runtime"] = runtime
    tool_code = "import importlib.util,platform,ssl,sqlite3,json;print(json.dumps({'pip_absent':importlib.util.find_spec('pip') is None,'ensurepip_absent':importlib.util.find_spec('ensurepip') is None,'python':platform.python_version(),'openssl':ssl.OPENSSL_VERSION,'sqlite':sqlite3.sqlite_version}))"
    checks["runtime_versions"] = json.loads(command(["docker", "exec", cid, "python", "-c", tool_code]))
    require(checks["runtime_versions"]["pip_absent"] and checks["runtime_versions"]["ensurepip_absent"], "build-only installers removed from runtime image")
    hash_code = "import hashlib,json;from pathlib import Path;print(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path('/app/src/onjeon').glob('*.py')}))"
    image_hashes = json.loads(command(["docker", "exec", cid, "python", "-c", hash_code]))
    local_hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT / "src/onjeon").glob("*.py")}
    require(image_hashes == local_hashes, "image source matches current source")
    checks["image_source_matches_workspace"] = True
    checks["verified_at_utc"] = datetime.now(timezone.utc).isoformat()
    (ROOT / "submission/DOCKER_RUNTIME_CHECK.json").write_text(json.dumps(checks, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(checks, indent=2))


if __name__ == "__main__":
    main()
