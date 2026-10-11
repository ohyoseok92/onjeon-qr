"""Reproducible synthetic product evaluation; no external traffic or saved secrets.

Run: .venv/Scripts/python.exe scripts/evaluate_product.py
Latency includes the local TestClient/ASGI and SQLite path, not production networking.
"""

import argparse
from collections import Counter
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from importlib.metadata import version
import json
from pathlib import Path
import platform
import secrets
import socket
import ssl
import sys
import tempfile
import time
from unittest.mock import patch

from fastapi.testclient import TestClient

from onjeon import analyzer, api
from onjeon.api import Settings, create_app
from onjeon.crypto import b64url_encode, canonical_bytes, create_private_key, parse_qr


def percentile(values: list[float], fraction: float) -> float:
    """Linearly interpolated sample percentile, explicitly used for p50/p95."""
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    return round(ordered[low] + (ordered[high] - ordered[low]) * (position - low), 3)


def evaluate_signed_qrs() -> dict:
    with tempfile.TemporaryDirectory(prefix="onjeon-evaluation-") as temporary, patch.dict(
        "os.environ", {"ONJEON_ENV": "evaluation", "ONJEON_KEY_PASSWORD": ""},
    ), ExitStack() as stack:
        root = Path(temporary)
        settings = Settings(root / "state.sqlite3", root / "keys", secrets.token_urlsafe(32))
        public = create_private_key(settings.key_directory / "evaluation-v1.pem")
        app = create_app(settings)
        # These are simulated client identities, not forwarded headers or real network hosts.
        # Ten separate clients retain the application's unmodified per-IP rate limits.
        clients = [stack.enter_context(TestClient(app, client=(f"192.0.2.{number + 1}", 50000))) for number in range(10)]
        admin = stack.enter_context(TestClient(app, client=("192.0.2.100", 50000)))
        registered = admin.post("/admin/institutions", headers={"Authorization": "Bearer " + settings.admin_token}, json={
            "institution_id": "evaluation", "name": "평가용 기관", "official_domains": ["evaluation.example.org"],
            "key_version": "v1", "public_key": public,
        })
        registered.raise_for_status()
        issuer = {"Authorization": "Bearer " + registered.json()["issuer_token"]}
        now = datetime.now(timezone.utc)

        def issue(index: int, expiry: datetime) -> str:
            response = clients[index % len(clients)].post("/institutions/evaluation/qrs", headers=issuer, json={
                "destination": f"https://evaluation.example.org/notice/{index}",
                "purpose": f"평가 안내 {index}", "expires_at": expiry.isoformat(),
            })
            response.raise_for_status()
            return response.json()["qr_text"]

        normal = [issue(index, now + timedelta(days=7)) for index in range(50)]
        tampered = []
        for index, qr in enumerate(normal[:25]):
            payload, _, signature = parse_qr(qr)
            if index % 3 == 0:
                payload["destination"] += "?modified=1"
            elif index % 3 == 1:
                payload["purpose"] += " 변경"
            else:
                payload["expires_at"] += 1
            tampered.append("onqr:v1:" + b64url_encode(canonical_bytes(payload)) + "." + b64url_encode(signature))
        expired = [issue(index + 50, now + timedelta(hours=1)) for index in range(12)]
        revoked = [issue(index + 62, now + timedelta(days=7)) for index in range(13)]
        for index, qr in enumerate(revoked):
            qr_id = parse_qr(qr)[0]["qr_id"]
            response = clients[index % len(clients)].post(f"/institutions/evaluation/qrs/{qr_id}/revoke", headers=issuer)
            response.raise_for_status()
        categories = {}

        def assess(name: str, samples: list[str], expected_status: str, expected_reason: str) -> None:
            reasons = Counter()
            passed = 0
            for index, qr in enumerate(samples):
                response = clients[index % len(clients)].post("/verify", json={"qr_text": qr})
                response.raise_for_status()
                result = response.json()
                reasons[result["reason"]] += 1
                passed += result["status"] == expected_status and result["reason"] == expected_reason
            categories[name] = {"samples": len(samples), "correct": passed, "expected_status": expected_status, "reasons": dict(reasons)}

        assess("normal", normal, "trusted", "valid_signature")
        assess("tampered", tampered, "blocked", "invalid_signature")
        assess("revoked", revoked, "blocked", "revoked")

        class LaterClock(datetime):
            @classmethod
            def now(cls, tz=None):
                later = now + timedelta(hours=2)
                return later.astimezone(tz) if tz else later.replace(tzinfo=None)

        # Expired samples were issued through the real API; only wall-clock time advances.
        with patch.object(api, "datetime", LaterClock):
            assess("expired", expired, "blocked", "expired_or_invalid_time")

        latencies = []
        for index in range(100):
            started = time.perf_counter()
            response = clients[index % len(clients)].post("/verify", json={"qr_text": normal[index % len(normal)]})
            elapsed = (time.perf_counter() - started) * 1000
            response.raise_for_status()
            if response.json().get("status") != "trusted":
                raise RuntimeError("Latency sample failed verification")
            latencies.append(elapsed)
        correct = sum(item["correct"] for item in categories.values())
        return {
            "data_origin": "synthetic", "samples": 100, "correct": correct, "correct_rate_percent": correct,
            "categories": categories,
            "method": "Real issuance/revocation/verification API with temporary SQLite and keys; 12 expiry cases use a clock advanced by two hours.",
            "rate_limits": "Unmodified; ten TestClient identities from documentation-only address range 192.0.2.0/24.",
            "latency": {
                "samples": 100, "unit": "milliseconds", "p50": percentile(latencies, 0.5), "p95": percentile(latencies, 0.95),
                "minimum": round(min(latencies), 3), "maximum": round(max(latencies), 3),
                "method": "Sequential successful signed verification API calls via TestClient; includes ASGI middleware and SQLite, excludes real network/browser/TLS/production load.",
            },
        }


RISK_SIGNALS = {"install_file", "idn_domain", "lookalike_domain", "left_official_domain", "tls_invalid"}


def evaluate_url_policy() -> dict:
    def synthetic_dns(host, port, *args, **kwargs):
        address = "127.0.0.1" if host.startswith("private-") else "93.184.215.14"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]

    def synthetic_head(url, host, address, **kwargs):
        if host.startswith("tls-"):
            raise ssl.SSLCertVerificationError("synthetic invalid certificate")
        if host.startswith("redirect-"):
            return 302, "http://evaluation.example.org/downgrade"
        return 200, None

    scenarios = [
        ("private_dns", [f"https://private-{index}.example.org/" for index in range(20)], "non_public_address"),
        ("insecure_http", [f"http://http-{index}.example.org/" for index in range(20)], "insecure_scheme"),
        ("insecure_redirect", [f"https://redirect-{index}.example.org/" for index in range(20)], "unsafe_redirect"),
        ("invalid_tls", [f"https://tls-{index}.example.org/" for index in range(20)], "tls_invalid"),
        ("installation_file", [f"https://evaluation.example.org/download/app-{index}.apk" for index in range(20)], "install_file"),
    ]
    groups = {}
    with patch.object(analyzer.socket, "getaddrinfo", synthetic_dns), patch.object(analyzer, "_head", synthetic_head):
        for name, urls, expected in scenarios:
            detected = 0
            blocked = 0
            for url in urls:
                result = analyzer.analyze_url(url, ["evaluation.example.org"])
                detected += result["reason"] == expected or expected in result.get("signals", [])
                blocked += result["status"] == "blocked"
            groups[name] = {"samples": len(urls), "expected_policy_signal": expected, "signal_detected": detected, "blocked": blocked}
        benign_results = [analyzer.analyze_url(f"https://evaluation.example.org/notice/{index}", ["evaluation.example.org"]) for index in range(50)]
    flagged = sum(result["status"] == "blocked" or bool(RISK_SIGNALS.intersection(result.get("signals", []))) for result in benign_results)
    return {
        "data_origin": "synthetic", "risk_samples": 100, "benign_samples": 50,
        "network_mock_scope": "DNS answers and HEAD/TLS outcomes are controlled fixtures. URL parsing, public-IP filtering, redirect policy, and warning classification execute real analyzer code. No external network request.",
        "risk_scenarios": groups, "expected_policy_signal_rate_percent": sum(group["signal_detected"] for group in groups.values()),
        "blocked_risk_samples": sum(group["blocked"] for group in groups.values()),
        "benign_specific_risk_flags": flagged, "benign_specific_risk_flag_rate_percent": flagged / 50 * 100,
        "benign_unsigned_warning_samples": sum(result["status"] == "warning" for result in benign_results),
        "definitions": {
            "risk_detected": "Expected scenario signal appears in reason or signals; installation-file cases are warnings, not blocked.",
            "benign_risk_flag": "Blocked verdict or a specific listed risk signal. The required unsigned_qr and official_domain_unverified warnings are excluded.",
            "limits": "This measures synthetic policy branches, not malicious-URL detection accuracy or production false positives. All benign unsigned URLs remain warnings and never become trusted.",
        },
    }


def run_evaluation() -> dict:
    started = time.perf_counter()
    executed = datetime.now(timezone.utc)
    signed = evaluate_signed_qrs()
    urls = evaluate_url_policy()
    return {
        "schema_version": 1, "executed_at_utc": executed.isoformat(),
        "executed_at_korea": executed.astimezone(timezone(timedelta(hours=9), "Asia/Seoul")).isoformat(),
        "duration_seconds": round(time.perf_counter() - started, 3),
        "environment": {"python": platform.python_version(), "os": platform.system(), "os_release": platform.release(), "architecture": platform.machine(),
                        "dependencies": {name: version(name) for name in ("fastapi", "starlette", "httpx", "cryptography")}},
        "signed_qr": signed, "unsigned_url_policy": urls,
        "target_comparison": {
            "signed_qr_correctness": "100 synthetic API cases cover 50 normal, 25 tampered, and 25 expired/revoked QRs.",
            "verification_time": "Local p95 can be compared to the one-second goal only as a local API benchmark; real browser/network/scan latency remains unmeasured.",
            "dangerous_url_detection_95_percent": "Not established. Synthetic expected-policy-signal coverage is not accuracy on independently labeled malicious URLs.",
            "false_positive_below_5_percent": "Not established. Benign unsigned warning rate is deliberately 100%; the narrower specific-risk-flag metric cannot replace the planned production false-positive target.",
        },
        "privacy": "Only aggregate counts, timing, and environment are saved. Temporary keys, tokens, QR payloads, destinations, and database files are discarded.",
    }


def render_markdown(report: dict) -> str:
    signed, urls = report["signed_qr"], report["unsigned_url_policy"]
    rows = "\n".join(f"| {name} | {item['samples']} | {item['correct']} |" for name, item in signed["categories"].items())
    risk_rows = "\n".join(f"| {name} | {item['samples']} | {item['signal_detected']} | {item['blocked']} |" for name, item in urls["risk_scenarios"].items())
    return f"""# 제품 평가 실행 결과

실행 시각: {report['executed_at_korea']} (한국 시각). 실행 시간: {report['duration_seconds']}초.
환경: {report['environment']['os']} {report['environment']['os_release']}, Python {report['environment']['python']}, {report['environment']['architecture']}.
상세 환경과 집계 수치는 `PRODUCT_EVALUATION.json`에 저장했다. 재실행 명령은 `.venv/Scripts/python.exe scripts/evaluate_product.py`다.

## 서명 QR 판정

합성 자료 100건 중 {signed['correct']}건이 기대한 판정과 일치했다. 정상 50건, 변조 25건, 만료·폐기 25건이며 실제 발급·폐기·검증 API와 임시 SQLite를 사용했다. 만료 12건은 발급 API로 생성한 뒤 평가용 시계를 2시간 앞으로 옮겨 확인했다.

| 구분 | 표본 | 기대 판정 일치 |
|---|---:|---:|
{rows}

요청 제한은 그대로 유지했다. TestClient에 문서용 주소 대역의 가상 클라이언트 10개를 지정해 요청을 분산했다. 외부 네트워크를 사용하거나 클라이언트 IP 헤더를 조작한 평가는 아니다.

## 검증 응답 시간

정상 서명 QR 검증 API를 순차적으로 100회 호출했다. p50은 {signed['latency']['p50']}ms, p95는 {signed['latency']['p95']}ms였다. 백분위수는 정렬한 표본 사이를 선형 보간했다.

이 시간은 로컬 TestClient·ASGI·보안 미들웨어·SQLite 처리 시간이다. 카메라 인식, 브라우저, 실제 네트워크, TLS, 운영 부하는 포함하지 않는다. 기획서의 1초 목표는 이 로컬 API 조건에서만 비교할 수 있다.

## 일반 URL 정책

위험 시나리오 100건과 위험 징후가 없는 합성 HTTPS 주소 50건을 평가했다. DNS 응답과 HEAD·TLS 결과를 고정했고 URL 파싱, 공인 IP 필터, 리디렉션 정책, 경고 판정은 실제 분석 코드를 실행했다. 외부 서버에 접속하지 않았다.

| 합성 시나리오 | 표본 | 기대 위험 신호 감지 | 차단 |
|---|---:|---:|---:|
{risk_rows}

기대 정책 신호는 {urls['expected_policy_signal_rate_percent']}%에서 나타났다. 설치 파일은 경고로 표시하므로 위험 시나리오 전체가 차단되지는 않는다. 정상 합성 주소의 구체적 위험 신호는 {urls['benign_specific_risk_flags']}/50건이었다. 기관 서명이 없는 정상 주소 50건은 모두 경고로 남았으며 신뢰 판정을 받지 않았다.

이는 정책 분기를 점검한 결과다. 독립적으로 수집·라벨링한 악성 URL 자료나 실운영 탐지 정확도를 측정한 결과는 아니다. 기획서의 위험 탐지율 95%·오탐률 5% 목표 달성 여부는 아직 확인하지 못했다. 서명 없는 주소에 항상 붙는 경고를 오탐으로 계산할지, 구체적 위험 신호만 계산할지부터 정한 뒤 별도 자료로 평가해야 한다.

키·토큰·QR 원문·목적지·임시 DB는 결과 파일에 저장하지 않았고 실행 후 삭제했다. 다른 테스트에서 수행한 실제 로컬 TLS·HTTP 공격 검증은 이번 합성 정책 평가와 별도의 근거다.
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, default=Path(__file__).resolve().parents[1] / "submission")
    arguments = parser.parse_args()
    report = run_evaluation()
    arguments.output_directory.mkdir(parents=True, exist_ok=True)
    (arguments.output_directory / "PRODUCT_EVALUATION.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (arguments.output_directory / "PRODUCT_EVALUATION.md").write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps({"signed_correct": report["signed_qr"]["correct"], "signed_total": 100, "latency_p95_ms": report["signed_qr"]["latency"]["p95"], "synthetic_policy_signal_percent": report["unsigned_url_policy"]["expected_policy_signal_rate_percent"], "production_url_accuracy": "unmeasured"}, ensure_ascii=False))
    return 0 if report["signed_qr"]["correct"] == 100 else 1


if __name__ == "__main__":
    sys.exit(main())
