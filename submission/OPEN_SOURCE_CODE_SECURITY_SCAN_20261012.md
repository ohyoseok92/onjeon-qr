# 오픈소스 도구를 이용한 코드 보안 재점검

점검일: 2026-10-12 (KST). 대상: `e243ca127f2227019d3f85f5d351c9ef84f9dc16`의 Git 추적 파일 178개를 `git archive HEAD`로 분리한 현재 소스. `.secrets`, 운영 DB·백업, `node_modules`, 로컬 생성물은 포함하지 않았다. 원본 JSON 보고서는 Git에서 제외된 `demo-output/security-scan-20261012/`에 보관한다. 기존 서명 제출 ZIP과 운영 서버는 변경하지 않았다.

| 도구 | 범위와 결과 |
| --- | --- |
| Semgrep CE 1.180.0 | `p/security-audit`: Dockerfile을 제외한 154개 대상·116개 적용 규칙, 경고 2건. `p/owasp-top-ten`: 154개 대상·262개 적용 규칙, 검출 0건. 첫 실행에서 Semgrep의 Dockerfile 파서 오류가 있어 해당 파일을 제외하고 오류 0건으로 다시 실행했다. Dockerfile은 아래 Trivy로 별도 검사했다. |
| Bandit 1.9.4 | 서비스 `src/` 0건. 운영·평가 `scripts/`까지 포함하면 42건(중간 4, 낮음 38, 높음 0). 세부 문맥은 아래에서 검토했다. |
| Gitleaks 8.30.1 | 현재 Git 추적 파일 스냅숏 0건. 로컬 Git의 모든 참조에 걸친 7개 커밋 이력 0건. 비밀값은 출력하지 않도록 `--redact`를 사용했다. |
| Trivy 0.75.0 | 현재 소스의 취약 의존성·비밀·Dockerfile 설정 검사. 개발 의존성 포함 `frontend/package-lock.json` 취약점 0건, Dockerfile 설정 오류 0건, 비밀 0건. 공개 DB 갱신 시각은 2026-10-11 13:06 UTC. Trivy가 이 저장소의 Python 사용자 지정 lock을 인식한 것으로 간주하지 않고 별도 pip-audit 결과를 사용한다. |
| pip-audit 2.10.1 | `requirements-dev.lock`의 53개 의존성에서 알려진 취약점 0건. |
| npm audit 11.17.0 | `frontend` 의존성에서 정보·낮음·보통·높음·치명 모두 0건. |

## 경고 대조

- Semgrep의 2건은 `scripts/check_operational_health.py:41`, `scripts/check_public_tls.py:121`의 `HTTPSConnection` 사용 경고다. 두 코드 모두 `ssl.PROTOCOL_TLS_CLIENT`를 사용하며 시스템 CA 또는 지정한 CA를 로드한다. 후자는 `check_hostname=True`, `CERT_REQUIRED`를 명시한다. Python 3.12에서 전자도 기본 `check_hostname=True`, `CERT_REQUIRED`임을 직접 확인했다. 따라서 이 두 경고로 인증서 검증 우회를 입증할 수 없다. [Python SSL 문서](https://docs.python.org/3.12/library/ssl.html)
- Bandit 중간 2건 `B608`은 복구 검사 도구의 SQL 식별자 결합이다. 한 곳은 코드에 고정된 테이블 목록만 사용하고, 다른 곳은 DB 메타데이터의 테이블 이름을 `[a-z_]+`로 제한한 뒤 큰따옴표로 감싼다. 공격 입력이 SQL 구조를 바꾸는 경로는 확인되지 않았다.
- Bandit 중간 2건 `B104`는 컨테이너 안에서 `0.0.0.0`으로 수신하는 실행 스크립트다. 확인한 Compose 설정은 호스트 `127.0.0.1:8443`에만 포트를 게시한다. 공개 운영은 별도 Nginx 앞단을 사용한다. 스크립트를 그 격리 밖에서 직접 실행할 때는 바인딩 범위를 다시 확인해야 한다.
- 낮음 38건은 검증 도구의 `assert` 23건, 인자 배열을 사용한 서브프로세스 실행·가져오기 14건, 평가 모드의 빈 암호 자리표시자 1건이다. `check_recovery.py`는 `-O` 최적화로 assert가 비활성화되면 즉시 중단하는 보호 장치가 있다. `ssh`, `docker`, `npm`, `PowerShell` 등 운영 도구의 실행 경로는 운영자 PC의 PATH 신뢰에 의존한다.

이번 도구 실행과 수동 대조에서 **서비스 코드에 재현 가능한 새 취약점은 확인되지 않았다.** 경고를 모두 취약점 0건으로 환산하거나 자동 도구의 무검출을 안전 보증으로 해석하지 않는다. 특히 Gitleaks는 알려진 비밀 패턴, pip-audit·npm audit·Trivy는 당시 공개 취약점 DB, Semgrep·Bandit은 해당 규칙 범위에 한정된다. 이 점검은 실제 휴대폰 시연, 배포 서비스 침투시험, 향후 취약점 갱신을 대신하지 않는다.

도구 출처: [Semgrep CE](https://semgrep.dev/products/community-edition), [Gitleaks](https://github.com/gitleaks/gitleaks), [Trivy](https://www.trivy.dev/docs/latest/getting-started/), [Bandit](https://bandit.readthedocs.io/), [pip-audit](https://github.com/pypa/pip-audit), [npm audit](https://docs.npmjs.com/cli/v11/commands/npm-audit/).
