# 공급망 대조 결과

생성 시각: 2026-10-11T09:39:33.305688Z

판정: 통과. Python 생산 구성요소 20개, 프런트 생산 구성요소 8개. 라이선스 원문 30개를 `submission/licenses/`에 복사했다.

두 SBOM은 CycloneDX 1.5 형식으로 구성요소 이름·버전·purl·공급자 선언 여부·실제 의존관계·문서 생성자·타임스탬프를 기록한다. `requirements-runtime.lock`의 정확한 버전을 설치 metadata와 대조하고, pyproject의 생산 의존성과 `qrcode[pil]` extra부터 현재 플랫폼 marker를 평가해 실제 그래프를 구성한다. 프런트는 npm SBOM을 재생성한 뒤 package-lock과 설치 package.json을 대조했다.

npm `--omit dev` 원본에서는 생산 패키지 ['react-dom@19.3.0', 'react@19.3.0', 'scheduler@0.28.0']가 누락됐다. 원본은 `SBOM.frontend.npm-production.raw.cdx.json`에 남겼다. 전체 설치 SBOM 중 생산 lock과 정확히 일치하는 구성요소를 선택하고, 설치 package.json의 dependencies/optionalDependencies/peerDependencies와 Node 상위 디렉터리 해석으로 실제 의존관계를 다시 구성해 최종 SBOM의 누락을 해결했다.

공급자 필드가 없으면 unknown을 명시했다. 작성자나 저장소 소유자를 공급자로 추정하지 않았다. Python lock의 wheel/sdist 후보 해시는 설치된 wheel 자체 해시가 아니며, RECORD 집계값도 wheel 해시로 싣지 않았다. 원문 복사 파일의 SHA-256은 복사 무결성을 확인하는 값이다.

| 대조 | Python | 프런트 |
|---|---:|---:|
| 구성요소 | 20 | 8 |
| 의존관계 | 27 | 11 |
| 버전 불일치 | 0 | 0 |
| 존재하지 않는 참조 | 0 | 0 |
| 누락된 그래프 노드 | 0 | 0 |
| 루트에서 닿지 않는 구성요소 | 0 | 0 |
| 중복 참조 | 0 | 0 |

현재 Python 플랫폼: win32. 플랫폼/extra 평가 후 생산 루트에서 도달하지 않는 잠금 항목: []. 비활성 잠금 항목은 이 플랫폼의 활성 SBOM에서 제외하며, 활성 의존성의 lock 누락이나 설치 버전 불일치는 계속 실패 처리한다. Windows는 활성20개다. Windows 설치 metadata에 Linux marker를 적용한 회귀에서는 colorama를 제외한 활성19개를 확인했다. Linux의 실제 설치/실행·바이너리/컨테이너 전체 명세를 확인한 결과는 아니다.

라이선스 원문 누락: 0개. 프런트 플랫폼 선택사항 미설치: 0개. 상세 원문 경로·해시·버전 증거는 `SUPPLY_CHAIN_VALIDATION.json`, 읽을 라이선스 전문은 `THIRD_PARTY_NOTICES.md`에서 확인한다.

이 검사는 오프라인 설치 목록과 잠금 파일의 대조다. 라이선스 의무의 법률 판정, 네이티브 바이너리에 포함된 모든 하위 라이브러리의 독립 SBOM을 보증하지 않는다. 기존 취약점 조회 결과는 별도 보안 점검 기록에 있다.

## 공식 스키마 검증

CycloneDX 공식 저장소의 1.5 태그에 있는 JSON 스키마와 두 참조 스키마를 내려받아 `submission/schemas/`에 보존했다. 출처와 SHA-256은 `schemas/SOURCES.json`에 있다. jsonschema Draft7 검증 결과: 두 최종 SBOM 모두 통과. 검증 도구는 별도 임시 환경에서 실행했으며 서비스 생산 의존성에 추가하지 않았다.
