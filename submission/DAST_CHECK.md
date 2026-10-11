# 로컬 서버 동적 점검

실행일: 2026-10-11. ZAP 2.17.0과 Temurin JRE17을 공식 배포처에서 내려받고 SHA256을 대조했다. 기존 OS 설치나 인증서 저장소는 변경하지 않았다. 제품 서버는 임시 DB·암호화 키·가상 기관을 사용하는 `127.0.0.1:8001`이었다.

## 발견·수정·재검증

첫 quick scan에서 중간 위험 `10055 CSP: Failure to Define Directive with No Fallback` 1건을 확인했다. CSP의 `form-action`이 빠져 있었다. `api.py`에 `form-action 'self'`를 추가하고 응답 헤더 회귀 시험을 보완했다.

수정된 프로세스를 새로 시작한 뒤 ZAP Automation Framework의 requestor·spider·passive·active 작업을 실행했다. 첫 재검사에서 보고서 상대 경로 오류가 났고, 이어진 실행은 직전 검사의 제한 카운터 때문에 seed 요청 일부가429였다. 경로를 수정하고 제품 프로세스·ZAP home을 새로 만든 **최종 실행은 모든 seed 응답 확인과 자동화 작업이 성공**했다.

| 최종 검사 | 결과 |
| --- | --- |
| `/`, `/health` GET | 200 기대값 확인 |
| `/verify` 잘못된 합성 QR POST | 200의 차단 결과 확인 |
| `/verify` 빈 JSON POST | 422 확인 |
| 관리자 보안 이벤트/기관 대시보드 비인증 GET | 401 확인 |
| spider | URL20개 발견 |
| passive/active와 보고서 | 자동화 종료0, 높은/중간/낮은 위험 경고0개 |
| 정보 수준 경고 | 최종19:24 재검사3종·5개 사례: 주석 추정1, SPA1, User-Agent 응답 변화3 |

주석 추정은 React 번들에서 SVG/MathML 네임스페이스 URL과 HTML `select` 처리 코드를 SQL/주석으로 인식한 결과였다. 실제 비밀 주석이나 SQL 실행 경로가 아니었다. SPA 정보는 JavaScript 화면 탐색이 더 필요하다는 알림이다. User-Agent 변화는 비인증 endpoint에서 발생했고 코드에는 User-Agent로 인가를 결정하는 경로가 없다. API 자동화 시험의 인가·속도 제한 결과와 함께 검토했으며 이를 새로운 취약점으로 집계하지 않았다.

## 범위와 제한

조건부 보완·SQLite 동시 초기화 수정 후 서버를 새로 시작해2026-10-11 19:24:14(KST)에 다시 검사했다. 유효한 합성 CRL을 설정한 production 앱을 사용했고 seed6개·spider20개·전체작업 종료0을 확인했다. high/medium/low0, info3종5사례다. 새 원본 JSON은 `demo-output/zap-final-current/zap-final.json`에 보관했다. 이전 실행의 info6사례와 이번5사례를 구분했다.

컨텍스트는 loopback 한 출처로 제한하고 `/analyze`를 제외했다. 외부 기관이나 공개 서비스에 공격하지 않았다. 관리자/기관 토큰을 ZAP에 넣지 않아 인증된 변경 기능은 자동 API·트랜잭션 시험으로 검증한다. active scan의 허용 상한은2분, 규칙당1분이며 최종 작업은4초였다. 요청 제한429가 공격 탐색 범위를 줄일 수 있다. JavaScript DOM 실행, 실물 카메라, 공개 HTTPS·프록시·실제 부하·인증서 해지 확인은 이 검사 범위가 아니다.

잘못된 HTTP 공격 중 Uvicorn이 요청 거부 경고와 Windows h11 연결 상태의 내부 callback 오류를 기록했다. 서버는 계속 health200을 반환했으며 해당 로그가 HTTP 응답으로 전달된 증거는 없었다. 실제 배포 프록시의 비정상 헤더·연결 처리와 서버 로그 접근권한은 추가 확인해야 한다. 무검출을 전체 침투시험 통과나 취약점 부재로 해석하지 않는다.

도구 식별: ZAP 배포 SHA256 `94c8f767b1c2e94f0db66b3ae56514d5e3f5a728ee1b6c798e0c8fe2d61fbff0`, JRE ZIP SHA256 `bc21a93923103cdaac93ee337b0ae4365e739fde36df823dd456bc67c8a9d352`. 원본 report·도구·세션은 비밀 제외 경계인 `demo-output/`에 보관했다. 제출에는 이 요약만 포함한다.

재현용 `scripts/zap_local_plan.yaml`의 `REPORT_DIR`를 절대 로컬 폴더로 바꾸고, README 설치·프런트 빌드 뒤 `python scripts/run_security_demo.py`로 합성 기관 qa-city의 임시 서버를 loopback8001에서 실행한다. ZAP에 `-cmd -silent -notel -autorun scripts/zap_local_plan.yaml -host 127.0.0.1 -port 8094`를 전달한다. 실제 도구 사용은 [ZAP 공식 Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/)와 [requestor 작업 문서](https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-requestor/)를 참조한다.
