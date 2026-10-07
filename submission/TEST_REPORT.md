# 로컬 검증 결과

실행일: 2026-10-07 (한국시간)

| 검사 | 결과 |
| --- | --- |
| `pytest -q` | 31개 통과, 1개 의존성 사용 중단 경고 |
| `npm run build` | TypeScript·Vite 빌드 성공 |
| `bandit -r src -q` | 종료 코드 0, 보고된 문제 없음 |
| `pip-audit -r requirements-dev.lock` | 알려진 취약점 없음 |
| `npm audit --omit=dev --audit-level=high` | 취약점 0건 |
| `pip check` | 의존성 충돌 없음 |

시험은 로컬 Windows 환경에서 실행했습니다. Pytest 경고는 FastAPI TestClient가 사용하는 Starlette의 `httpx` 호환 계층에 관한 것으로 현재 시험 결과에는 영향을 주지 않았습니다.

실물 휴대폰 카메라, 공개 HTTPS 배포, 실제 기관 연동, ZAP 동적 진단은 아직 확인하지 않았습니다. 대회 미션이 공지되면 관련 시험을 추가한 뒤 이 표를 갱신해야 합니다.
