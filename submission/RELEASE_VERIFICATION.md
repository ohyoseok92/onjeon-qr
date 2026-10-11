# 소스 ZIP 분리 서명 검증

소스 ZIP은 `OE-1_onjeon_source.zip`, 분리 서명은 `RELEASE_SIGNATURE.json`이다. 서명은 ZIP 밖에 두며 암호화된 로컬 Ed25519 릴리스키로 생성한다. 개인키·암호·운영 비밀은 제출하지 않는다.

이번 로컬 릴리스 공개키의 SHA256 지문(원시 Ed25519 공개키32bytes 기준):

```text
b79bab9e74200187685b03d6d00bbca294007b34dbe6f44e4aca623fce316dd9
```

위 지문은 파일 자체만 보고 신뢰할 수 없다. 수신자가 발행자를 확인한 독립 채널에서 얻은 기대 지문과 대조해야 한다. 이 문서·ZIP·서명 JSON을 함께 교체할 수 있는 공격자를 막으려면 기대 지문을 그 묶음 밖에서 확보해야 한다. 현재 키는 법적 발행자 신원이나 공공기관 인증을 입증하지 않는다.

의존성을 설치한 프로젝트 루트에서 다음처럼 검증한다.

```powershell
.\.venv\Scripts\python.exe scripts/secure_profile.py verify submission/OE-1_onjeon_source.zip submission/RELEASE_SIGNATURE.json --expected-fingerprint <외부에서확인한64자SHA256지문>
```

검증은 기대 지문·Ed25519 서명·ZIP 파일명/크기/SHA256을 모두 확인한다. 변조·공격자 키 교체·외부 지문 누락은 운영도구 시험에서 거부를 확인했다. ZIP의 내부 파일 manifest는 별도로 `scripts/verify_submission.py`로 확인한다. 원본 ZIP을 바꾸면 서명을 다시 만들어야 한다.
