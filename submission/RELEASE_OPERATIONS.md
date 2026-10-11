# S15 릴리스 신뢰와 CI 운영

## 구현한 검증 절차

`scripts/release_gate.py`는 외부에서 승인한 공개키 지문과 해당 릴리스의 ZIP SHA256을 모두 필수로 받는다. 서명 JSON에 들어 있는 지문을 자동으로 신뢰하거나 신뢰 파일을 만들지 않는다. 두 입력이 없거나 잘못되면 검증을 거부한다.

검증은 하나의 제한된 ZIP 스냅샷을 읽어 기대 SHA256, Ed25519 공개키 지문, 서명, 서명된 파일명·크기·해시를 확인한다. 이어 내부 manifest가 모든 파일을 정확히 한 번 포함하는지, 각 파일의 SHA256이 맞는지 검사한다. 중복 파일·경로 이탈·개인키 및 운영 파일·링크·과도한 크기의 압축 파일도 거부한다. `--source-root`를 주면 ZIP 안의 파일과 현재 소스도 대조한다.

과거 릴리스가 같은 키로 정상 서명되었더라도 최신 승인 기록의 ZIP SHA256과 다르면 거부한다. 따라서 기대 SHA256도 최신의 독립 기록에서 가져와야 한다. 이 도구는 파일 무결성을 확인하며 법적 발행자 신원이나 외부 기록 자체의 신뢰성을 판정하지 않는다.

```powershell
.\.venv\Scripts\python.exe scripts/release_gate.py submission/OE-1_onjeon_source.zip submission/RELEASE_SIGNATURE.json --expected-fingerprint <독립채널에서승인한공개키지문> --expected-sha256 <독립채널에서승인한최신ZIP해시> --source-root .
```

검증 대상 ZIP 안에 들어 있는 Python 스크립트를 곧바로 실행하면 서명 검증 전에 공격자 코드를 실행할 수 있다. 수신자는 검증 도구를 이미 신뢰하는 별도 설치본에서 실행해야 한다. 이 저장소의 CI는 체크아웃한 검증 도구를 실행하며 내려받은 ZIP은 실행하거나 추출하지 않는다.

## CI 설정

`.github/workflows/ci.yml`은 GitHub hosted `ubuntu-24.04`를 사용한다. 서비스 운영 서버를 self-hosted runner로 쓰지 않는다. GitHub는 이 표준 runner를 작업마다 새 VM으로 제공한다고 설명한다. [GitHub hosted runner 문서](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)

워크플로 토큰은 `contents: read`만 허용한다. checkout은 자격증명을 Git 설정에 남기지 않으며 모든 action은 전체 commit SHA로 고정한다. npm 캐시와 setup-node의 자동 캐시도 끈다. 일반 PR 검사에는 운영 비밀·릴리스 개인키·배포 자격증명이 없다. 시간 제한과 중복 실행 취소를 설정했다. [GitHub 보안 지침](https://docs.github.com/en/actions/reference/security/secure-use)

기존 backend·frontend 검사에 이어 `workflow_dispatch`를 선택하면 릴리스 검증 job을 실행한다. 고정 저장소 `ohyoseok92/onjeon-qr`의 지정 태그에서 ZIP과 분리 서명만 내려받는다. 저장소 밖에서 확인한 공개키 지문을 관리자가 `ONJEON_RELEASE_PUBLIC_KEY_SHA256` 저장소 variable에 등록해야 한다. 값이 없으면 job이 실패한다. 최신 승인 기록의 ZIP SHA256은 dispatch 입력으로 받으며 셸 코드에 직접 삽입하지 않는다.

GitHub Actions의 공개키 variable은 비밀이 아니다. 변경 권한은 저장소 관리자에게만 주고, 키 교체 시에는 수신자에게 별도 확인을 거쳐 새 지문을 전달해야 한다. 서명 키는 CI에 넣지 않는다.

## 확인 결과와 실제 운영의 완료 기준

로컬 검증 도구의 공격 시나리오 시험 **13개가 통과**했다. 외부 기대값 누락, 공격자 키의 정상 서명, 과거 릴리스, 잘못되거나 중복된 manifest, 경로 이탈, 중복 JSON 속성, 크기 제한을 확인했다.

이 문서를 작성한 시점에는 변경한 워크플로를 원격에 올리거나 실행하지 않았다. 저장소 variable 등록, 원격 CI 성공, 해당 릴리스의 외부 게시를 이 문서만으로 완료했다고 판단하지 않는다. Root 작업의 실제 운영 결과를 함께 확인해야 한다.

외부 기록에는 공개키 지문·최신 ZIP SHA256·릴리스 식별자·발행 주체·발행 시점을 넣는다. 소스 ZIP이나 분리 서명 파일과 함께 교체할 수 있는 채널 하나만 신뢰 앵커로 쓰면 안 된다. 수신자가 이미 알고 있는 발행자 계정, 별도로 관리하는 전달 경로, 또는 승인된 신뢰 저장소에 등록한 기록과 대조한다. 공개키 파일과 함께 만든 로컬 JSON은 외부 게시 증거가 아니다.

GitHub 공개 계정은 코드 발행 계정의 연속성을 확인하는 자료다. 공공기관의 승인이나 법적 발행자 신원 인증은 해당 기관의 별도 절차를 거쳐야 한다.
