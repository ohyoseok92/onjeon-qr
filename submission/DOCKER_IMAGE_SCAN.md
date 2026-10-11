# Docker 이미지 취약점 검사

검사일: 2026-10-11. Docker Scout는 로그인이 필요해 검사를 완료하지 못했다. 로그인이나 자격 설정을 바꾸지 않고 공식 Trivy를 사용했다. 애플리케이션 이미지는 레지스트리에 올리지 않았으며, `docker save`로 만든 로컬 아카이브를 네트워크가 없는 컨테이너에서 분석했다.

검출 수는 **패키지와 취약점 ID의 조합별 행 수**다. 하나의 util-linux 취약점이 여러 바이너리 패키지에 반복되어 나타날 수 있으므로 고유 ID 수도 함께 기록했다. 원시 결과를 임의로 숨기거나 `--ignore-unfixed`로 제외하지 않았다. 전체 패키지·버전·취약점·상태·수정 버전은 [DOCKER_IMAGE_SCAN.json](DOCKER_IMAGE_SCAN.json)에 보존했다.

## 도구·데이터와 격리

| 항목 | 확인한 값 |
|---|---|
| 스캐너 | Trivy 0.75.0, 공식 2026-10-01 릴리스, source revision `591e9799316a602e703f0b484f6c6d7b234ec8f3` |
| 스캐너 이미지 | `ghcr.io/aquasecurity/trivy@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa` |
| 스캐너 확인 범위 | 공식 레지스트리 digest, 릴리스·revision·이미지 label과 실제 `--version` 대조. 별도 cosign 게시자 서명 검증은 수행하지 않음 |
| 공개 DB | `ghcr.io/aquasecurity/trivy-db:2`, 조회한 OCI manifest digest `sha256:5393bc6f744928502de96983ed97b46f06f84e718a33169dce616fe304c8024a` |
| DB 시각 | UpdatedAt `2026-10-11T07:05:14.103977313Z`, DownloadedAt `2026-10-11T10:25:39.833431079Z` |
| 다운로드와 분석 분리 | DB 다운로드 컨테이너에는 공개 DB 캐시만 마운트. 실제 분석은 `--network none` |
| 분석 접근 범위 | 이미지 tar 1개 읽기 전용, 전용 DB 캐시와 결과 폴더. Docker 소켓·앱 볼륨·비밀 파일·호스트 자격 파일을 마운트하지 않음 |
| 컨테이너 제한 | UID/GID 10001, 읽기 전용 루트, 모든 capability 제거, `no-new-privileges`, 메모리·프로세스 상한 |
| 스캐너 옵션 | `--scanners vuln --offline-scan --skip-db-update --skip-java-db-update --skip-check-update --skip-vex-repo-update --skip-version-check --disable-telemetry --ignorefile /dev/null` |

공식 릴리스와 이미지 출처는 [Trivy 릴리스](https://github.com/aquasecurity/trivy/releases/tag/v0.75.0) 및 [설치 문서](https://trivy.dev/docs/latest/getting-started/installation/)로 확인했다. 알려진 공급망 사고의 영향 버전과 시기를 공식 보안 공지에서 확인해 해당 버전을 사용하지 않았다. [Trivy 보안 공지](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)

로컬 tar 입력과 오프라인 옵션은 공식 문서를 따랐다. DB 다운로드 후 네트워크를 끄므로 오프라인 옵션 설정 오류가 있더라도 검사 컨테이너에서 앱 내용을 외부로 보낼 수 없다. [컨테이너 검사](https://trivy.dev/docs/latest/guide/target/container_image/), [네트워크 제한](https://trivy.dev/docs/latest/guide/advanced/air-gap/)

## 교체 전 이미지

대상 index digest: `sha256:b625a267ead072c48cb273435ebedaee20809852db94ed1514c1c8f018d4d177`. Trivy가 읽은 config digest는 `sha256:c263348ab675a554e07fe7ac9afb97a87a17530f5c161d9ed1880399af6e6eeb`다. 두 값의 차이는 OCI index와 이미지 config의 차이이며, 저장한 아카이브의 index·manifest와 대조했다.

| 범위 | 패키지 수 | Critical | High | Medium | Low | Unknown | 전체 행 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Debian 12.15 | 105 | 2 | 55 | 116 | 101 | 4 | 278 |
| Python 설치 패키지 | 22 | 0 | 0 | 5 | 1 | 0 | 6 |

OS 고유 ID는 121개(Critical 2, High 15, Medium 49, Low 51, Unknown 4), Python 고유 ID는 6개다. OS에는 스캐너가 제시한 수정 버전이 없었으며 상태는 affected 216행, fix_deferred 45행, will_not_fix 17행이었다. **수정 버전이 없다는 사실은 안전하거나 영향이 없다는 뜻이 아니다.**

Python 검출 6건은 모두 기저 이미지의 pip 25.0.1이다. CVE-2025-8869, CVE-2026-13346, CVE-2026-3219, CVE-2026-6357, CVE-2026-8643, CVE-2026-1703이며 스캐너가 제시한 최대 수정 버전은 26.2.0이다. 그 밖에 탐지한 제품 Python 패키지에서는 이 DB 기준 검출이 없었다. pip는 서비스 요청 처리에 사용되지 않지만 이미지에 취약한 도구를 남겨둘 이유가 없어 제거하기로 했다.

## Critical·High 수동 검토와 보완 판단

| 취약점 | 실제 범위와 판단 |
|---|---|
| CVE-2025-7458, SQLite Critical | 실제 Python `sqlite3`가 3.40.1을 사용함. 임의 SQL 실행이 선행 조건이며 현재 API는 고정 SQL과 매개변수 바인딩을 사용한다. 직접 도달 가능한 HTTP 공격 경로는 확인하지 못했으나 실제 사용하는 취약 라이브러리이므로 기저 이미지를 교체함. Debian도 Bookworm을 vulnerable, Trixie 3.46.1을 fixed로 표시. [Debian](https://security-tracker.debian.org/tracker/CVE-2025-7458) |
| CVE-2023-45853, zlib Critical | 취약 코드는 MiniZip이다. Debian은 Bookworm zlib에서 contrib/minizip을 빌드하지 않아 바이너리 영향이 없다고 설명한다. 설치 목록에 minizip·pyminizip이 없고 `find_library('minizip')`도 None. 원시 Critical 행을 삭제하지 않고 이 범위를 별도로 기록. [Debian](https://security-tracker.debian.org/tracker/CVE-2023-45853) |
| CVE-2026-11822 / CVE-2026-11824, SQLite FTS5 High | 실제 빌드에 FTS5가 활성화됨. 앱은 FTS5 MATCH 질의나 사용자가 제출한 DB 파일을 처리하지 않음. 직접 도달성은 확인되지 않았으나 사용 중인 SQLite의 잔여 위험으로 분류 |
| CVE-2026-84782, OpenSSL High | DTLS 재전송 처리 취약점. 현재 서버와 analyzer는 TCP TLS를 사용하며 DTLS를 사용하지 않음. 라이브러리의 원시 검출은 보존. Trixie 교체 비교에서는 해당 검출이 사라짐. [Debian](https://security-tracker.debian.org/tracker/CVE-2026-84782) |
| CVE-2026-88647 / CVE-2026-88648, GnuTLS High | 현재 Python TLS는 OpenSSL을 사용한다. 앱의 GnuTLS 호출 경로는 확인하지 못함. Debian은 upstream 평가 대기 상태를 포함하고 있으므로 이 기록을 해결 완료로 바꾸지 않음. [Debian](https://security-tracker.debian.org/tracker/CVE-2026-88647) |
| CVE-2026-53613 / CVE-2026-76642 / CVE-2026-78408 / CVE-2026-78409 / CVE-2026-78410, util-linux High | mount helper·fstab·특권 namespace/cgroup 조작 등의 조건. 현재 HTTP 코드에는 명령 실행 경로가 없고 컨테이너는 모든 capability 제거와 no-new-privileges를 적용. 5개 ID가 여러 패키지에 반복됨. 제품의 완화 조건이며 OS 패치 완료 증거는 아님 |
| CVE-2026-54369, libacl High | 특권 호출자와 공격자가 바꿀 수 있는 경로의 symlink 조건. 앱은 libacl의 경로 기반 API를 호출하지 않음. Windows 프로필 도구는 앱 컨테이너 안에서 실행하지 않음 |
| CVE-2025-69720, ncurses High | infocmp 명령의 분석 처리 취약점. 현재 API에는 infocmp나 사용자 명령을 실행하는 경로가 없음 |
| CVE-2026-16742, systemd High | systemd-homed 로컬 특권 조건. 현재 앱은 해당 데몬을 실행하지 않음. 라이브러리 패키지 검출을 그대로 보존 |
| CVE-2026-9538, Perl Archive::Tar High | 조작된 tar를 Perl로 읽는 조건. 제품 요청 처리에서 Perl이나 Archive::Tar를 사용하지 않음 |

위 도달성 판단은 현재 API·storage·analyzer·TLS 시작 코드의 수동 검토에 따른다. 패키지 존재 여부만으로 실제 악용을 입증한 결과도, 모든 향후 코드와 관리 작업에 대한 무영향 보증도 아니다. 악용 샘플을 실행하지 않았다.

## Trixie 기저 이미지 비교

공식 `python:3.12-slim-trixie`의 index digest `sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1`를 확인했다. linux/amd64 manifest는 `sha256:2b4f19dae3a777dfc3b76730bda1e82e1f66ab2a2686fa93ca78edbfb4f04ffe`, 버전은 3.12.15-slim-trixie다. 공식 이미지 목록과 레지스트리 정보를 대조했다. [Docker 공식 Python](https://hub.docker.com/_/python), [공식 이미지 정의](https://github.com/docker-library/official-images/blob/master/library/python)

같은 DB와 오프라인 방식으로 기저 이미지만 비교했다. 제품 패키지를 설치한 최종 이미지 결과와 구별한다.

| 범위 | 패키지 수 | Critical | High | Medium | Low | Unknown | 전체 행 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Trixie 기저 OS, Debian 13.7 | 87 | 0 | 44 | 58 | 61 | 3 | 166 |
| 기저 Python 패키지(pip) | 1 | 0 | 0 | 5 | 1 | 0 | 6 |

기저 OS의 High 고유 ID는 8개다. Critical 제거와 OS 검출 감소를 확인했으나 High가 모두 해소된 결과는 아니다. 수정 가능 2행은 liblzma5의 `DSA-6549-1` 및 `TEMP-1147318-639065`(5.8.1-1+deb13u1 → 5.8.1-1+deb13u2)로, 빌드 담당자에게 전달했다.

## 교체 전 Trixie 제품 이미지

이전 제품 index digest는 `sha256:ca462dbe0c6d04f061ba4329cee84a17eee6eb846a58dbbecefa37396392b69c`다. Trixie 기저 이미지 교체, liblzma5의 5.8.1-1+deb13u2 보안 갱신, pip와 ensurepip 제거 후 이미지를 같은 DB로 검사했다. 다음 수치는 Alpine 교체 전 기록이며 원시 결과와 아카이브를 보존했다.

| 이전 범위 | 패키지 수 | Critical | High | Medium | Low | Unknown | 전체 행 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Debian 13.7 | 87 | 0 | 44 | 58 | 61 | 1 | 164 |
| Python 설치 패키지 | 21 | 0 | 0 | 0 | 0 | 0 | 0 |

이전 Trixie OS 고유 ID는 71개(High 8, Medium 29, Low 33, Unknown 1)다. 상태는 affected 162행, fix_deferred 2행이며 스캐너가 제시한 수정 버전은 없었다. liblzma5의 수정 가능 2행과 pip 6건이 사라진 사실을 확인했다. Python 패키지 21개는 앱 자체 메타데이터와 설치된 의존 패키지를 포함한 스캐너 인벤토리 수이며, 프로젝트의 플랫폼별 의존성 개수와 동일한 지표는 아니다.

이전 Trixie 이미지에서 실제 Python 3.12.15, SQLite 3.46.1, OpenSSL 3.5.7을 확인했다. cryptography wheel 내부 OpenSSL은 4.0.3으로 시스템 OpenSSL과 별개다. pip·ensurepip를 import할 수 없고 minizip도 찾을 수 없었다. 당시 `mount`, `nsenter`, `infocmp`, `gzip`, `perl`은 존재했으며 systemd-homed 실행 파일은 찾지 못했다.

이전 Trixie 이미지에 남았던 High 고유 ID는 CVE-2026-76642, CVE-2026-78408, CVE-2026-78409, CVE-2026-78410, CVE-2026-54369, CVE-2025-69720, CVE-2026-16742, CVE-2026-9538이다. 당시 특권 제한과 직접 HTTP 도달성 검토만으로 해결 완료로 처리하지 않았다. 아래에 각 ID의 최종 해결 근거를 따로 기록했다.

## Alpine 기저·제품 후보 비교

공식 `python:3.12-alpine` index digest `sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4`를 고정했다. 공식 이미지 정의는 Python 3.12.15-alpine3.24이며, 실제 `/etc/alpine-release`와 Trivy는 Alpine 3.24.2로 식별했다. [Docker 공식 Python](https://hub.docker.com/_/python), [공식 이미지 정의](https://github.com/docker-library/official-images/blob/master/library/python)

기저 이미지와 제품 후보를 각각 저장한 뒤 기존 검사와 동일한 공개 DB·스캐너·격리 옵션으로 분석했다. 제품 후보 digest는 `sha256:06a11028a951ab850ab38fdbeed88162e38663ffa87cf953fce6401c36e64dae`다. Python 의존성은 기존 SHA256 잠금 파일과 `--only-binary` 설치를 통과했고, 서비스에 불필요한 pip·ensurepip를 제거했다.

| 비교 대상 | 패키지 수 | Critical | High | Medium | Low | Unknown | 전체 행 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Alpine 기저 OS | 38 | 0 | 0 | 1 | 0 | 0 | 1 |
| Alpine 기저 Python(pip) | 1 | 0 | 0 | 5 | 1 | 0 | 6 |
| Alpine 제품 후보 OS | 38 | 0 | 0 | 1 | 0 | 0 | 1 |
| Alpine 제품 후보 Python | 21 | 0 | 0 | 0 | 0 | 0 | 0 |

OS의 Medium은 `CVE-2026-85091`, zlib `1.3.2-r0`이며 수정 버전은 `1.3.2-r1`이다. 이 항목도 남겨두지 않고 공식 Alpine 저장소의 서명 검증을 거친 APK로 해당 버전을 설치했다. 기저·제품 후보의 원시 행과 SHA256은 JSON의 별도 scan 항목에 그대로 남겼다.

### 배포판 변경에 따른 검사 범위 차이

**Trivy의 Alpine 검사는 미수정 취약점(unfixed vulnerabilities) 탐지를 지원하지 않는다.** Alpine의 보안 공지·secfixes를 기준으로 판단하므로 Debian의 affected·fix_deferred 검출 수와 같은 범위라고 볼 수 없다. `--ignore-unfixed`를 사용하지 않았어도 이 데이터 범위 차이는 남는다. 따라서 Alpine에서 검출이 0이라는 사실만으로 기존 8개 ID의 해결을 판정하지 않았다. 실제 APK origin·버전·소유 파일, 실행 파일의 symlink 대상, 라이브러리 부재와 공식 취약 코드 범위를 추가 대조했다. [Trivy Alpine 검사 범위](https://trivy.dev/docs/latest/coverage/os/alpine/)

## 기존 High 8종의 개별 해결 근거

공식 Debian 보안 tracker를 2026-10-11 확인했을 때 8종 모두 Trixie의 고정 버전이 없었다. Perl은 수정 연기 상태였고 나머지는 안정판 보안 갱신 대신 후속 배포판 수정이 기록되어 있었다. 안정판 패키지 삭제 모의 실행에서는 coreutils·apt 및 필수 의존성 연결이 깨졌다. 배포판 혼합 설치를 적용하지 않고 Alpine 제품을 새로 빌드했다. 아래의 해결은 해당 이미지에 취약 구성요소가 포함되지 않았거나 수정된 버전을 쓴다는 의미다.

| ID | 공식 취약 코드 범위 | 최종 이미지의 해결 방식·실제 근거 |
|---|---|---|
| CVE-2026-76642 | util-linux `libmount/src/context_mount.c`, helper 실패 후 idmap·owner hooks | **취약 구성요소 부재.** libmount 패키지·라이브러리가 없고 `/bin/mount`는 `/bin/busybox`로 연결된다. [upstream 공지](https://github.com/util-linux/util-linux/security/advisories/GHSA-m25x-3hj9-m26f), [Debian 상태](https://security-tracker.debian.org/tracker/CVE-2026-76642) |
| CVE-2026-78408 | util-linux `sys-utils/nsenter.c`, `--join-cgroup`의 fd 유출 | **취약 구현 부재.** `/usr/bin/nsenter`는 `/bin/busybox`이며 util-linux의 nsenter를 설치하지 않았다. Debian 고정 버전 2.42.4와 upstream 공지의 2.42.3 표기가 달라 남은 libuuid 전체를 패치 완료라고 주장하지 않는다. [수정 소스](https://github.com/util-linux/util-linux/commit/286dd3ff41526b582ef48830de239dffbaa61f90), [Debian 상태](https://security-tracker.debian.org/tracker/CVE-2026-78408) |
| CVE-2026-78409 | util-linux libmount `hook_subdir.c`·`hook_mount.c`, detached-tree 경로 처리 | **취약 구성요소 부재.** libmount가 없으며 BusyBox mount는 해당 util-linux 구현이 아니다. [upstream 공지](https://github.com/util-linux/util-linux/security/advisories/GHSA-8f2p-47x3-43mv), [Debian 상태](https://security-tracker.debian.org/tracker/CVE-2026-78409) |
| CVE-2026-78410 | util-linux libmount bind source·owner/group/mode hooks | **취약 구성요소 부재.** libmount가 없고 util-linux mount 대신 BusyBox applet을 쓴다. [upstream 공지](https://github.com/util-linux/util-linux/security/advisories/GHSA-rh77-686x-2f2m), [Debian 상태](https://security-tracker.debian.org/tracker/CVE-2026-78410) |
| CVE-2026-54369 | ACL 경로 기반 함수의 symlink 처리 | **취약 구성요소 부재.** APK origin `acl`이 없고 `/lib`, `/usr/lib`, `/usr/local/lib`에서 libacl을 찾지 못했다. [Debian 상태](https://security-tracker.debian.org/tracker/CVE-2026-54369) |
| CVE-2025-69720 | ncurses `progs/infocmp.c::analyze_string` | **수정된 버전 사용·취약 도구 부재.** ncurses origin 3개 패키지는 `6.6_p20260516-r0`이며 upstream `6.5-20251213` 수정 이후 버전이다. infocmp 실행 파일도 없다. [upstream 변경 기록](https://invisible-island.net/ncurses/NEWS.html#index-t20251213), [Debian 상태](https://security-tracker.debian.org/tracker/CVE-2025-69720) |
| CVE-2026-16742 | systemd-homed 그룹 추가 인증 | **취약 구성요소 부재.** systemd origin APK, libsystemd·libudev, systemd-homed 실행 파일이 없다. [Debian 상태](https://security-tracker.debian.org/tracker/CVE-2026-16742) |
| CVE-2026-9538 | Perl `Archive::Tar`의 조작된 tar 처리 | **취약 구성요소 부재.** perl origin APK와 Perl 실행 파일이 없다. [Debian 상태](https://security-tracker.debian.org/tracker/CVE-2026-9538) |

util-linux origin 자체가 전부 사라진 것은 아니다. 남은 `libuuid 2.42.3-r1`의 APK 소유 파일은 `/usr/lib/libuuid.so.1`과 `/usr/lib/libuuid.so.1.3.0` 두 개이며, 위 4개 취약점의 mount/nsenter/libmount 코드와 구분했다. ncurses도 libncursesw·libpanelw·terminfo가 남아 있고 버전과 범위를 명시했다. BusyBox의 mount·nsenter·gzip는 실제 존재한다. 다른 구현의 명령이 있다는 사실을 해당 util-linux 취약 코드의 존재로 간주하지 않았고, BusyBox에 다른 취약점이 없다고 보증하지도 않는다.

패키지 인벤토리를 숨기지 않았다. 최종 APK 데이터베이스에 38개 패키지가 남아 있고 SHA256은 `18926f3c00205435d7df8a8e2ed4382c69bf35a00b8c219d21c11277c46e0c96`다. 전체 이름·버전·origin·의존성, 관련 소유 파일, 명령의 실제 경로와 라이브러리 확인 결과를 JSON의 `final_runtime_observation`에 보존했다. 취약점 제외 파일·VEX 무시·패키지 DB 삭제를 사용하지 않았다.

## 최종 Alpine 이미지 검사와 차단 판단

최종 index digest는 `sha256:1e5f37f52e3ae5f34cc982310eeaea5f3bd3aaaec2c1cc6aad01913fd61ac331`이며 Trivy가 읽은 config digest는 `sha256:8f5b3d5f5a2e313e4aa5d58c9be5e8a5c461b0b29709a317a76241cd82455332`다. 아카이브 index·manifest·config와 대조했다. zlib `1.3.2-r1` 설치와 pip·ensurepip 제거 후 최종 tar를 다시 저장해 동일 DB로 검사했고, 2026-10-11 10:47 UTC에 exit 0으로 완료했다.

| 최종 범위 | 패키지 수 | Critical | High | Medium | Low | Unknown | 전체 행 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Alpine 3.24.2 OS | 38 | 0 | 0 | 0 | 0 | 0 | 0 |
| Python 설치 패키지 | 21 | 0 | 0 | 0 | 0 | 0 | 0 |

JSON의 `final_scan_pending=false`이며 총 6회 검사 결과를 보존했다. Python 3.12.15, SQLite 3.53.4, 시스템 OpenSSL 3.5.9와 cryptography 내부 OpenSSL 4.0.3을 실제 확인했다. pip·ensurepip import는 불가능하다. Python 패키지 수 21개에는 앱 메타데이터가 포함되어 있으며 플랫폼별 의존성 개수와 같은 지표는 아니다.

**차단 판단:** 기존 OS High 8종은 위 구성요소·버전 검토에서 해결되었고, 추가로 발견한 zlib Medium도 수정했다. 이 DB와 지원되는 패키지 검사 범위에서는 남은 취약점 차단 항목이 없다. JSON의 `package_vulnerability_gate`는 검사 통과이며 `public_deployment_approval`은 미승인으로 구분했다. S05·S11·S15의 실제 운영 환경·신원·공급망 조건 3개는 별도다. Alpine의 미수정 취약점 탐지 한계를 포함하므로 모든 알려지지 않은 취약점이 없다는 보증이나 공개 배포 자동 승인으로 확대하지 않는다. 실제 실행·비밀 마운트·TLS·발급·검증·폐기·재시작 후 상태 유지 증거는 같은 digest의 [DOCKER_RUNTIME_CHECK.json](DOCKER_RUNTIME_CHECK.json), 최종 컨테이너 백업·복원 증거는 [DOCKER_BACKUP_CHECK.json](DOCKER_BACKUP_CHECK.json)을 참조한다.

CPython 인터프리터와 표준 라이브러리, Docker 엔진·호스트 커널, 웹 빌드 단계 이미지, 실행 중 마운트된 비밀·DB 볼륨은 이 패키지 검사 하나로 모두 검증되지 않는다. 설치 패키지는 `.dist-info` 등에서 식별한다. [Trivy Python 검사 범위](https://trivy.dev/docs/latest/guide/coverage/language/python/)

이미지의 Python 3.12.15는 공식 2026-09-30 보안 릴리스이며, 이미지의 Python source SHA256을 공식 릴리스 값과 대조했다. 이 대조는 인터프리터에 앞으로도 취약점이 없다는 보증이 아니다. [Python 3.12.15](https://www.python.org/downloads/release/python-31215/)

원시 결과와 아카이브는 ignored `demo-output/container-scan/`에 로컬 보관한다. Bookworm·Trixie 3회, Alpine 기저·제품 후보·수정된 최종 제품 3회의 원시 결과를 덮어쓰지 않았다. 제출 JSON에는 코드·환경 자격 값·비밀 파일 내용을 넣지 않는다. 스캐너 프로세스 exit 0은 검사 완료를 뜻하며, 취약점 수는 별도 결과 배열로 확인했다.

## Opus 지적 수정 후 최종 이미지 재검사

최신 index digest는 `sha256:0d92379cf5be9f47768d3a789cfcd676c5d8e732f126d2c8a79d561d33cda91a`다. config digest는 `sha256:729a1b46ee4bb9d6ce6461c0789f9d84740a726c28c2430fd1def16fd9f10050`다. 최신 JSON의 마지막 scan에 아카이브와 원시 보고서 해시를 보존했다. 동일 공개 DB에서 OS38/Python21 패키지의 모든 등급 검출0을 재확인했다. 실제 새 이미지의 APK DB SHA256이 이전 Alpine 최종 이미지와 일치하며 구성요소·명령 경로·pip/ensurepip 부재도 다시 조회했다. 기존 High8종의 구성요소별 판단은 유지된다.

이 후속 스캔은 네트워크 없음·UID10001·읽기 전용 rootfs·모든 capability 제거·no-new-privileges를 사용했다. 이 실행에는 별도 메모리/PID 상한을 주지 않았다. 이전 실행의 자원 상한과 구분해 JSON에 기록했다.

휠에 포함된 네이티브 라이브러리(cryptography에 정적으로 포함된 OpenSSL, Pillow의 pillow.libs)는 APK/Python 패키지 버전 매칭만으로 독립 검사되지 않는다. Alpine 미수정 취약점 탐지 한계와 함께 운영 중 별도 업스트림 추적 대상이다. 검출0을 이 범위까지 안전하다는 보증으로 해석하지 않는다.

### 후속 발견 재수정 뒤 최종 검사

DB 설치 식별자·인증 동시성 상한·health 캐시가 반영된 최종 index digest는 `sha256:1b5c6bed0b940e956d1debb854a9e2d14ec5e848a3475de9da4ee1ad709ef910`, config digest는 `sha256:0d2b8c12c69b288bb092b9b8d8ffe31a092978c876d8939c73c18fbbd6084c40`다. JSON의 마지막 scan이 최종 판단 기준이다. 동일 공개 DB에서 OS38/Python21의 모든 등급 검출0. APK DB hash·구성요소 라이브러리 목록·명령 경로를 다시 대조했다. 이 최종 검사에는 네트워크 없음·UID10001·읽기 전용 rootfs·capability 제거·no-new-privileges 외에도1GiB/PID128 상한을 적용했다. 이전 검사와 범위 제한은 기록으로 보존한다.
