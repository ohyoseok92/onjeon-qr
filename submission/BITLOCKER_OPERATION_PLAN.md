# PC 키 보관 드라이브 암호화 준비

## 실제 확인한 상태

2026-10-11 13:33:11 UTC, 사용자가 승인한 관리자 권한의 읽기 전용 WMI 조회로 C: 상태를 확인했다. `GetConversionStatus`와 `GetProtectionStatus`의 반환값은 모두 0이었다. 볼륨의 `ConversionStatus=0`, 암호화율 0%, `ProtectionStatus=0`, `EncryptionMethod=0`으로 **암호화·보호가 꺼져 있음**을 확인했다.

현재 PC의 앱 백업 키·암호는 사용자/SYSTEM만 접근하는 폴더에 보관한다. 이 권한 제한과 MYBOX의 암호화 백업 왕복 검증은 완료했지만, PC 드라이브 암호화 완료로 간주하지 않는다. 이번 작업에서는 보호자를 추가하거나 복구키를 생성하지 않았고, 암호화·자격 증명 전송·재시작도 실행하지 않았다.

## 실행 전 확인

보호된 `operator-tools`에 읽기 전용 `prepare_bitlocker_activation.ps1`을 준비했다. UAC를 띄우거나 스스로 권한을 올리지 않는다. 관리자 권한으로 실행하면 Windows 에디션, C: 크기·여유 공간·NTFS·상태, GPT, TPM 준비·잠금·재시작 필요 여부, Secure Boot, 기존 암호화 상태와 보호자 ID를 확인한다. TPM의 `OwnerAuth`와 48자리 복구 암호는 보고서·콘솔에 노출하지 않으며 복구 암호를 조회하는 메서드도 호출하지 않는다.

이 계획은 지원 에디션·정상 NTFS/GPT·준비된 TPM·Secure Boot·기존 보호자 없음·암호화 없음 조건을 요구한다. TPM이 없거나 준비되지 않은 상태, 이미 암호화/보호자가 있는 상태, 재시작 대기 상태, 조회 실패는 별도 검토 전 중단한다. 이 검사는 펌웨어·TPM·파티션·정책을 자동 수정하지 않는다. 실제 TPM과 에디션의 관리자 재점검 결과는 아직 확보하지 않았다. 지원 요건은 [Microsoft BitLocker 개요](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/)와 [Get-Tpm 문서](https://learn.microsoft.com/en-us/powershell/module/trustedplatformmodule/get-tpm?view=windowsserver2025-ps)를 따른다.

## 복구키 보관과 활성화 순서

1. **독립 복구키 보관처를 먼저 정한다.** PC 밖의 USB를 분리 보관하거나 다른 기기에서도 접근할 수 있는 Microsoft 계정의 복구키 보관소 등 승인된 수단을 선택한다. C:의 폴더만으로는 복구를 보장할 수 없다. 준비 스크립트의 경로 검사 어댑터는 C:와 다른 물리 USB 디스크만 지원한다. 계정 보관은 별도 로그인을 통해 실제 접근 가능 여부를 확인해야 하며 자동으로 업로드하지 않는다.
2. C: 전체의 개인 파일까지 영향을 받는 변경 범위, 기존 개인 자료 백업, 전원 연결과 재시작 시점을 사용자가 확인하고 활성화를 명시 승인한다. 앱 보안 점검이나 상태 조회 승인을 C: 암호화 승인으로 해석하지 않는다.
3. 승인 뒤 Windows가 생성하는 48자리 복구 암호 보호자 한 개를 추가한다. 반환 객체를 변수로 받아 콘솔·PowerShell transcript·로그에 암호가 나오지 않게 한다. 새 사용자/SYSTEM 전용 파일에 최초 복구 기록을 저장하며 기존 파일을 덮어쓰지 않는다. 아직 드라이브 암호화는 시작하지 않는다.
4. 사용자가 선택한 독립 매체/계정에 복구 기록을 보관한다. C:를 사용할 수 없는 다른 기기에서 복구 암호와 보호자 ID를 다시 확인한다. 같은 C: 안의 복사, PC에서만 열리는 암호화 파일, 저장했다고 표시한 체크박스만으로 확인을 대신하지 않는다. 복구키를 MYBOX 앱 암호문이나 공개 제출 증거와 함께 올리지 않는다.
5. 독립 보관·회수 검증 이후에만 TPM 보호자와 소프트웨어 `XtsAes256`으로 **C: 전체** 암호화를 활성화한다. 기존 개인 자료가 있는 드라이브이므로 사용 영역만 암호화하는 옵션은 쓰지 않고, 하드웨어 시험도 생략하지 않는다. Microsoft는 복구 보호자를 먼저 마련하고 저장한 뒤 암호화를 활성화하는 순서를 설명한다. [Enable-BitLocker 문서](https://learn.microsoft.com/en-us/powershell/module/bitlocker/enable-bitlocker?view=windowsserver2025-ps)
6. 자동 재시작은 하지 않는다. 사용자가 정한 시점에 재시작하고 정상 부팅, `FullyEncrypted`, 100%, `Protection On`, TPM·복구 보호자 존재를 확인한다. 완료 전에는 PC 키의 드라이브 암호화 조건을 충족했다고 기록하지 않는다.

Microsoft 계정·USB·인쇄물 등 복구키의 외부 보관 방법과 회수 확인은 [Microsoft 복구키 백업 안내](https://support.microsoft.com/en-us/windows/security/encryption/back-up-your-bitlocker-recovery-key)에 나와 있다. 독립 보관처가 정해지지 않았거나 사용자가 전체 C: 변경을 승인하지 않으면 활성화하지 않는다.

## 지금 준비된 결과

관리자 상태 조회 결과와 변경 범위, 중단 조건, 복구키 분리 보관 순서를 문서화했고 읽기 전용 사전 점검 스크립트를 보호 폴더에 만들었다. 변경 명령은 검토용 문자열로만 들어 있으며 실행하는 경로가 없다. 복구 암호·TPM 소유자 인증값·개인 자격 증명은 생성하거나 저장하지 않았다.

남은 입력은 **독립 복구키 보관처**, **전체 C: 암호화의 명시 승인**, **관리자 사전 점검 결과와 재시작 시점**이다. 복구키의 보관·회수 확인이 끝난 뒤 별도 승인된 활성화 구현을 실행한다. 현재 단계는 준비 완료이며 BitLocker 활성화 완료가 아니다.

PowerShell 문법 파싱 오류는 0개였다. 명령 AST에는 읽기 전용 조회·JSON 직렬화·StrictMode 설정만 있으며 보호자 추가·암호화·TPM 초기화·재시작 명령 실행이 없다. 일반 권한 실행은 `administrator_read_only_query_required`, `activation_allowed=false`로 중단했다. 권한 상승 창을 띄우지 않았다. 준비 PS1은 사용자/SYSTEM 전용 파일이며 Git과 제출 ZIP에 포함하지 않는다.
