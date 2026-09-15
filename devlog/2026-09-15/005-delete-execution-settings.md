# OIDC·SAML 실행 설정 삭제 기능

## 작업 정보

| 항목 | 내용 |
| --- | --- |
| 날짜 | 2026-09-15 |
| 리뷰 ID | `kqlabukdqlnoqctcbhrcbjdtnpssffou` |
| 선택 AI 모델 | `gpt-5.6-sol` |
| 실제 AI 모델 | `gpt-5.6-sol` |
| 추론 수준 | `xhigh` |

## 사용자 원본 요청

```text
실행 설정 프로필은 삭제할 수 있어야 해
```

## 참고 자료

- 기존 OIDC·SAML 저장 설정 목록과 삭제 처리 경로를 확인했다.
- 프로젝트 지침의 삭제 확인 화면, 처리 중 상태, 렌더링 및 테스트 규칙을 적용했다.

## 작업 정의 및 주요 개발 항목

1. 저장된 실행 설정을 선택했을 때만 삭제 버튼을 활성화한다.
2. 삭제 전 설정 이름과 복구 불가 안내를 표시하고 사용자 확인을 받는다.
3. 삭제 성공 후 선택과 입력값을 기본 상태로 되돌리고 목록을 갱신한다.
4. OIDC와 SAML에서 동일한 흐름을 제공한다.

## 파일 변경

- `src/portal/oidcidp/app/provider.publish/view.ts`, `view.html`: OIDC 실행 설정 삭제·확인·완료 흐름.
- `src/portal/samlidp/app/idp.metadata/view.ts`, `view.pug`: SAML 실행 설정 삭제·확인·완료 흐름.
- `tests/test_reviewops_profiles.py`, `tests/test_protocol_console_ux.py`: 실제 저장 파일 삭제와 화면 동작 회귀 검사.

## 검증 및 배포 결과

- 대상 테스트: `28 passed`.
- 전체 테스트: `52 passed`.
- `git diff --check`: 통과.
- `wiz project build --project=main`: 일반 빌드 성공.
- 공개 JavaScript 파일과 현재 빌드 파일의 SHA-256이 일치하며 삭제 동작이 포함된 것을 확인했다.
- 실제 저장 설정은 삭제하지 않았다.
- 서비스 재시작은 수행하지 않았다.

## 남은 리스크

- 실제 저장 설정 삭제는 데이터 보존을 위해 메모리 기반 테스트로 검증했다.
- 브라우저에서 직접 삭제 버튼을 누르는 검사는 수행하지 않았다.
