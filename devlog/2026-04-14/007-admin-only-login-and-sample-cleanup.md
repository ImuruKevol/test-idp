# 기본 샘플 계정 정리 및 admin 전용 로그인 정책 적용

- **ID**: 007
- **날짜**: 2026-04-14
- **유형**: 버그 수정

## 작업 요약
기본 내장 테스트 계정에서 admin만 남기고 alice, bob, carol, mfauser를 seed 단계에서 정리하도록 변경했다.
로그인 화면과 SAML 로그인 프롬프트의 비밀번호 인증은 admin 계정만 허용하도록 제한하고, Overview와 문서 및 테스트 기대값도 현재 정책에 맞게 갱신했다.

## 변경 파일 목록
- `config/idp.py`: 보호 대상 기본 계정을 admin만 남기도록 정리
- `src/portal/idpcore/model/struct/user.py`: 기본 샘플 계정을 admin만 유지하고, 기존 비관리자 기본 계정을 자동 삭제하도록 seed 정리 로직 추가
- `src/app/page.access/api.py`: 일반 로그인 API를 admin 전용으로 제한
- `src/portal/samlidp/route/saml/controller.py`: SAML 로그인 프롬프트의 비밀번호 인증을 admin 전용으로 제한
- `src/app/page.landing/view.ts`: Overview 시스템 요약 문구를 현재 정책에 맞게 수정
- `src/app/page.landing/view.pug`: 더 이상 표시할 기본 테스트 계정이 없을 때 해당 섹션을 숨기도록 조정
- `src/app/page.access/view.pug`: 로그인 힌트를 관리자 계정 기준으로 수정
- `src/portal/idpcore/README.md`: 관리자 계정 정책과 seed 설명으로 문서 정리
- `tests/test_idpcore.py`: 사용자 목록, 로그인 정책, Overview 응답 기대값을 admin-only 정책에 맞게 수정
- `tests/test_samlidp.py`: SAML 로그인 체크 API의 사용자 목록 기대값을 현재 seed 상태에 맞게 수정

## 검증
- `pytest tests/test_idpcore.py tests/test_samlidp.py tests/test_saml_slo.py tests/test_oidcidp_ui.py tests/test_security.py` → 97 passed
- WIZ project build (`clean: false`) 완료