# OIDC Provider issuer 도메인을 debug-idp.nanoha.kr로 교체

- **ID**: 009
- **날짜**: 2026-04-14
- **유형**: 설정 변경

## 작업 요약
OIDC Provider의 issuer 및 파생 endpoint가 test-idp.local 대신 실제 운영 도메인인 https://debug-idp.nanoha.kr 을 사용하도록 수정했다.
OIDC authorize 화면에서 빠르게 생성하는 임시 사용자 이메일 예시와 OIDC 회귀 테스트 기대값도 동일 도메인으로 맞췄다.

## 변경 파일 목록
- `config/idp.py`: `OIDC_ISSUER`를 `https://debug-idp.nanoha.kr`로 명시
- `src/portal/oidcidp/app/authorize.check/view.ts`: OIDC quick create 사용자 이메일 도메인을 debug-idp.nanoha.kr로 변경
- `tests/test_oidcidp_ui.py`: issuer, JWKS URI, logout endpoint 및 예시 이메일 기대값을 새 도메인 기준으로 수정

## 검증
- `pytest tests/test_oidcidp_ui.py` → 5 passed
- WIZ project build (`clean: false`) 완료