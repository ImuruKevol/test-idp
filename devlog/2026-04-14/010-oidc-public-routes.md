# OIDC discovery와 JWKS public route 추가 및 외부 well-known 경로 복구

- **ID**: 010
- **날짜**: 2026-04-14
- **유형**: 기능 추가

## 작업 요약
OIDC 운영 UI만 존재하고 실제 public HTTP route가 없어서 `/.well-known/openid-configuration` 요청이 SPA index.html로 떨어지던 문제를 수정했다.
OIDC discovery와 `/api/oidc/*` route를 추가해 discovery, JWKS, authorize, logout, userinfo 경로가 실제 HTTP 응답을 반환하도록 만들고, 외부 도메인 `https://debug-idp.nanoha.kr/.well-known/openid-configuration` 에서 정상 JSON 응답을 확인했다.

## 변경 파일 목록
- `src/portal/oidcidp/route/oidc-discovery/controller.py`: raw OIDC discovery JSON 응답 추가
- `src/portal/oidcidp/route/oidc/controller.py`: JWKS, authorize, logout, userinfo, token route 처리 추가
- `tests/test_oidcidp_ui.py`: discovery 및 JWKS public route 회귀 테스트 추가
- `src/portal/oidcidp/README.md`: public route 동작 범위 문서화

## 검증
- `pytest tests/test_oidcidp_ui.py` → 7 passed
- `curl https://debug-idp.nanoha.kr/.well-known/openid-configuration` → 200 JSON 확인
- `curl https://debug-idp.nanoha.kr/api/oidc/jwks` → 200 JSON 확인
- WIZ project build (`clean: true`) 완료