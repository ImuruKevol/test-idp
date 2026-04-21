# OIDC authorization code + PKCE 실제 흐름과 token/userinfo/debug raw 구현

- **ID**: 012
- **날짜**: 2026-04-14
- **유형**: 기능 추가

## 작업 요약
OIDC authorize/token/userinfo가 기존 preview 시뮬레이션 위주 상태에서 실제 authorization code + PKCE 흐름으로 동작하도록 runtime flow를 구현했다.
authorization code/token 발급 이력 저장, debug raw 조회, authorize.check 실플로우 확인 UI, public route의 올바른 HTTP 오류 status 반환까지 함께 정리했다.

## 변경 파일 목록
- `src/portal/oidcidp/model/db/oidc_authorization_code.py`: authorization code 저장용 DB 모델 추가
- `src/portal/oidcidp/model/db/oidc_token_log.py`: token 발급 이력 및 raw request/response 저장용 DB 모델 추가
- `src/portal/oidcidp/model/struct.py`: OIDC runtime DB 초기화와 flow struct 연결 추가
- `src/portal/oidcidp/model/struct/flow.py`: authorize, token, userinfo, PKCE, debug raw 조회를 담당하는 실제 OIDC 플로우 구현
- `src/portal/oidcidp/model/struct/provider.py`: access token 발급용 JWT 생성 지원 확장
- `src/portal/oidcidp/route/oidc/controller.py`: authorize/token/userinfo/debug raw route와 HTTP error status 처리 보강
- `src/portal/oidcidp/app/authorize.check/api.py`: authorize check UI를 실제 code/token/userinfo 흐름에 연결
- `src/portal/oidcidp/app/authorize.check/view.ts`: PKCE code verifier/challenge 생성과 실제 token 교환 결과 처리 추가
- `src/portal/oidcidp/app/authorize.check/view.html`: code verifier 입력, debug raw URL, decoded token/userinfo 표시 UI 추가
- `src/portal/oidcidp/README.md`: 실제 authorize/token/userinfo/debug raw 지원 범위 문서화
- `tests/test_oidcidp_ui.py`: public authorization code + PKCE + userinfo + replay 방지 회귀 테스트 추가

## 검증
- `pytest tests/test_oidcidp_ui.py -q` → 8 passed
- WIZ project build (`clean: false`) 완료