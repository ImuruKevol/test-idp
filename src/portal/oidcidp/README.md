# oidcidp package

OIDC Provider 운영 화면과 관련 모델을 담당하는 패키지.

- RP registration UI 및 registry 저장
- discovery publication / JWKS 노출 정보 생성
- authorize request / consent / token preview 시뮬레이션
- RP-Initiated Logout / post_logout_redirect_uri 검증 및 세션 종료
- OIDC debug history 저장
- authorization code 저장, token 교환, userinfo 응답, debug raw 조회

## Portal Apps

- `rp.register`: RP 등록, 목록, 상세, 삭제
- `provider.publish`: discovery, JWKS, endpoint 정보 게시
- `authorize.check`: authorize request 시뮬레이션, userinfo / id_token preview
- `logout.check`: end_session 요청 시뮬레이션, redirect 검증

## Model Entry Points

- `registry`: RP client 저장/조회/삭제
- `provider`: issuer/discovery/JWKS 및 id_token 서명용 키 관리
- `preview`: authorize/logout 화면용 시뮬레이션 및 debug history 기록
- `flow`: authorization code, token, userinfo, debug raw 실제 처리

## Public Routes

- `GET /.well-known/openid-configuration`: OIDC discovery document raw JSON 반환
- `GET /api/oidc/jwks`: JWKS raw JSON 반환
- `GET|POST /api/oidc/authorize`: 세션 사용자 또는 `user_id` 기준 authorize redirect/preview 처리
- `GET /api/oidc/debug/raw/<key>`: authorize/token/userinfo raw bundle JSON 조회
- `GET|POST /api/oidc/logout`: `id_token_hint`, `logout_hint`, `client_id`, `post_logout_redirect_uri`, `state`, `ui_locales` 검증 후 사용자 확인을 거쳐 IdP 세션 종료

`post_logout_redirect_uri`는 RP에 등록된 값과 정확히 일치할 때만 사용하며, `state`는 검증된 복귀 주소에만 전달한다. 만료된 `id_token_hint`도 현재 OP가 발급한 서명된 토큰이면 RP-Initiated Logout 용도로 검증한다.
- `GET /api/oidc/userinfo`: Bearer access token 또는 세션 기준 claim JSON 반환
- `POST /api/oidc/token`: authorization code + PKCE 검증 후 access token / id token 발급
