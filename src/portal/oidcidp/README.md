# oidcidp package

OIDC Provider 운영 화면과 관련 모델을 담당하는 패키지.

- RP registration UI 및 registry 저장
- discovery publication / JWKS 노출 정보 생성
- authorize request / consent / token preview 시뮬레이션
- logout / post_logout_redirect_uri 검증 시뮬레이션
- OIDC debug history 저장
- authorization code 저장, token 교환, userinfo 응답, debug raw 조회

## Portal Apps

- `rp.register`: RP 등록, 목록, 상세, 삭제
- `provider.publish`: discovery, JWKS, endpoint contract 게시
- `authorize.check`: authorize request 시뮬레이션, userinfo / id_token preview
- `logout.check`: end session 요청 시뮬레이션, redirect 검증

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
- `GET|POST /api/oidc/logout`: 세션 사용자 또는 `user_id` 기준 logout redirect/preview 처리
- `GET /api/oidc/userinfo`: Bearer access token 또는 세션 기준 claim JSON 반환
- `POST /api/oidc/token`: authorization code + PKCE 검증 후 access token / id token 발급