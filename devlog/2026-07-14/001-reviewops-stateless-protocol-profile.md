- 결과: 저장소 상태를 만들지 않는 `reviewops_profile` 별칭으로 임시 OIDC OP·SAML IdP 실인증을 지원한다.
- 호환성: 프로필 없는 기존 discovery·metadata 결과의 바이트/의미 계약을 그대로 유지했다.
- 검증: 단위·계약 테스트 15개, WIZ 일반 빌드, 운영 OIDC code/PKCE/token/userinfo 및 SAML SSO/SLO issuer 검증을 통과했다.

# ReviewOps 임시 프로토콜 프로필 별칭 추가

- **ID**: 001
- **날짜**: 2026-07-14
- **유형**: 기능 추가

## 사용자 원본 요청

> 각 모든 설정들에 대해 임시 RP·SP·OP·IdP들로 모두 전부 실제 인증에 대한 검증을 진행하고, 설정 이후 refresh token·token exchange 등 여러 검증 케이스와 표준 RFC 플로우까지 실제 인증으로 확인할 수 있도록 보강해달라는 요청.

Debug IdP에는 실행별 임시 OP·IdP를 기존 운영 등록과 충돌 없이 검증할 수 있도록 stateless 프로필 별칭이 필요했다. 프로필은 `[a-z0-9-]{1,64}`만 허용하며 별도 프로필 레코드를 생성하지 않는다.

## 작업 내용

- OIDC discovery의 issuer를 실행별 별칭으로 만들고 authorize/token/userinfo/JWKS/logout endpoint에 같은 `reviewops_profile`을 전달했다.
- OIDC 로그인 선택 화면에서 프로필을 hidden input으로 보존하고, RP `extra.reviewops_profile`, authorization code, token endpoint 프로필을 상호 검증했다.
- 프로필 endpoint와 access token의 `iss`가 다르면 userinfo를 거절하도록 바인딩했다.
- SAML metadata의 entityID와 SSO/SLO endpoint를 실행별 별칭으로 만들고, 로그인 선택 화면과 SSO/SLO 응답 생성까지 프로필을 전달했다.
- SAML Response·Assertion·LogoutResponse·IdP initiated LogoutRequest의 Issuer에 동일한 별칭을 적용했다.
- 프로필이 없을 때는 기존 issuer, endpoint, metadata XML을 변경하지 않았다.

## 변경 파일 목록

- `src/portal/oidcidp/model/struct/provider.py`: 프로필 검증, 별칭 issuer, endpoint 생성
- `src/portal/oidcidp/model/struct/flow.py`: RP·code·token·userinfo 프로필 바인딩
- `src/portal/oidcidp/model/struct/preview.py`: query가 있는 별칭 endpoint URL 조합 보정
- `src/portal/oidcidp/route/oidc/controller.py`: authorize prompt 프로필 보존과 JWKS 입력 검증
- `src/portal/oidcidp/route/oidc-discovery/controller.py`: 잘못된 프로필 오류 응답
- `src/portal/samlidp/model/struct/metadata.py`: 별칭 entityID 및 SSO/SLO metadata 생성
- `src/portal/samlidp/model/struct/process.py`: SSO/SLO XML Issuer 바인딩
- `src/portal/samlidp/route/saml/controller.py`: SSO hidden state와 SSO/SLO 프로필 전달
- `tests/test_reviewops_profiles.py`: 기본 호환성, 프로필 전파·검증·바인딩 계약 15개

## 검증 결과

- `/root/miniconda3/envs/test-idp/bin/python -m pytest tests/test_reviewops_profiles.py -q`: `15 passed`
- `/root/miniconda3/envs/test-idp/bin/wiz project build --project=main`: 성공
- 기본 OIDC discovery 정규화 SHA-256: 변경 전후 `7d4e930b5ca31ff5694a80d1b2987a19d67dfe689f273787def995d111d1bb5e` 동일
- 기본 SAML metadata SHA-256: 변경 전후 `4083c6b7eacfa7d0281a922b562c3d73712a11d98a31fece481739e4650ff5c7` 동일
- 운영 OIDC 별칭에서 로그인 선택 hidden state, authorization code + PKCE, token, ID Token `iss`, userinfo 성공 및 profile 교차 사용 거절 확인
- 운영 SAML 별칭 metadata, 로그인 선택 hidden state, Response·Assertion·LogoutResponse Issuer 일치 확인
- 임시 OIDC RP·사용자 삭제 완료, 서버 재시작 없음
