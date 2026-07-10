# samlidp package

SAML IdP 기능을 담당하는 패키지.

- SP metadata registry
- IdP metadata publication
- SSO processing
- SLO processing
- Raw XML debug

## SSO AuthnContextClassRef

SAMLResponse 생성 시 `authn_context_class_ref` 입력값을 `AuthnStatement/AuthnContext/AuthnContextClassRef`에 반영한다.
값을 비우면 AuthnRequest의 `RequestedAuthnContext` 첫 번째 값을 사용하고, 요청값도 없으면 `urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport`를 사용한다.

지원 입력 경로:

- Login Check 화면의 `AuthnContextClassRef` 입력
- SAML 로그인 계정 선택 화면의 `AuthnContextClassRef` 입력 및 REFEDS 빠른 선택
- `portal.samlidp.login.check` `build_response` API의 `authn_context_class_ref`
- `/api/saml/sso-respond` 및 `/api/saml/sso`의 `authn_context_class_ref`
- 호환 alias: `AuthnContextClassRef`, `acr_values`

0001 단계에서는 구조와 진입점만 생성한다.
