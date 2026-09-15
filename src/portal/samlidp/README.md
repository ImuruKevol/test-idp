# samlidp package

SAML IdP 기능을 담당하는 패키지.

- SP metadata registry
- IdP metadata publication
- SSO processing
- HTTP-POST / HTTP-Redirect SLO processing

## SLO

- SP 시작 SLO: LogoutRequest의 Issuer, Destination, 시간, NameID, SessionIndex와 Binding별 signature를 검증하고 같은 Binding의 `SingleLogoutService`로 LogoutResponse를 반환한다.
- IdP 시작 SLO: 등록된 Binding의 endpoint로 LogoutRequest를 전송하고 돌아온 LogoutResponse의 signature, Issuer, InResponseTo, Destination, RelayState, Status를 검증한 뒤 연결된 세션을 종료한다.
- HTTP-Redirect는 XML signature를 제거한 뒤 DEFLATE하고 URL query signature를 적용한다.
- 서명 누락, SessionIndex 누락, 등록 Binding 불일치는 호환 시험으로 지원하며 결과 화면에 표시한다.
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
