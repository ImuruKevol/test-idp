# samlidp package

SAML IdP 기능을 담당하는 패키지.

- SP metadata registry
- IdP metadata publication
- signed federation `EntitiesDescriptor` publication
- SSO processing
- HTTP-POST / HTTP-Redirect SLO processing

## SLO

- SP 시작 SLO: LogoutRequest의 Issuer, Destination, 시간, NameID, SessionIndex와 Binding별 signature를 검증하고 같은 Binding의 `SingleLogoutService`로 LogoutResponse를 반환한다.
- IdP 시작 SLO: 등록된 Binding의 endpoint로 LogoutRequest를 전송하고 돌아온 LogoutResponse의 signature, Issuer, InResponseTo, Destination, RelayState, Status를 검증한 뒤 연결된 세션을 종료한다.
- HTTP-Redirect는 XML signature를 제거한 뒤 DEFLATE하고 URL query signature를 적용한다.
- 서명 누락, SessionIndex 누락, 등록 Binding 불일치는 호환 시험으로 지원하며 결과 화면에 표시한다.
- Raw XML debug

## Federation Metadata

- `GET /api/saml/federation-metadata`: 기본 IdP와 저장된 실행 설정별 IdP alias를 집계한 서명된 `EntitiesDescriptor`
- `GET /api/saml/federation-info`: entity 수, 만료/캐시, 서명 알고리즘, signing certificate SHA-256 fingerprint
- aggregate에는 `validUntil`/`cacheDuration`과 ETag가 포함된다. `reviewops_profile` query로 단일 alias feed를 선택할 수 있다.
- Publish 화면의 Quick Federation에서 이름, IdP 개수(최대 20), 기본 IdP 포함 여부와 `standard`/`encrypted`/`mixed` 프리셋만 선택하면 alias와 묶음 URL을 함께 만든다.
- 같은 이름으로 다시 실행하면 해당 빠른 생성 alias의 개수와 프리셋을 즉시 재구성한다.
- 저장된 묶음은 `?federation=<name>`으로 독립 배포한다. 묶음 삭제는 alias 실행 설정을 삭제하지 않으므로 다른 조합에서 재사용할 수 있다.
- 소비자는 Publish 화면의 certificate fingerprint를 별도 신뢰 채널에서 확인하고 만료 전에 feed를 갱신해야 한다.

## Metadata Credentials and Encryption

- signing과 encryption은 서로 다른 RSA keypair와 X.509 certificate를 사용하며 각각 별도의 `KeyDescriptor use="signing"`/`use="encryption"`에 게시한다.
- X.509 certificate는 metadata로 전달하는 공개키 컨테이너로 취급한다. metadata 자체의 신뢰가 확인된 뒤에는 TLS PKI처럼 path/revocation/date를 다시 적용하지 않는다.
- IdP encryption credential은 SLO `EncryptedID` 수신에 사용한다. AES-128/192/256-GCM과 RSA-OAEP를 허용하며 RSA-OAEP 1.1의 SHA-256 Digest/MGF 파라미터를 명시한다.
- XML Encryption 기본값과의 상호운용을 위해 생략된 OAEP Digest/MGF는 SHA-1로 처리하고, 구형 `rsa-oaep-mgf1p`의 고정 MGF1-SHA1 규칙도 지원한다. RSA1_5와 CBC/3DES는 IdP 수신 metadata에는 게시하지 않는다.
- SP metadata의 signing/encryption credential과 `EncryptionMethod`는 역할별로 보존한다. 동일 certificate 재사용, 2048-bit 미만 RSA, `use` 생략은 경고로 드러낸다.

## SSO AuthnContextClassRef

SAMLResponse 생성 시 `authn_context_class_ref` 입력값을 `AuthnStatement/AuthnContext/AuthnContextClassRef`에 반영한다.
값을 비우면 AuthnRequest의 `RequestedAuthnContext` 첫 번째 값을 사용하고, 요청값도 없으면 `urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport`를 사용한다.

지원 입력 경로:

- Login Check 화면의 `AuthnContextClassRef` 입력
- SAML 로그인 계정 선택 화면의 `AuthnContextClassRef` 입력 및 REFEDS 빠른 선택
- `portal.samlidp.login.check` `build_response` API의 `authn_context_class_ref`
- `/api/saml/sso-respond` 및 `/api/saml/sso`의 `authn_context_class_ref`
- 호환 alias: `AuthnContextClassRef`, `acr_values`

`RequestedAuthnContext`의 `exact`는 완전히 검증한다. `minimum`/`maximum`은 동일 class 발급만 허용하며, 임의 URI 사이의 강도 순서를 결정할 수 없는 `better`는 거짓 성공 대신 거부한다.
