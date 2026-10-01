# 프로토콜 표준 준수 및 기능 감사

감사 기준일: 2026-10-01

이 문서는 Test IdP가 실제 endpoint에서 제공하는 기능을 기준으로 작성한다. 화면에 보이는 선택지, Discovery/Metadata로 광고하는 기능, 실제 요청 검증 및 응답 생성 경로, 자동 테스트를 함께 대조했다. 이 서비스는 상용 인증 시스템이 아니라 SP/RP 상호운용성 검증용이므로, 의도적으로 잘못된 응답을 만드는 기능은 **호환 시험**으로 분리하고 정상 프로필에서는 광고하지 않는다.

## 기준 문서

- [OpenID Connect Core 1.0 incorporating errata set 2](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0 incorporating errata set 2](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
- [RFC 6749: OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749.html), [RFC 7636: PKCE](https://www.rfc-editor.org/rfc/rfc7636.html), [RFC 9700: OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html)
- [RFC 7523: JWT Client Authentication](https://www.rfc-editor.org/rfc/rfc7523.html), [RFC 9207: Authorization Server Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207.html)
- [OASIS SAML 2.0 Core, Bindings, Profiles, Metadata](https://docs.oasis-open.org/security/saml/v2.0/)
- [SAML V2.0 Metadata Interoperability Profile 1.0](https://docs.oasis-open.org/security/saml/Post2.0/sstc-metadata-iop.html)
- [XML Encryption 1.1](https://www.w3.org/TR/xmlenc-core1/), [XML Signature 1.1](https://www.w3.org/TR/xmldsig-core1/)

## OIDC/OAuth 기능 감사

| 영역 | 제공 기능 | 판정과 경계 |
| --- | --- | --- |
| Provider Metadata | issuer, authorize/token/userinfo/JWKS/logout endpoint, 지원 scope/claim/알고리즘, `response_modes_supported`, PKCE method 게시 | 지원. 정상 Discovery는 실제 구현된 값만 게시한다. |
| Authorization | Authorization Code, `query`/`fragment`/`form_post`, 정확한 redirect URI 일치, state/nonce, `prompt`, `max_age`, `acr_values`, Claims parameter | 지원. 신뢰가 확인된 redirect URI에만 성공·오류를 반환하며 RFC 9207 `iss`를 포함한다. |
| PKCE | S256, verifier 길이·문자 및 challenge 검증 | 지원. Public Client는 S256이 필수다. `plain`은 RP별 명시적 호환 시험에서만 수신하며 Discovery에는 광고하지 않는다. |
| Token endpoint | `authorization_code`, `refresh_token` | 지원. 등록 화면과 Discovery에서 구현되지 않은 implicit/hybrid/client credentials를 제거했다. |
| Refresh Token | `offline_access` + 명시적 consent, 서명된 refresh token, 축소 scope, 1회 회전, 동시 교환 차단, 재사용 탐지 시 하위 token 계열 폐기 | 지원. refresh token 원문은 로그에서 마스킹한다. |
| Client 인증 | `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, `private_key_jwt`, Public Client `none` | 지원. JWT assertion의 iss/sub/aud/iat/exp/jti, 알고리즘, signature와 재사용을 검증한다. 원격 JWKS는 내부·예약 주소를 차단한다. |
| Token/JWKS | RS256/PS256/ES256 및 RP 조건부 HS256 ID Token, `kid`, `at_hash`, auth_time/sid/acr/amr, Bearer access token | 지원. 잘못된 issuer/audience/signature/시간은 별도 호환 시험 프로필이다. |
| UserInfo | Bearer access token signature, issuer/audience/용도 검증 후 scope 기반 claim 반환 | 지원. |
| Logout | RP-Initiated Logout의 id_token_hint/logout_hint/client_id, 등록된 post logout URI, state, 사용자 확인 | 지원. Front-Channel/Back-Channel Logout은 별도 규격이며 미지원이다. |
| RP 등록 | 운영 UI/API를 통한 사전 등록, client secret 1회 표시, redirect/logout URI와 JWKS 관리 | 지원. RFC 7591 Dynamic Client Registration endpoint는 제공하거나 광고하지 않는다. |

### OIDC에서 의도적으로 제공하지 않는 선택 기능

다음 기능은 Core Authorization Code 기반 RP 검증에 필수는 아니며 현재 endpoint와 Discovery에서 광고하지 않는다.

- Implicit/Hybrid flow, Resource Owner Password Credentials, Client Credentials
- PAR, JAR, JARM, DPoP, mTLS sender-constrained token
- Device Authorization, CIBA, Token Exchange
- Token Introspection/Revocation 및 Dynamic Client Registration
- Front-Channel/Back-Channel Logout, Session Management iframe

## SAML 2.0 기능 감사

| 영역 | 제공 기능 | 판정과 경계 |
| --- | --- | --- |
| SP Metadata 등록 | `EntityDescriptor`/`EntitiesDescriptor`, 정확히 하나의 SP entity 선택, SAML 2.0 protocol, HTTP-POST ACS, index/isDefault, 용도별 인증서·EncryptionMethod·NameID·RequestedAttribute·SLO 파싱 | 지원. 중복 XML ID와 만료된 상위/하위 `validUntil`을 거부한다. X.509는 metadata 신뢰로 전달된 공개키 컨테이너로 처리하며 `use` 생략·키 재사용·약한 RSA 키는 경고한다. 미서명 또는 signature 검증 실패 metadata는 호환 시험 경고로만 등록한다. |
| IdP Metadata | 서명된 `EntityDescriptor`, 분리된 signing/encryption keypair와 KeyDescriptor, POST/Redirect SSO·SLO, NameID, Organization/Contact, 실제 구현 알고리즘만 게시 | 지원. `validUntil`과 `cacheDuration`, ETag/304 및 전용 SAML Metadata media type을 제공한다. encryption descriptor는 AES-GCM과 RSA-OAEP만 게시하고 OAEP SHA-256 Digest/MGF를 명시한다. |
| AuthnRequest | HTTP-Redirect DEFLATE 및 HTTP-POST, Issuer/Destination/IssueInstant/ID, 재사용 방지, exact ACS 및 POST Binding, XML/query signature, RelayState 80-byte 제한 | 지원. 서명 필수 여부는 SP metadata를 따른다. |
| SSO Response | HTTP-POST, InResponseTo/Destination/Audience/Recipient, Response·Assertion 서명, Attribute, session index, NameID | 지원. Assertion 암호화 기본 권장 조합은 AES-GCM + RSA-OAEP SHA-256이다. CBC/3DES/RSA1_5는 호환 시험으로 표시한다. |
| Authentication Context | RequestedAuthnContext `exact`; `minimum`/`maximum`은 요청 값과 같은 class를 발급하는 보수적 처리 | 부분 지원. 임의 URI 사이 강도 순서를 추론하지 않으며 `better`는 거짓 성공 대신 거부한다. |
| 세션·프롬프트 | ForceAuthn, IsPassive/NoPassive, AuthnInstant, SessionIndex | 지원. |
| SLO | SP 시작 및 IdP 시작, HTTP-POST/Redirect, LogoutRequest/Response signature·Issuer·Destination·InResponseTo·시간·NameID/EncryptedID·SessionIndex·RelayState 검증 | 지원. 등록 Binding/ResponseLocation을 사용하며 EncryptedID는 전용 IdP encryption private key로 복호화한다. |
| 디버그 변형 | unsigned/bad signature, 잘못된 issuer/audience/time/status/ciphertext, 누락 Attribute 등 | 호환 시험 전용. 정상 Metadata와 기본 실행 설정에는 섞이지 않는다. |

### SAML에서 의도적으로 제공하지 않는 선택 프로필

- HTTP-Artifact 및 Artifact Resolution SOAP service
- ECP/PAOS, SOAP 기반 AttributeQuery/AuthorizationDecisionQuery
- ManageNameID, NameID Mapping, Identity Provider Discovery Service
- 프록시 IdP/IdP chaining 및 `RequestedAuthnContext better` 강도 순서 판정

## SAML Federation IdP

`GET /api/saml/federation-metadata`는 이 서비스가 운영하는 기본 IdP와 저장된 실행 설정별 IdP alias를 하나의 `EntitiesDescriptor`로 배포한다. Publish 화면에서는 이름, 개수, 기본 IdP 포함 여부와 프리셋만 입력해 여러 alias와 이름 있는 묶음을 한 번에 만들 수 있다.

- 기본 요청은 기본 IdP와 저장된 모든 alias를 집계한다. `reviewops_profile`을 주면 해당 entity만 필터링한다.
- Quick Federation은 한 번에 최대 20개 alias를 만들며 `standard`, `encrypted`, 두 모드를 번갈아 쓰는 `mixed` 프리셋을 제공한다. 저장된 묶음은 `?federation=<name>` 전용 URL로 배포하고, 최대 50개 entity를 포함할 수 있다.
- 묶음 삭제와 alias 설정 삭제를 분리해 만들어 둔 IdP를 다른 묶음에서 재사용할 수 있다.
- aggregate 루트 하나에 RSA-SHA256 enveloped signature를 적용하고, 각 child는 중복 서명하지 않는다.
- `Name`, 안정적인 `ID`, `validUntil`, `cacheDuration`을 포함하며 entity 수를 50개로 제한한다.
- 표준 feed는 ETag/304와 bounded cache를 사용한다. unsigned/bad-signature 시험 feed는 `no-store`다.
- `GET /api/saml/federation-info`와 SAML Publish 화면에서 entity 목록 정보, 만료/캐시, 서명 알고리즘 및 signing certificate SHA-256 fingerprint를 확인할 수 있다.
- 소비자는 최초 trust anchor를 안전한 별도 채널로 확인하고, `validUntil` 이전에 metadata를 갱신해야 한다. 이 서비스는 federation 운영자 간 자동 trust 교환, MDQ, registration authority/entity category 정책, key rollover orchestration은 제공하지 않는다.

## Metadata signing/encryption credential 판정

- Metadata Interoperability Profile에 따라 각 키는 독립된 `KeyDescriptor`에 두고 `use`를 명시한다. IdP signing key는 metadata/Response/Assertion 서명에, 별도 encryption key는 수신 `EncryptedID` 복호화에 사용한다.
- Metadata의 X.509 certificate는 공개키를 전달하는 컨테이너다. 신뢰된 metadata를 처리한 뒤 인증서 path, revocation, 유효기간을 TLS 인증서처럼 별도 판정하지 않는다. 대신 metadata signature와 trust anchor, `validUntil`을 검증한다.
- XML Encryption 1.1에서 AES-128-GCM은 필수 구현 알고리즘이고 RSA1_5는 선택이며 권장되지 않는다. 따라서 IdP 수신 metadata는 AES-GCM 3종과 RSA-OAEP만 게시한다.
- 현대 RSA-OAEP URI에는 SHA-256 Digest와 MGF1-SHA256을 명시한다. 파라미터가 생략되면 표준 기본값인 SHA-1/MGF1-SHA1을 적용하며, `rsa-oaep-mgf1p`에서는 MGF override를 거부한다.
- SP가 게시한 encryption `KeyDescriptor`의 content/key-transport 허용 목록을 응답 암호화에 적용한다. signing과 encryption에 같은 키를 쓰거나 `use`를 생략한 경우에는 상호운용을 위해 수용하되 명시적인 진단 경고를 남긴다.

## 이번 감사에서 수정한 불일치

1. RP 기본값에는 `refresh_token`이 있었지만 token endpoint가 이를 거부하던 불일치를 없애고 회전·재사용 탐지까지 구현했다.
2. RP 등록 UI가 실제 endpoint에 없는 implicit/hybrid/client credentials를 허용하던 문제를 제거했다.
3. Discovery가 PKCE `plain`을 정상 기능으로 광고하던 문제를 수정하고 S256만 게시한다.
4. authorization 오류를 검증된 redirect URI로 반환하고 `prompt=consent`를 사용자 상호작용으로 처리한다.
5. SP metadata의 SAML 2.0 protocol, POST ACS Binding, index, 상위 aggregate 만료 및 중복 ID 검증을 추가했다.
6. 단일 profile만 감싸던 federation endpoint를 전체 IdP alias aggregate로 확장하고 root signature, expiry/cache, ETag 및 trust-anchor fingerprint를 추가했다.
7. 이름/개수/프리셋만으로 여러 IdP와 이름 있는 Federation 묶음을 만드는 Quick Federation UI/API를 추가했다.
8. 기존 signing key를 유지하면서 별도 encryption keypair를 생성하고, metadata의 용도/알고리즘 게시와 SP credential 파싱을 실제 암복호화 경로에 맞췄다.
9. LogoutRequest `EncryptedID`의 AES-GCM + RSA-OAEP 복호화를 추가하고 OAEP Digest/MGF 기본값과 명시 파라미터를 XML Encryption 1.1대로 처리한다.

## 검증 범위

자동 테스트는 Discovery 광고값, 미구현 RP flow 등록 거부, refresh token 회전·동시 재사용·계열 폐기, aggregate root signature, 빠른 Federation 생성, entity 집계, metadata expiry/cache, 독립 signing/encryption keypair, OAEP SHA-256/표준 SHA-1 기본값, EncryptedID, SP metadata credential 역할과 SAML2/POST/상위 만료 검증을 포함한다. 외부 federation 운영자 또는 상용 SP/RP와의 실제 브라우저 상호운용 시험과 장기 key rollover 훈련은 배포 환경에서 별도로 수행해야 한다.
