# Test IdP

Test IdP는 SAML Service Provider(SP)와 OpenID Connect Relying Party(RP)를 검증하기 위한 테스트용 Identity Provider입니다. 외부 상용 IdP 없이 SP/RP 등록, 메타데이터/Discovery 배포, SSO, Token, UserInfo, Logout, Raw XML/JWT 디버그 흐름을 한 프로젝트 안에서 확인할 수 있습니다.

Live URL: <https://debug-idp.nanoha.kr/>

Framework: [WIZ Framework](https://github.com/season-framework/wiz) (`season==2.5.2`)

## 주요 기능

### 공통

- 24시간 유효한 임시 테스트 계정 생성, 수정, 삭제
- 일반, 연구소, 학교, 기관 프리셋 기반 SAML Attribute 및 OIDC Claim 자동 구성
- admin 로그인 기반 만료 계정/SP/RP 정리, 유효기간 연장, 영구 전환
- Raw XML/JWT 디버그 payload 인덱스와 감사 로그 저장
- 등록/삭제/로그인 시도에 대한 IP 기반 제한과 rate limit
- 한국어/영어 리소스와 상단 탭형 운영 UI 제공

### SAML IdP

- SP metadata XML 업로드 또는 붙여넣기 등록
- Entity ID, ACS, SLO, 인증서, RequestedAttribute 파싱
- IdP metadata XML 배포
- AuthnRequest 파싱, RelayState 유지, SAMLResponse 생성
- Redirect/POST 기반 SSO 및 SLO 처리
- SAML Request/Response 원문 XML 저장 및 조회

### OpenID Connect Provider

- RP client 등록, 수정, 삭제
- redirect URI, response type, grant type, scope, auth method 관리
- Discovery document와 JWKS 공개
- authorization code + PKCE 흐름 처리
- token endpoint에서 access token / id token 발급
- Bearer access token 기반 userinfo 응답
- end session logout redirect 검증
- authorize/token/userinfo/logout raw debug bundle 저장

## 화면 구조

| 경로 | 설명 |
| --- | --- |
| `/` | Overview, SAML/OIDC 진입, 임시 테스트 계정 관리 |
| `/access` | admin 로그인 화면 |
| `/saml/register` | SP metadata 등록 및 등록된 SP 목록 |
| `/saml/publish` | IdP metadata, SSO/SLO endpoint, 인증서, XML 배포 |
| `/saml/logincheck` | SAML AuthnRequest 파싱과 SAMLResponse 발급 테스트 |
| `/saml/logoutcheck` | SAML LogoutRequest/LogoutResponse 테스트 |
| `/oidc/register` | RP client 등록 및 credential 관리 |
| `/oidc/publish` | OIDC Discovery, JWKS, endpoint contract 확인 |
| `/oidc/authorizecheck` | authorize request, claim release, token preview 테스트 |
| `/oidc/logoutcheck` | OIDC logout request와 post logout redirect 검증 |

## 프로토콜 엔드포인트

### SAML

| 엔드포인트 | 용도 |
| --- | --- |
| `GET /api/saml/metadata` | IdP metadata XML |
| `GET/POST /api/saml/sso` | AuthnRequest 수신 및 SAMLResponse 발급 |
| `GET/POST /api/saml/slo` | SAML Single Logout 처리 |
| `GET /api/saml/sp-list` | 등록된 SP 목록 |
| `POST /api/saml/sp-register` | SP metadata 등록 |
| `GET /api/saml/debug-raw` | 저장된 SAML raw XML 조회 |

### OIDC

| 엔드포인트 | 용도 |
| --- | --- |
| `GET /.well-known/openid-configuration` | OIDC discovery document |
| `GET /api/oidc/jwks` | 공개 JWKS |
| `GET/POST /api/oidc/authorize` | authorize request 처리 |
| `POST /api/oidc/token` | authorization code와 PKCE 검증 후 token 발급 |
| `GET /api/oidc/userinfo` | access token 기반 userinfo 반환 |
| `GET/POST /api/oidc/logout` | end session logout 처리 |
| `GET /api/oidc/debug/raw/<key>` | OIDC raw debug bundle 조회 |

### 공통 API

| 엔드포인트 | 용도 |
| --- | --- |
| `GET /api/idpcore/info` | 패키지 상태와 데이터 카운트 |
| `GET /api/idpcore/users` | 활성 테스트 사용자 목록 |
| `GET /api/idpcore/users-temporary` | 임시 테스트 계정 목록 |
| `POST /api/idpcore/user-create-temporary` | 임시 테스트 계정 생성 |
| `POST /api/idpcore/user-update` | 테스트 계정 수정 |
| `POST /api/idpcore/user-delete` | 테스트 계정 삭제 |
| `GET /api/idpcore/presets?protocol=saml` | 속성/클레임 프리셋 |
| `GET /api/idpcore/saml-attribute-catalog` | SAML attribute OID catalog |

## 프로젝트 구조

```text
src/
├── app/
│   ├── layout.empty/          # 인증/프로토콜 후처리용 빈 레이아웃
│   ├── layout.topnav/         # Test IdP 상단 탭 레이아웃
│   ├── page.access/           # admin 로그인
│   ├── page.landing/          # Overview와 임시 계정 관리
│   ├── page.saml/             # SAML 화면군 라우팅
│   └── page.oidc/             # OIDC 화면군 라우팅
├── controller/
│   ├── base.py                # 세션 초기화
│   ├── user.py                # 로그인 사용자 검증
│   └── admin.py               # admin 권한 검증
├── model/
│   └── struct.py              # 프로젝트 루트 Struct
├── portal/
│   ├── season/                # WIZ 공통 UI, session, auth, ORM
│   ├── idpcore/               # 공통 사용자, preset, debug, audit
│   ├── samlidp/               # SAML IdP 모델, UI, route
│   └── oidcidp/               # OIDC Provider 모델, UI, route
└── assets/
    ├── brand/                 # Test IdP favicon/logo
    ├── font/SUIT/             # SUIT web font
    └── lang/                  # ko/en language resources
```

## 데이터와 저장소

| 경로 | 내용 |
| --- | --- |
| `data/idpcore.db` | 테스트 사용자, 속성 프리셋, debug payload, audit log |
| `data/samlidp.db` | SAML SP registry와 SAML transaction |
| `data/oidcidp.db` | OIDC RP client, authorization code, token log |
| `metadata/saml/idp/` | SAML IdP key/certificate |
| `metadata/saml/sp/` | 등록된 SP metadata XML |
| `metadata/oidc/` | OIDC signing key와 JWKS |
| `metadata/oidc/debug/` | OIDC raw debug JSON |
| `metadata/debug/` | SAML raw request/response XML |

## 개발 메모

- 초기 관리자 비밀번호는 `TEST_IDP_ADMIN_PASSWORD` 환경 변수로 설정하거나 Overview의 관리자 비밀번호 변경 기능으로 교체하세요.
- 임시 사용자, SAML SP, OIDC RP의 기본 유효기간은 24시간입니다.

## 테스트

```bash
cd /root/workspace/test-idp/project/main
/root/miniconda3/envs/test-idp/bin/python -m pytest tests
```

주요 테스트 범위:

- idpcore 사용자/프리셋/임시 계정
- SAML SP 등록, SSO, SLO, XML 보안 검증
- OIDC RP UI, authorize, token, userinfo
- compact UI template 검증
- rate limit, 삭제 권한, mass assignment 방어

---

# Test IdP (English)

Test IdP is a test-focused Identity Provider for validating SAML Service Providers and OpenID Connect Relying Parties. It lets SP/RP owners verify registration, metadata/discovery publication, SSO, token issuance, userinfo, logout, and raw XML/JWT debugging without depending on an external production IdP.

Live URL: <https://debug-idp.nanoha.kr/>

Framework: [WIZ Framework](https://github.com/season-framework/wiz) (`season==2.5.2`)

## Features

### Shared Core

- Create, edit, and delete temporary test accounts with a default 24-hour TTL
- Generate protocol-ready SAML attributes and OIDC claims from presets
- Clean up expired test accounts, SPs, and RPs from the admin console
- Extend validity or mark selected entries as permanent
- Store raw XML/JWT debug payloads and audit events
- Apply IP-based delete restrictions and rate limits
- Provide Korean/English resources and a compact operations UI

### SAML IdP

- Register SP metadata by XML upload or paste
- Parse Entity ID, ACS, SLO, certificates, and RequestedAttribute entries
- Publish IdP metadata XML
- Parse AuthnRequest values, preserve RelayState, and issue SAMLResponse payloads
- Handle Redirect/POST SSO and SLO flows
- Save and inspect raw SAML request/response XML

### OpenID Connect Provider

- Register, update, and delete RP clients
- Manage redirect URIs, response types, grant types, scopes, and auth methods
- Publish discovery document and JWKS
- Process authorization code + PKCE flows
- Issue access tokens and ID tokens from the token endpoint
- Return userinfo from bearer access tokens
- Validate end-session logout redirects
- Store authorize/token/userinfo/logout debug bundles

## Application Routes

| Path | Purpose |
| --- | --- |
| `/` | Overview, protocol entry points, temporary test accounts |
| `/access` | Admin login |
| `/saml/register` | SP metadata registration and SP list |
| `/saml/publish` | IdP metadata, SSO/SLO endpoints, certificate, XML |
| `/saml/logincheck` | AuthnRequest parsing and SAMLResponse test flow |
| `/saml/logoutcheck` | SAML LogoutRequest/LogoutResponse test flow |
| `/oidc/register` | RP registration and credential management |
| `/oidc/publish` | OIDC discovery, JWKS, endpoint contract |
| `/oidc/authorizecheck` | Authorize request, claim release, token preview |
| `/oidc/logoutcheck` | OIDC logout request and post logout redirect validation |

## Protocol Endpoints

### SAML

| Endpoint | Purpose |
| --- | --- |
| `GET /api/saml/metadata` | IdP metadata XML |
| `GET/POST /api/saml/sso` | Receive AuthnRequest and issue SAMLResponse |
| `GET/POST /api/saml/slo` | Process SAML Single Logout |
| `GET /api/saml/sp-list` | List registered SPs |
| `POST /api/saml/sp-register` | Register SP metadata |
| `GET /api/saml/debug-raw` | Read stored SAML raw XML |

### OIDC

| Endpoint | Purpose |
| --- | --- |
| `GET /.well-known/openid-configuration` | OIDC discovery document |
| `GET /api/oidc/jwks` | Public JWKS |
| `GET/POST /api/oidc/authorize` | Handle authorize requests |
| `POST /api/oidc/token` | Verify authorization code and PKCE, then issue tokens |
| `GET /api/oidc/userinfo` | Return userinfo for access tokens |
| `GET/POST /api/oidc/logout` | Process end-session logout |
| `GET /api/oidc/debug/raw/<key>` | Read OIDC raw debug bundle |

### Shared API

| Endpoint | Purpose |
| --- | --- |
| `GET /api/idpcore/info` | Package status and data counts |
| `GET /api/idpcore/users` | Active test users |
| `GET /api/idpcore/users-temporary` | Temporary test users |
| `POST /api/idpcore/user-create-temporary` | Create a temporary test user |
| `POST /api/idpcore/user-update` | Update a test user |
| `POST /api/idpcore/user-delete` | Delete a test user |
| `GET /api/idpcore/presets?protocol=saml` | Attribute/claim presets |
| `GET /api/idpcore/saml-attribute-catalog` | SAML attribute OID catalog |

## Architecture

```text
src/
├── app/
│   ├── layout.empty/          # Empty layout for auth/protocol pages
│   ├── layout.topnav/         # Test IdP top navigation layout
│   ├── page.access/           # Admin login
│   ├── page.landing/          # Overview and temporary account management
│   ├── page.saml/             # SAML route shell
│   └── page.oidc/             # OIDC route shell
├── controller/
│   ├── base.py                # Session bootstrap
│   ├── user.py                # Signed-in user guard
│   └── admin.py               # Admin guard
├── model/
│   └── struct.py              # Project root Struct
├── portal/
│   ├── season/                # Shared WIZ UI, session, auth, ORM
│   ├── idpcore/               # Users, presets, debug payloads, audit logs
│   ├── samlidp/               # SAML IdP models, UI, routes
│   └── oidcidp/               # OIDC Provider models, UI, routes
└── assets/
    ├── brand/                 # Test IdP favicon/logo
    ├── font/SUIT/             # SUIT web font
    └── lang/                  # ko/en language resources
```

## Storage

| Path | Contents |
| --- | --- |
| `data/idpcore.db` | Test users, presets, debug payloads, audit logs |
| `data/samlidp.db` | SAML SP registry and SAML transactions |
| `data/oidcidp.db` | OIDC RP clients, authorization codes, token logs |
| `metadata/saml/idp/` | SAML IdP key/certificate |
| `metadata/saml/sp/` | Registered SP metadata XML |
| `metadata/oidc/` | OIDC signing key and JWKS |
| `metadata/oidc/debug/` | OIDC raw debug JSON |
| `metadata/debug/` | SAML raw request/response XML |

## Development Notes

- Set the initial admin password with `TEST_IDP_ADMIN_PASSWORD` or rotate it from the Overview admin password dialog.
- Temporary users, SAML SPs, and OIDC RPs default to a 24-hour validity window.

## Tests

```bash
cd /root/workspace/test-idp/project/main
/root/miniconda3/envs/test-idp/bin/python -m pytest tests
```

Covered areas include idpcore data handling, SAML registration/SSO/SLO/security checks, OIDC UI and protocol flow behavior, compact UI templates, rate limits, delete permissions, and mass-assignment protection.
