# Test IDP 설계 문서

## 1. 문서 목적

이 문서는 test-idp 프로젝트에 SAML SP와 OIDC RP를 검증하기 위한 테스트용 IdP를 구축하기 위한 상세 설계 문서다.

- SAML 영역은 pysaml2 기반 테스트 IdP로 설계한다.
- OIDC 영역은 idpyoidc 기반 테스트 OP(OpenID Provider)로 설계한다.
- 화면 흐름과 사용 경험은 kafe-debug의 테스트용 SP/RP 도구를 참고하되, 역할을 반대로 뒤집어 SP와 RP가 테스트 대상이 되도록 설계한다.

핵심 목표는 다음과 같다.

- SP/RP 담당자가 별도 외부 IdP 없이 로컬 또는 개발 환경에서 인증 플로우를 재현할 수 있어야 한다.
- 메타데이터, Discovery, JWKS, Raw XML, JWT, RelayState, PKCE, ACR, NameID, Logout 흐름을 한 화면군에서 검증할 수 있어야 한다.
- kafe-debug처럼 단계형 화면과 즉시 확인 가능한 디버그 정보를 제공해야 한다.

## 2. 참고 기준: kafe-debug에서 계승할 요소

kafe-debug는 테스트용 SP/RP 도구로서 다음 특성이 있다.

- 랜딩에서 SAML과 OIDC를 명확히 분기한다.
- 상단 네비게이션과 단계형 진행 UI를 사용한다.
- 등록과 검증 단계를 분리해 사용자가 현재 위치를 쉽게 이해할 수 있다.
- Raw XML, JWT, 응답 파라미터를 화면에서 바로 확인할 수 있다.
- 등록한 메타데이터와 클라이언트 정보를 일정 기간 후 자동 정리한다.

이번 test-idp 설계는 이 UX 패턴을 그대로 계승하되, 다음처럼 역할만 반전한다.

| 참고 시스템 | 새 시스템 |
|---|---|
| SAML SP 디버거 | SAML IdP 디버거 |
| OIDC RP 디버거 | OIDC OP 디버거 |
| IdP 메타데이터 업로드 | SP 메타데이터 업로드 |
| OP 정보 등록 | RP 클라이언트 등록 |
| 응답 소비 결과 표시 | 인증 응답 발급 결과 표시 |

## 3. 제품 목표와 비목표

### 3.1 목표

1. SAML 테스트 IdP 제공
2. OIDC 테스트 OP 제공
3. 등록, 발급, 디버그, 로그아웃까지 한 프로젝트 안에서 일관된 UX 제공
4. 실무 검증 포인트를 화면에서 바로 확인 가능하도록 설계
5. 개발 중 임시 테스트 대상 정보를 쉽게 등록하고 쉽게 폐기 가능하도록 설계
6. 기본 제공 계정 외에 24시간만 유지되는 사용자 정의 임시 테스트 계정 제공

### 3.2 비목표

1. 운영용 상용 IdP 기능 전부를 구현하지 않는다.
2. 다중 테넌트 운영 관리 콘솔 수준의 권한 체계는 우선순위가 아니다.
3. 완전한 Federation 운영 기능과 외부 사용자 디렉토리 연동은 1차 범위에 포함하지 않는다.

## 4. 설계 원칙

### 4.1 WIZ 구조 준수

- 공통 UI와 서비스는 기존 season 패키지를 재사용한다.
- 프로토콜별 로직은 portal 패키지로 분리한다.
- 프로토콜 엔드포인트는 route 또는 App api가 아니라 실제 프로토콜 URI가 필요하므로 route 중심으로 설계한다.
- 구현 순서는 데이터 계층, 프로토콜 로직, UI 순서를 따른다.

### 4.2 역할 분리

- 공통 계층: 테스트 계정, 속성 프리셋, 디버그 저장소, 공통 레이아웃
- SAML 계층: SP 메타데이터 등록, AuthnRequest 파싱, SAMLResponse 생성, SLO 처리
- OIDC 계층: RP 등록, authorize, token, userinfo, jwks, discovery, logout 처리

### 4.3 UX 원칙

- kafe-debug처럼 시작점은 단순하게 유지한다.
- 모든 주요 파라미터는 폼 입력과 즉시 보이는 결과를 같은 흐름 안에서 제공한다.
- 디버그 정보는 숨기지 않고 토글 형태로 노출한다.
- 성공과 실패를 모두 재현할 수 있게 설계한다.

### 4.4 프레임워크 규칙 반영

- 탭 전환 감지는 ngDoCheck 대신 Router.events NavigationEnd를 사용한다.
- WIZ의 service.render 호출이 필요한 상태 변경 흐름을 기준으로 UI를 설계한다.
- wiz.response는 try 블록 밖에서 종료되도록 백엔드 흐름을 분리한다.

## 5. 권장 프로젝트 구조

### 5.1 Source 앱

```text
src/app/
├── layout.topnav/                 # kafe-debug 느낌의 상단 네비게이션 레이아웃
├── layout.empty/                  # 인증 처리/콜백/오류 전용 레이아웃
├── page.landing/                  # 시작 화면
├── page.saml/                     # /saml/** 라우팅 전용
├── page.oidc/                     # /oidc/** 라우팅 전용
├── page.process.saml.logout/      # SAML 로그아웃 후처리 페이지
└── page.process.oidc.logout/      # OIDC 로그아웃 후처리 페이지
```

### 5.2 Portal 패키지

```text
src/portal/
├── season/                        # 기존 공통 패키지 재사용
├── idpcore/                       # 공통 테스트 계정, 속성 프리셋, 디버그 저장소
├── samlidp/                       # SAML IdP 전용 패키지
└── oidcidp/                       # OIDC OP 전용 패키지
```

### 5.3 권장 세부 구조

```text
src/portal/samlidp/
├── app/
│   ├── step/
│   ├── register-sp/
│   ├── publish-metadata/
│   ├── logincheck/
│   └── logoutcheck/
├── model/
│   ├── db/
│   ├── struct/
│   └── struct.py
├── route/
│   └── saml/
├── assets/
└── README.md

src/portal/oidcidp/
├── app/
│   ├── step/
│   ├── register-rp/
│   ├── publish-discovery/
│   ├── authorizecheck/
│   └── logoutcheck/
├── model/
│   ├── db/
│   ├── struct/
│   └── struct.py
├── route/
│   └── oidc/
├── assets/
└── README.md
```

## 6. 정보구조와 화면 설계

## 6.1 공통 UX

### 랜딩 페이지

- 제목: Test Identity Provider
- 설명: SAML IdP 또는 OIDC Provider로 동작하여 SP와 RP를 검증할 수 있다고 명시
- 두 개의 진입 카드 제공
  - SAML IdP
  - OIDC Provider
- 임시 계정 생성 진입 버튼 또는 요약 카드 제공
- 최근 등록 대상 수, 최근 발급 성공/실패 수, 샘플 계정 수 같은 요약 카드 제공

### 임시 계정 UX

- 기본 제공 테스트 계정과 별도로 사용자가 직접 생성하는 임시 계정 지원
- 임시 계정은 생성 후 24시간 동안만 유효
- 생성 시 아래 정보를 사용자가 직접 설정 가능
  - 계정 ID
  - 비밀번호
  - 표시 이름, 이메일
  - SAML Attribute 세트
  - OIDC Claims 세트
- 만료 예정 시각과 남은 시간을 UI에 표시
- 만료된 계정은 선택 목록과 로그인 대상에서 자동 제외

### 상단 네비게이션

- 브랜드 영역
- SAML 탭
- OIDC 탭
- 현재 로그인한 테스트 사용자 또는 로컬 세션 상태

### 디버그 공통 패턴

- Copy 버튼
- Download 버튼
- Raw XML/JWT 보기 토글
- Warning 배지와 사유 표시
- Local logout, Global logout 구분

## 6.2 SAML 화면군

### 1단계: SP 등록 화면

경로:

- /saml/register

기능:

- SP 메타데이터 XML 파일 업로드
- Raw XML 붙여넣기
- XML 문법 검증
- SP 메타데이터 필수 요소 검증
  - EntityDescriptor
  - entityID
  - SPSSODescriptor
  - AssertionConsumerService
- 선택 검증
  - SingleLogoutService 존재 여부
  - 서명 인증서 존재 여부
  - AuthnRequestsSigned 값
  - WantAssertionsSigned 값
- 저장 후 경고 표시
  - 인증서 없음
  - SLO 미지원
  - 암호화 키 없음

화면 출력:

- 파싱된 entityID
- ACS 엔드포인트 목록
- SLO 엔드포인트 목록
- 요청 NameIDFormat 힌트
- RequestedAttribute 목록

### 2단계: IDP 메타데이터 배포 화면

경로:

- /saml/publish

기능:

- 현재 테스트 IdP의 메타데이터 XML 표시
- 복사, 다운로드 제공
- 공개 인증서 표시
- 서명 알고리즘 설정 표시
- SP가 등록해야 할 엔드포인트 안내

메타데이터에 포함할 정보:

- entityID
- SingleSignOnService POST/Redirect
- SingleLogoutService POST/Redirect
- signing certificate
- optional encryption certificate
- NameIDFormat 지원 목록

### 3단계: 로그인 검증 화면

경로:

- /saml/logincheck

주요 시나리오:

1. SP initiated SSO
2. IdP initiated SSO
3. 속성 릴리스 제어
4. NameID 포맷 변경
5. Response/Assertion 서명 여부 제어
6. ForceAuthn, IsPassive, RequestedAuthnContext 수용 결과 확인

화면 입력 항목:

- 대상 SP 선택
- 테스트 사용자 선택
- NameID value 및 format
- Attribute preset 선택
- 개별 attribute override
- Response sign 여부
- Assertion sign 여부
- Assertion encrypt 여부
- SessionIndex 강제 생성 여부
- RelayState 표시 및 반환 여부

화면 출력 항목:

- Raw AuthnRequest XML
- 파싱된 AuthnRequest 요약
  - Issuer
  - ACS URL
  - Request ID
  - RequestedAuthnContext
  - NameIDPolicy
  - ForceAuthn
  - IsPassive
- 발급된 SAMLResponse XML
- 실제 전송 Binding
- Warning 정보
  - SP 메타데이터에 암호화 키가 없는데 encrypt 요청함
  - RequestedAuthnContext 미지원
  - NameID 정책 미충족

### 4단계: 로그아웃 검증 화면

경로:

- /saml/logoutcheck

지원 흐름:

1. SP initiated SLO 수신 및 응답
2. IdP initiated SLO 시작
3. Local session clear

표시 항목:

- SessionIndex
- NameID
- 최근 LogoutRequest XML
- 최근 LogoutResponse XML
- 성공 여부 및 사유

## 6.3 OIDC 화면군

### 1단계: RP 등록 화면

경로:

- /oidc/register

기능:

- RP 수동 등록
- 동적 클라이언트 등록용 샘플 정보 생성
- redirect_uri 다중 등록
- post_logout_redirect_uri 등록
- client authentication 방식 설정
- grant_types, response_types, scope 정책 설정
- 공개 RP 여부 설정
- JWKS 또는 jwks_uri 입력

필수 입력:

- client_name
- redirect_uris
- token_endpoint_auth_method
- allowed grant_types
- allowed response_types

저장 후 결과:

- client_id 발급
- client_secret 발급 또는 public client 처리
- issuer 안내
- discovery 문서 링크 안내

### 2단계: Discovery/JWKS 배포 화면

경로:

- /oidc/publish

기능:

- .well-known/openid-configuration 표시
- jwks 문서 표시
- 복사/다운로드 제공
- 엔드포인트 목록 안내

출력 항목:

- issuer
- authorization_endpoint
- token_endpoint
- userinfo_endpoint
- jwks_uri
- end_session_endpoint
- registration_endpoint 선택 지원 여부
- 지원 scope 목록
- 지원 claims 목록
- 지원 response_type, grant_type, token auth method 목록

### 3단계: Authorization 검증 화면

경로:

- /oidc/authorizecheck

주요 시나리오:

1. Authorization Code
2. Authorization Code + PKCE
3. Hybrid
4. Implicit
5. prompt, max_age, nonce, acr_values 테스트
6. consent 화면 표시/생략
7. 에러 응답 재현

입력 항목:

- 대상 RP 선택
- 테스트 사용자 선택
- scope
- claims
- response_type
- response_mode
- nonce
- state
- prompt
- max_age
- acr_values
- code_challenge 및 method
- 강제 에러 모드
  - access_denied
  - login_required
  - consent_required
  - invalid_request

출력 항목:

- Raw authorize request
- 파싱된 authorize 파라미터
- consent 결과
- redirect URI
- authorization code
- access token
- id token
- userinfo 응답
- decoded JWT

### 4단계: Logout 검증 화면

경로:

- /oidc/logoutcheck

지원 흐름:

- RP initiated logout
- post_logout_redirect_uri 검증
- id_token_hint 기반 세션 식별
- local session clear

표시 항목:

- 최근 logout 요청
- 세션 매칭 결과
- redirect 대상
- warning

## 7. 백엔드 아키텍처

## 7.1 공통 패키지: idpcore

역할:

- 테스트 사용자 관리
- 속성/클레임 프리셋 관리
- Raw 디버그 페이로드 저장
- 최근 인증 트랜잭션 요약 조회

권장 Struct:

- user
- attribute_preset
- debug_payload
- audit

권장 파일 저장소:

- metadata/debug/
- metadata/saml/
- metadata/oidc/

## 7.2 SAML IdP 계층

핵심 라이브러리:

- pysaml2
- xmlsec1

주요 책임:

- SP 메타데이터 검증 및 등록
- IdP 메타데이터 생성
- AuthnRequest 파싱
- SAMLResponse 생성 및 서명
- Assertion 암호화
- SLO 처리

권장 Struct 구성:

- registry: 등록된 SP 메타데이터 관리
- metadata: IdP 메타데이터 생성
- process: SSO/SLO 처리
- response_builder: NameID, AttributeStatement, Conditions 생성
- debug: raw xml 저장 및 조회

## 7.3 OIDC OP 계층

핵심 라이브러리:

- idpyoidc
- cryptojwt

주요 책임:

- provider configuration 생성
- JWKS 생성/로딩
- RP 클라이언트 등록
- authorize 처리
- token 발급
- id token 생성
- userinfo 제공
- end session 처리

권장 Struct 구성:

- client: RP 등록 정보 관리
- provider: provider info 및 jwks 관리
- authorization: authorize request 처리
- token: code, access token, id token 발급
- userinfo: scope와 claims 기반 사용자 정보 릴리스
- logout: end session 처리
- debug: request, response, token payload 기록

## 8. 권장 엔드포인트 설계

## 8.1 SAML Route

```text
/api/saml/metadata
/api/saml/sso
/api/saml/slo
/api/saml/slo/callback
/api/saml/login/init              # IdP initiated SSO helper
/api/saml/debug/raw/<key>
```

설명:

- metadata: SP가 읽어갈 IdP 메타데이터 제공
- sso: AuthnRequest 수신 및 로그인/동의 후 SAMLResponse 반환
- slo: LogoutRequest, LogoutResponse 처리
- login/init: 등록된 SP 대상으로 unsolicited response 테스트 보조
- debug/raw: 저장한 XML 조회

## 8.2 OIDC Route

```text
/.well-known/openid-configuration
/api/oidc/jwks
/api/oidc/authorize
/api/oidc/token
/api/oidc/userinfo
/api/oidc/logout
/api/oidc/logout/callback
/api/oidc/introspect              # 선택
/api/oidc/revoke                  # 선택
/api/oidc/register                # 2차 단계의 동적 등록용
/api/oidc/debug/raw/<key>
```

설명:

- authorize: 로그인 세션 확인, 사용자 선택, consent 후 redirect
- token: code 교환, client auth 검증, PKCE 검증
- userinfo: access token scope에 따라 응답
- logout: end session 요청 처리
- register: 향후 RP 동적 등록 실험용 확장 지점

## 9. 데이터 모델 설계

## 9.1 공통 테이블

### idp_user

| 컬럼 | 타입 | 설명 |
|---|---|---|
| id | char(32) | 내부 사용자 ID |
| username | varchar(64) | 로그인용 이름 |
| password_hash | varchar(255) | 테스트 로그인 비밀번호 |
| email | varchar(255) | 이메일 |
| display_name | varchar(255) | 표시 이름 |
| role | varchar(32) | admin, tester |
| profile | json | 공통 사용자 속성 |
| created | datetime | 생성일 |

### idp_attribute_preset

| 컬럼 | 타입 | 설명 |
|---|---|---|
| id | char(32) | 프리셋 ID |
| protocol | varchar(16) | saml, oidc |
| name | varchar(64) | 프리셋 이름 |
| payload | json | 속성 또는 claims 템플릿 |
| created | datetime | 생성일 |

## 9.2 SAML 테이블

### saml_sp_registry

| 컬럼 | 타입 | 설명 |
|---|---|---|
| id | char(32) | 내부 ID |
| entity_id | varchar(512) | SP entityID |
| acs_url | json | ACS 목록 |
| slo_url | json | SLO 목록 |
| nameid_formats | json | 요청/지원 NameID 포맷 |
| certificates | json | SP signing/encryption cert 정보 |
| requested_attributes | json | 요청 속성 |
| raw_metadata_path | varchar(255) | 저장 XML 경로 |
| flags | json | signed/encrypted 관련 힌트 |
| created | datetime | 생성일 |
| updated | datetime | 수정일 |

### saml_transaction

| 컬럼 | 타입 | 설명 |
|---|---|---|
| id | char(32) | 트랜잭션 ID |
| request_id | varchar(255) | AuthnRequest ID |
| sp_entity_id | varchar(512) | 요청 SP |
| relay_state | varchar(512) | RelayState |
| binding | varchar(32) | Redirect, POST |
| nameid_format_requested | varchar(255) | 요청 NameID |
| authn_context_requested | json | 요청 ACR |
| raw_request_path | varchar(255) | Raw Request XML |
| raw_response_path | varchar(255) | Raw Response XML |
| session_index | varchar(255) | 발급 세션 인덱스 |
| status | varchar(32) | success, error, logout |
| created | datetime | 생성일 |

## 9.3 OIDC 테이블

### oidc_rp_client

| 컬럼 | 타입 | 설명 |
|---|---|---|
| id | char(32) | 내부 ID |
| client_id | varchar(255) | 발급된 클라이언트 ID |
| client_secret | varchar(255) | 비밀값 또는 공란 |
| client_name | varchar(255) | RP 이름 |
| redirect_uris | json | 허용 Redirect URI |
| post_logout_redirect_uris | json | 로그아웃 복귀 URI |
| grant_types | json | 허용 grant |
| response_types | json | 허용 response type |
| scope_policy | json | 허용 scope |
| claims_policy | json | 허용 claims |
| token_endpoint_auth_method | varchar(64) | client_secret_basic 등 |
| jwks | json | RP 공개키 또는 null |
| extra | json | 추가 설정 |
| created | datetime | 생성일 |

### oidc_authorization_code

| 컬럼 | 타입 | 설명 |
|---|---|---|
| id | char(32) | 내부 ID |
| code | varchar(255) | authorization code |
| client_id | varchar(255) | RP client_id |
| user_id | char(32) | 인증 사용자 |
| redirect_uri | varchar(1024) | redirect_uri |
| scope | varchar(1024) | scope 문자열 |
| nonce | varchar(255) | nonce |
| code_challenge | varchar(255) | PKCE challenge |
| code_challenge_method | varchar(32) | plain, S256 |
| auth_time | datetime | 인증 시간 |
| expires | datetime | 만료 시간 |
| consumed | datetime | 사용 시간 |

### oidc_token_log

| 컬럼 | 타입 | 설명 |
|---|---|---|
| id | char(32) | 내부 ID |
| client_id | varchar(255) | RP |
| user_id | char(32) | 사용자 |
| grant_type | varchar(64) | code, implicit, hybrid |
| access_token_jti | varchar(255) | access token 식별자 |
| id_token_jti | varchar(255) | id token 식별자 |
| raw_request | json | token request |
| raw_response | json | token response |
| created | datetime | 생성일 |

## 10. 프로토콜 플로우 설계

## 10.1 SAML SP initiated SSO

1. SP가 /api/saml/sso 로 AuthnRequest 전송
2. samlidp.process가 Request 파싱 및 saml_transaction 생성
3. 사용자 세션이 없으면 로그인/사용자 선택 화면으로 이동
4. 속성 프리셋 및 NameID 정책을 적용
5. SAMLResponse 생성, 서명 또는 암호화 적용
6. SP ACS로 POST 또는 Redirect 반환
7. Raw Request와 Raw Response를 디버그 저장소에 기록

## 10.2 SAML IdP initiated SSO

1. 사용자가 /saml/logincheck 에서 대상 SP 선택
2. NameID와 Attribute preset 지정
3. AuthnRequest 없이 unsolicited response 생성
4. ACS로 바로 응답 전송
5. 화면에 경고 표시
   - SP가 unsolicited를 허용하지 않을 수 있음

## 10.3 OIDC Authorization Code

1. RP가 /api/oidc/authorize 호출
2. oidcidp.authorization이 client_id, redirect_uri, scope, response_type 검증
3. 로그인 세션 없으면 테스트 사용자 선택 화면 표시
4. consent 필요 시 scope와 claims 동의 화면 표시
5. authorization code 저장
6. redirect_uri로 code와 state 반환
7. RP가 /api/oidc/token 호출
8. client auth와 PKCE 검증 후 access token, id token 발급
9. 필요 시 /api/oidc/userinfo 호출

## 10.4 OIDC Hybrid and Implicit

- authorize 단계에서 id_token 또는 access_token 직접 반환
- JWT payload를 화면에서 바로 해석 가능해야 한다.
- nonce 누락, response_mode 부적합, redirect mismatch 같은 오류도 재현 가능해야 한다.

## 11. 사용자와 속성 설계

기본 제공 테스트 계정 예시:

| 아이디 | 비밀번호 | 용도 |
|---|---|---|
| admin | admin1234 | 관리 및 모든 속성 테스트 |
| alice | alice1234 | 일반 사용자 |
| bob | bob1234 | 다른 조직 소속 사용자 |
| mfauser | mfa1234 | MFA/고신뢰 ACR 테스트 |

임시 계정 정책:

- 사용자가 UI에서 직접 생성할 수 있다.
- 생성 시점부터 24시간 후 자동 만료된다.
- 임시 계정은 기본 profile 외에 protocol별 필드를 가진다.
  - `saml_attributes`
  - `oidc_claims`
- 만료 계정은 인증, 계정 선택, 로그아웃 대상에서 제외된다.
- 정리 작업 수행 시 만료 계정의 세션 및 디버그 연관 데이터도 함께 정리한다.

기본 SAML Attribute preset 예시:

- minimal
- eduPerson-basic
- eduPerson-full
- custom-json

기본 OIDC claims preset 예시:

- openid-basic
- profile
- email
- groups
- academic-profile

## 12. 디버깅 및 운영 편의 기능

1. Raw XML/JWT 저장
2. Copy, Download 버튼
3. Warning 배지
4. 최근 인증 내역 목록
5. 등록 대상 7일 자동 정리
6. 임시 계정 24시간 자동 만료 및 정리
7. 기본 샘플 대상 보호 목록
8. 로그아웃 시 세션과 디버그 저장소 정리

파일 저장 전략:

- metadata/saml/sp/<id>.xml
- metadata/saml/debug/<transaction-id>-request.xml
- metadata/saml/debug/<transaction-id>-response.xml
- metadata/oidc/jwks_public.json
- metadata/oidc/jwks_private.json
- metadata/oidc/debug/<transaction-id>.json

## 13. 보안 및 테스트 환경 정책

- 이 시스템은 테스트용 도구이므로 self-signed 인증서와 verify false 옵션이 일부 구간에서 허용될 수 있다.
- 단, 운영용 기본값처럼 보이지 않도록 모든 화면에 test-only 배지를 둔다.
- 만료 시간이 짧은 code와 token을 사용한다.
- local session과 protocol session을 명확히 구분한다.
- 공개용 인터넷 환경 배포가 아니라 내부 개발/검증 환경 기준으로 설계한다.

## 14. 구현 우선순위

### Phase 1: 기반 구축

1. layout.topnav, page.landing, page.saml, page.oidc 생성
2. idpcore 패키지 생성
3. 테스트 계정과 속성 프리셋 구조 생성

### Phase 2: SAML 1차

1. SP 메타데이터 등록
2. IdP 메타데이터 생성
3. SP initiated SSO
4. Raw XML 뷰어

### Phase 3: OIDC 1차

1. RP 등록
2. discovery와 jwks 배포
3. authorization code flow
4. PKCE 지원
5. JWT 디코드 뷰어

### Phase 4: 프로토콜 확장

1. SAML SLO
2. OIDC hybrid, implicit
3. userinfo, introspection, revoke
4. consent와 에러 시뮬레이션 강화

### Phase 5: 실제 연동형 테스트 하네스

1. mock SAML SP HTTP 서버 구축
2. mock OIDC RP HTTP 서버 구축
3. 테스트 실행 스크립트와 HTML 리포트 구축
4. 임시 계정 속성 반영까지 포함한 회귀 테스트 구축

## 15. 테스트 전략

test-idp는 단순 단위 테스트만으로는 충분하지 않다. kafe-debug처럼 실제 HTTP 서버를 띄워 프로토콜 상대편 역할을 흉내 내는 통합 테스트가 필요하다.

### 15.1 테스트 계층

1. 단위 테스트
   - Struct, parser, token builder, metadata generator 검증
2. 프로토콜 통합 테스트
   - 간단한 HTTP 서버를 띄워 mock SP/RP와 실제 연동처럼 검증
3. 수동 검증 시나리오
   - 브라우저 화면에서 Raw XML, JWT, logout 흐름 확인

### 15.2 SAML 테스트 방식

- mock SP 서버가 아래 endpoint를 제공
  - metadata
  - ACS
  - SLO
- test-idp는 이 mock SP metadata를 등록한 뒤 실제 SSO/SLO를 수행
- 테스트는 아래를 검증
  - AuthnRequest 처리
  - SAMLResponse 전달
  - RelayState 유지
  - NameID format 반영
  - 임시 계정 attribute 반영
  - SLO round-trip

### 15.3 OIDC 테스트 방식

- mock RP 서버가 아래 endpoint를 제공
  - callback
  - post logout redirect
- test-idp의 discovery, jwks, authorize, token, userinfo, logout endpoint와 실제로 통신
- 테스트는 아래를 검증
  - discovery 문서 조회
  - JWKS 조회
  - authorization code + PKCE
  - id_token/userinfo claims
  - 임시 계정 claims 반영
  - logout redirect

### 15.4 실행 방식

- `project/main/tests/` 아래에 테스트 코드를 둔다.
- `run_idp_protocol_tests.sh`로 테스트를 일괄 실행한다.
- 기본 Python 환경은 `/root/miniconda3/envs/test-idp/bin/python`을 사용한다.
- 테스트 결과는 텍스트와 HTML 리포트 둘 다 확인 가능하게 한다.

## 16. 구현 시 주의사항

1. kafe-debug의 UX는 참고하되, 금지된 ngDoCheck 패턴은 그대로 가져오면 안 된다.
2. SAML 응답 생성과 OIDC 토큰 생성은 공통 사용자 속성 모델을 공유해야 한다.
3. 테스트 중 저장되는 raw payload는 파일시스템과 세션 인덱스를 함께 써서 화면 조회를 단순화하는 편이 낫다.
4. SP/RP 등록 정보 자동 삭제 정책은 샘플 기본 대상만 제외하고 적용한다.
5. OIDC dynamic registration endpoint는 2차 범위로 두는 편이 초기 복잡도를 낮춘다.

## 17. 권장 최종 산출물

최초 구현 완료 기준은 아래와 같다.

1. /saml/register 에서 SP 메타데이터 등록 가능
2. /saml/publish 에서 IdP 메타데이터 다운로드 가능
3. /saml/logincheck 에서 SP initiated 또는 IdP initiated SSO 1회 이상 성공
4. /oidc/register 에서 RP 등록 후 client_id 발급 가능
5. /oidc/publish 에서 discovery와 jwks 문서 노출 가능
6. /oidc/authorizecheck 에서 authorization code + PKCE 흐름 1회 이상 성공
7. 두 프로토콜 모두 raw request/response 디버그 뷰 제공
8. Local logout과 protocol logout 흐름 제공
9. mock SP/RP 기반 통합 테스트 스크립트 제공
10. HTML 또는 동등 수준의 테스트 리포트 제공

이 설계는 test-idp를 kafe-debug의 반대 역할을 수행하는 대칭형 인증 디버거로 만드는 것을 목표로 한다. 구현 시에는 먼저 SAML과 OIDC의 최소 기능을 수직 슬라이스로 완성한 뒤, 그 위에 logout, consent, error simulation, dynamic registration 같은 확장 기능을 얹는 방식이 가장 안정적이다.