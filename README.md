# Test IdP

Test IdP는 SAML Service Provider(SP)와 OpenID Connect Relying Party(RP)를 검증하기 위한 테스트용 Identity Provider입니다. 외부 상용 IdP 없이 SP/RP 등록, 메타데이터/Discovery 배포, SSO, Token, UserInfo, Logout, Raw XML/JWT 디버그 흐름을 한 프로젝트 안에서 확인할 수 있습니다.

Live URL: <https://debug-idp.nanoha.kr/>

Framework: [WIZ Framework](https://github.com/season-framework/wiz) (`season==2.5.2`)

## 설치 및 실행

Test IdP 저장소는 WIZ 워크스페이스 전체가 아니라 `project/main`에 들어가는 애플리케이션 프로젝트입니다. 아래 명령은 Linux/macOS 셸 기준이며, WIZ 공식 구조와 CLI 흐름에 맞춰 새 워크스페이스를 구성합니다.

### 1. 준비 사항

- Git
- [Miniconda 또는 Anaconda](https://docs.conda.io/projects/conda/en/latest/user-guide/install/index.html) (Miniconda 권장)
- Node.js 18.19.1 이상과 npm (Node.js 20 LTS 권장)
- Ubuntu/Debian에서는 SAML 라이브러리 빌드용 시스템 패키지 설치

```bash
sudo apt update
sudo apt install -y git build-essential \
  pkg-config libxml2-dev libxmlsec1-dev libxmlsec1-openssl

conda --version
node --version
npm --version
git --version
```

macOS에서는 Xcode Command Line Tools와 Homebrew를 준비한 뒤 Miniconda와 `node`, `libxml2`, `libxmlsec1`, `pkg-config`를 설치합니다. `conda activate`를 처음 사용하는 셸이라면 `conda init` 실행 후 터미널을 다시 엽니다.

### 2. Conda 환경과 WIZ 워크스페이스 구성

```bash
mkdir test-idp-local
cd test-idp-local

conda create --name test-idp python=3.12 --yes
conda activate test-idp
python --version
python -m pip install --upgrade pip
python -m pip install "season==2.5.2" peewee pymysql bcrypt \
  python3-saml oic pysaml2 lxml signxml cryptography pytest

wiz --version
wiz create workspace
cd workspace
wiz project create --project=main --uri=https://github.com/ImuruKevol/test-idp.git
```

Python과 WIZ는 `test-idp` Conda 환경 안에 설치됩니다. `season`은 PyPI로 배포되므로 Conda 환경을 활성화한 상태에서 `python -m pip`로 설치합니다. `wiz create workspace`는 `config/`, `public/`, `ide/`, `plugin/`, `project/`로 이루어진 WIZ 워크스페이스를 만들고, `wiz project create`는 이 저장소를 `project/main`으로 가져와 초기 빌드를 수행합니다.

### 3. 로컬 설정

Git에서 제외되는 SQLite 설정을 샘플로부터 생성합니다. DB 파일과 SAML/OIDC 키는 첫 실행 시 각각 `data/`, `metadata/` 아래에 자동 생성됩니다.

```bash
cp project/main/config-sample/database.py project/main/config/database.py

# 첫 실행 전에 반드시 원하는 관리자 비밀번호로 변경하세요.
export TEST_IDP_ADMIN_PASSWORD='replace-with-a-strong-password'
```

`TEST_IDP_ADMIN_PASSWORD`를 지정하지 않으면 초기 admin 비밀번호가 임의 생성되어 확인할 수 없습니다. 이미 DB를 생성한 뒤 비밀번호를 바꾸려면 `python project/main/scripts/change_admin_password.py`를 실행합니다.

### 4. 빌드와 개발 서버 실행

```bash
wiz project build --project=main
wiz run --port=3000
```

- 애플리케이션: <http://127.0.0.1:3000/>
- WIZ IDE: <http://127.0.0.1:3000/wiz>
- 종료: 실행 중인 터미널에서 `Ctrl+C`

이후 다시 실행할 때는 `test-idp` Conda 환경을 활성화하고 WIZ 워크스페이스로 이동합니다.

```bash
cd test-idp-local
conda activate test-idp
cd workspace
wiz run --port=3000
```

### 5. 서비스 데몬 실행

리눅스 시스템 서비스로 등록하여 실행하는 방법도 존재합니다.

```bash
# 서비스 등록
wiz service regist myapp

# 서비스 시작
wiz service start myapp

# 서비스 중지
wiz service stop myapp

# 서비스 상태 확인
wiz service status myapp
```

### 자주 사용하는 WIZ 명령

| 명령 | 용도 |
| --- | --- |
| `wiz project list` | 워크스페이스의 프로젝트 목록 확인 |
| `wiz project build --project=main` | 소스 변경 후 일반 빌드 |
| `wiz project build --project=main --clean` | 앱/API 구조 변경 또는 캐시 문제 시 클린 빌드 |
| `wiz project npm install --project=main` | 빌드 디렉터리의 npm 의존성 재설치 |
| `wiz run --port=3000` | 개발 서버 실행 |
| `wiz bundle --project=main` | 배포용 번들 생성 |

> 모든 `wiz` 명령은 `project/main`이 아니라 `config/`, `public/`, `project/`가 보이는 WIZ 워크스페이스 루트에서 실행합니다.

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

## WIZ 프로젝트 구조

```text
workspace/                     # WIZ 명령 실행 위치
├── config/                    # WIZ 서버 설정
├── public/                    # WIZ 서버 엔트리포인트
├── ide/                       # 웹 기반 WIZ IDE
├── plugin/                    # WIZ 플러그인
└── project/
    └── main/                  # 이 Git 저장소
        ├── config/            # 로컬 프로젝트 설정 (Git 제외)
        ├── data/              # SQLite DB (자동 생성, Git 제외)
        ├── metadata/          # SAML/OIDC 키·디버그 데이터 (Git 제외)
        ├── build/             # 개발 빌드 산출물
        ├── bundle/            # 배포 번들 산출물
        └── src/
            ├── app/
            │   ├── layout.empty/  # 인증/프로토콜 후처리용 빈 레이아웃
            │   ├── layout.topnav/ # Test IdP 상단 탭 레이아웃
            │   ├── page.access/   # admin 로그인
            │   ├── page.landing/  # Overview와 임시 계정 관리
            │   ├── page.saml/     # SAML 화면군 라우팅
            │   └── page.oidc/     # OIDC 화면군 라우팅
            ├── controller/        # 인증·권한 전처리
            ├── model/             # 프로젝트 루트 Struct
            ├── portal/
            │   ├── season/        # WIZ 공통 UI, session, auth, ORM
            │   ├── idpcore/       # 공통 사용자, preset, debug, audit
            │   ├── samlidp/       # SAML IdP 모델, UI, route
            │   └── oidcidp/       # OIDC Provider 모델, UI, route
            └── assets/            # 브랜드, 폰트, 다국어 리소스
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
cd project/main
python -m pytest tests
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

## Installation and Running

This repository is an application project placed at `project/main`, not a complete WIZ workspace. The commands below create a fresh workspace following the official WIZ layout and CLI workflow. They assume a Linux or macOS shell.

### 1. Prerequisites

- Git
- [Miniconda or Anaconda](https://docs.conda.io/projects/conda/en/latest/user-guide/install/index.html) (Miniconda recommended)
- Node.js 18.19.1 or later with npm (Node.js 20 LTS recommended)
- SAML build libraries on Ubuntu/Debian

```bash
sudo apt update
sudo apt install -y git build-essential \
  pkg-config libxml2-dev libxmlsec1-dev libxmlsec1-openssl

conda --version
node --version
npm --version
git --version
```

On macOS, install Xcode Command Line Tools, Miniconda, and use Homebrew to install `node`, `libxml2`, `libxmlsec1`, and `pkg-config`. If the shell has not used `conda activate` before, run `conda init` and reopen the terminal.

### 2. Create the Conda environment and WIZ workspace

```bash
mkdir test-idp-local
cd test-idp-local

conda create --name test-idp python=3.12 --yes
conda activate test-idp
python --version
python -m pip install --upgrade pip
python -m pip install "season==2.5.2" peewee pymysql bcrypt \
  python3-saml oic pysaml2 lxml signxml cryptography pytest

wiz --version
wiz create workspace
cd workspace
wiz project create --project=main --uri=https://github.com/ImuruKevol/test-idp.git
```

Python and WIZ are installed inside the `test-idp` Conda environment. Because `season` is distributed through PyPI, install it with `python -m pip` after activating that environment. `wiz create workspace` creates the WIZ `config/`, `public/`, `ide/`, `plugin/`, and `project/` directories. `wiz project create` clones this repository into `project/main` and performs the initial build.

### 3. Configure local storage

Create the Git-ignored SQLite configuration from the included sample. Database files and SAML/OIDC keys are generated automatically under `data/` and `metadata/` on first use.

```bash
cp project/main/config-sample/database.py project/main/config/database.py

# Set this to a strong password before the first run.
export TEST_IDP_ADMIN_PASSWORD='replace-with-a-strong-password'
```

If `TEST_IDP_ADMIN_PASSWORD` is omitted, the initial admin password is generated randomly and cannot be retrieved. If the database already exists, run `python project/main/scripts/change_admin_password.py` to replace it.

### 4. Build and start the development server

```bash
wiz project build --project=main
wiz run --port=3000
```

- Application: <http://127.0.0.1:3000/>
- WIZ IDE: <http://127.0.0.1:3000/wiz>
- Stop: press `Ctrl+C` in the server terminal

For later runs, activate the `test-idp` Conda environment and return to the WIZ workspace root.

```bash
cd test-idp-local
conda activate test-idp
cd workspace
wiz run --port=3000
```

### 5. Service Daemon Execution

```bash
# 서비스 등록
wiz service regist myapp

# 서비스 시작
wiz service start myapp

# 서비스 중지
wiz service stop myapp

# 서비스 상태 확인
wiz service status myapp
```

### Common WIZ commands

| Command | Purpose |
| --- | --- |
| `wiz project list` | List projects in the workspace |
| `wiz project build --project=main` | Run a normal build after source changes |
| `wiz project build --project=main --clean` | Clean-build after app/API structure changes or cache issues |
| `wiz project npm install --project=main` | Reinstall npm dependencies in the build directory |
| `wiz run --port=3000` | Start the development server |
| `wiz bundle --project=main` | Create a deployment bundle |

> Run every `wiz` command from the WIZ workspace root where `config/`, `public/`, and `project/` are visible, not from `project/main`.

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

## WIZ Project Layout

```text
workspace/                     # Run WIZ commands here
├── config/                    # WIZ server configuration
├── public/                    # WIZ server entry point
├── ide/                       # Web-based WIZ IDE
├── plugin/                    # WIZ plugins
└── project/
    └── main/                  # This Git repository
        ├── config/            # Local project config (Git-ignored)
        ├── data/              # SQLite databases (generated, Git-ignored)
        ├── metadata/          # SAML/OIDC keys and debug data (Git-ignored)
        ├── build/             # Development build output
        ├── bundle/            # Deployment bundle output
        └── src/
            ├── app/
            │   ├── layout.empty/  # Empty layout for auth/protocol pages
            │   ├── layout.topnav/ # Test IdP top navigation layout
            │   ├── page.access/   # Admin login
            │   ├── page.landing/  # Overview and temporary account management
            │   ├── page.saml/     # SAML route shell
            │   └── page.oidc/     # OIDC route shell
            ├── controller/        # Authentication and authorization guards
            ├── model/             # Project root Struct
            ├── portal/
            │   ├── season/        # Shared WIZ UI, session, auth, ORM
            │   ├── idpcore/       # Users, presets, debug payloads, audit logs
            │   ├── samlidp/       # SAML IdP models, UI, routes
            │   └── oidcidp/       # OIDC Provider models, UI, routes
            └── assets/            # Brand, fonts, and translations
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
cd project/main
python -m pytest tests
```

Covered areas include idpcore data handling, SAML registration/SSO/SLO/security checks, OIDC UI and protocol flow behavior, compact UI templates, rate limits, delete permissions, and mass-assignment protection.
