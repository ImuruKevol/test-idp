# Test IdP

Test IdP는 SAML Service Provider(SP)와 OpenID Connect Relying Party(RP)를 검증하기 위한 테스트용 Identity Provider입니다. 외부 상용 IdP 없이 SP/RP 등록, 메타데이터/Discovery 배포, SSO, Token, UserInfo, Logout, Raw XML/JWT 디버그 흐름을 한 프로젝트 안에서 확인할 수 있습니다.

Live URL: <https://debug-idp.nanoha.kr/>

Framework: [WIZ Framework](https://github.com/season-framework/wiz) (`season==2.5.1`)

## 설치 및 실행

Test IdP 저장소는 WIZ 워크스페이스 전체가 아니라 `project/main`에 들어가는 애플리케이션 프로젝트입니다. 아래 명령은 Linux/macOS 셸 기준이며, WIZ 공식 구조와 CLI 흐름에 맞춰 새 워크스페이스를 구성합니다.

### 1. 준비 사항

- Git
- [Miniconda 또는 Anaconda](https://docs.conda.io/projects/conda/en/latest/user-guide/install/index.html) (Miniconda 권장)
- Node.js 18.19.1 이상과 npm (Node.js 20 LTS 권장)
- Ubuntu/Debian에서는 SAML 라이브러리 빌드용 시스템 패키지 설치

```bash
sudo apt update
sudo apt install -y curl git openssl xmlsec1
sudo apt install -y build-essential pkg-config libxml2-dev libxmlsec1-dev libxmlsec1-openssl

apt install nodejs npm
npm i -g n
n stable
apt purge nodejs npm
# nodejs, npm 설치 후 터미널 종료 및 재접속 필수

node --version
npm --version
```

### 2. WIZ 설치 및 워크스페이스 생성

WIZ와 프로젝트 의존성이 시스템 Python과 섞이지 않도록 전용 Conda 환경을 사용합니다. 이미 Conda가 설치되어 있다면 Miniconda 설치 부분은 건너뜁니다.

```bash
# Miniconda 설치(Linux x86_64)
curl -fsSLo /tmp/miniconda.sh https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
bash /tmp/miniconda.sh -b -p "$HOME/miniconda3"
rm -f /tmp/miniconda.sh

# 쉘에 conda init
$HOME/miniconda3/bin/conda init

# conda terms accept
conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/main
conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/r

# 프로젝트 전용 환경 생성 및 활성화
conda create -y -n test-idp python=3.14
conda activate test-idp
pip install season==2.5.1

python --version
wiz --version

wiz create workspace
cd workspace
wiz project create --project=main --uri=https://github.com/ImuruKevol/test-idp.git
pip install -r project/main/requirements.txt
```

### 3. 로컬 설정

Git에서 제외되는 SQLite 설정을 샘플로부터 생성합니다. DB 파일과 SAML/OIDC 키는 첫 실행 시 각각 `data/`, `metadata/` 아래에 자동 생성됩니다.

```bash
cp project/main/config-sample/database.py project/main/config/database.py
```

관리자 비밀번호는 다음 두 방법 중 하나로 설정합니다.

```bash
# 방법 1: 최초 실행 전에 환경변수로 지정
export TEST_IDP_ADMIN_PASSWORD='replace-with-a-strong-password'

# 방법 2: 대화형 변경 스크립트 실행
python project/main/scripts/change_admin_password.py
```

변경 스크립트는 새 설치처럼 DB와 admin 계정이 아직 없으면 WIZ 모델을 먼저 로드해 자동 초기화합니다. 이때 `project/main/config/database.py`와 Python 의존성 설치가 완료되어 있어야 합니다. 환경변수와 변경 스크립트를 모두 사용하지 않으면 초기 admin 비밀번호가 임의 생성되어 확인할 수 없습니다.

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
