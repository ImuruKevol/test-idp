# test-idp 기반 앱, 패키지, metadata, config 스켈레톤 생성

- **ID**: 002
- **날짜**: 2026-03-18
- **유형**: 기능 추가

## 작업 요약

test-idp의 첫 구현 작업으로 layout.topnav, page.landing, page.saml, page.oidc 앱 골격을 추가하고, idpcore, samlidp, oidcidp 포털 패키지 스켈레톤을 생성했다.

또한 이후 작업이 바로 이어질 수 있도록 metadata 디렉토리, SQLite 기반 database config 스켈레톤, protocol 기본 경로를 담는 idp config 파일을 추가했다.

## 변경 파일 목록

### Source App

- src/app/layout.topnav/app.json
- src/app/layout.topnav/view.ts
- src/app/layout.topnav/view.pug
- src/app/layout.topnav/view.scss
- src/app/page.landing/app.json
- src/app/page.landing/view.ts
- src/app/page.landing/view.pug
- src/app/page.landing/view.scss
- src/app/page.saml/app.json
- src/app/page.saml/view.ts
- src/app/page.saml/view.pug
- src/app/page.saml/view.scss
- src/app/page.oidc/app.json
- src/app/page.oidc/view.ts
- src/app/page.oidc/view.pug
- src/app/page.oidc/view.scss

### Portal Package Skeleton

- src/portal/idpcore/portal.json
- src/portal/idpcore/README.md
- src/portal/idpcore/model/struct.py
- src/portal/idpcore/model/README.md
- src/portal/idpcore/app/README.md
- src/portal/idpcore/route/README.md
- src/portal/samlidp/portal.json
- src/portal/samlidp/README.md
- src/portal/samlidp/model/struct.py
- src/portal/samlidp/model/README.md
- src/portal/samlidp/app/README.md
- src/portal/samlidp/route/README.md
- src/portal/oidcidp/portal.json
- src/portal/oidcidp/README.md
- src/portal/oidcidp/model/struct.py
- src/portal/oidcidp/model/README.md
- src/portal/oidcidp/app/README.md
- src/portal/oidcidp/route/README.md

### Config and Storage Scaffold

- config/idp.py
- config/database.py
- metadata/README.md
- metadata/saml/README.md
- metadata/oidc/README.md
- metadata/debug/README.md
- data/README.md