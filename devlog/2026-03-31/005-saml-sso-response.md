# SAML SSO Response 생성 및 디버그

- **ID**: 005
- **날짜**: 2026-03-31
- **유형**: 기능 추가

## 작업 요약
SAML AuthnRequest 파싱, SAMLResponse XML 생성(서명 포함), 트랜잭션 기록 관리, SSO 디버그 UI를 구현했다. SP-initiated와 IdP-initiated 양쪽 흐름을 모두 지원하며, 속성 프리셋·사용자 선택·서명 옵션 등 모든 파라미터를 커스터마이즈할 수 있다.

## 변경 파일 목록

### DB Model
- `src/portal/samlidp/model/db/saml_transaction.py` — 신규: SAML 트랜잭션 테이블 (request_id, sp_entity_id, relay_state, binding, status, user_id 등)

### Struct
- `src/portal/samlidp/model/struct/process.py` — 신규: AuthnRequest 파싱(Base64/Deflate 자동감지), SAMLResponse XML 빌드(signxml RSA-SHA256 서명), 템플릿 변수 치환, 트랜잭션 CRUD, 디버그 파일 관리
- `src/portal/samlidp/model/struct.py` — 수정: process 프로퍼티 추가, _init_tables에 saml_transaction 추가

### Route
- `src/portal/samlidp/route/saml/controller.py` — 수정: sso-parse, sso-respond, sso, debug-raw, transactions, transaction 액션 추가

### Portal App
- `src/portal/samlidp/app/login.check/` — 신규: SSO 디버그 컴포넌트 (view.ts, view.pug, view.scss, api.py)
  - api.py: sp_list, user_list, preset_list, tx_list, parse_request, build_response
  - view.ts: SP-initiated(파싱→응답), IdP-initiated(SP선택→응답), 결과 표시
  - view.pug: 4모드 UI (input, idp-init, respond, result)

### Source App
- `src/app/page.saml/view.pug` — 수정: logincheck 탭에 `wiz-portal-samlidp-login-check` 컴포넌트 연동
