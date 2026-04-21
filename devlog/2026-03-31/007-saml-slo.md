# SAML 로그아웃과 세션 정리 구현

- **ID**: 007
- **날짜**: 2026-03-31
- **유형**: 기능 추가

## 작업 요약
SAML Single Logout(SLO) 기능을 구현했다. SP-initiated LogoutRequest 수신/파싱, SessionIndex/NameID 기반 세션 매칭, LogoutResponse 생성(서명 포함), IdP-initiated LogoutRequest 생성, 세션 무효화 기능을 구현하고, Logout Check UI 컴포넌트를 통해 디버그할 수 있도록 했다.

## 변경 파일 목록

### 신규
- `src/portal/samlidp/app/logout.check/` — Logout Check 포탈 컴포넌트 (api.py, view.ts, view.pug, view.scss, app.json)
- `tests/test_saml_slo.py` — SAML SLO 통합 테스트 19개

### 수정
- `src/portal/samlidp/model/struct/process.py` — SLO 메서드 추가 (parse_logout_request, build_logout_response, build_logout_request, _match_sessions, invalidate_sessions, list_active_sessions)
- `src/portal/samlidp/route/saml/controller.py` — SLO 엔드포인트 추가 (slo, slo-parse, slo-respond, slo-initiate, slo-sessions, slo-invalidate)
- `src/app/page.saml/view.pug` — logoutcheck 탭에 wiz-portal-samlidp-logout-check 컴포넌트 연결
