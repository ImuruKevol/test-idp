# OIDC RP 수정 기능과 authorize admin 숨김 처리

- **ID**: 002
- **날짜**: 2026-04-21
- **유형**: 기능 추가

## 작업 요약
OIDC authorize 로그인 프롬프트의 빠른 계정 선택 목록에서 admin 계정이 노출되지 않도록 필터링하고, selected_user_id를 직접 보내도 admin 즉시 선택이 되지 않게 막았다.

또한 OIDC RP Registry 화면에서 등록된 RP를 수정할 수 있도록 registry update 로직, app API, 편집 UI를 추가했다. 기존 등록 폼을 재사용해 redirect URI, logout redirect URI, grant/response/scope/claims 정책, auth method, public client, JWKS, 운영 메모를 수정할 수 있고, public/confidential 전환에 따라 client_secret도 정리된다.

## 변경 파일 목록
- `src/portal/oidcidp/route/oidc/controller.py`: admin quick-pick 제외 및 direct selected_user_id 차단
- `src/portal/oidcidp/model/struct/registry.py`: RP payload 정규화 공통화와 update 메서드 추가
- `src/portal/oidcidp/app/rp.register/api.py`: update API 추가 및 audit 로그 기록
- `src/portal/oidcidp/app/rp.register/view.ts`: edit 모드, payload 공통화, update 처리 추가
- `src/portal/oidcidp/app/rp.register/view.html`: 수정 버튼과 edit 폼/상세 secret 표시 추가
- `tests/test_oidcidp_ui.py`: RP update 회귀 테스트와 admin 숨김 검증 추가

## 검증
- WIZ project build (`clean: false`)
- `pytest tests/test_oidcidp_ui.py -q`