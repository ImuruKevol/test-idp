# OIDC authorize quick account top-navigation 전환

- **ID**: 003
- **날짜**: 2026-04-21
- **유형**: 버그 수정

## 작업 요약
OIDC authorize 프롬프트에서 테스트 계정 카드를 클릭해도 RP로 넘어가지 않고 authorize 화면에 남는 문제를 줄이기 위해, quick account selection 동작을 POST form submit에서 top-level GET navigation으로 변경했다.

계정 카드는 이제 `selected_user_id`를 포함한 authorize URL 링크로 바로 이동하고 `target="_top"`으로 최상위 브라우저 컨텍스트를 사용한다. 이 방식으로 iframe/popup 환경에서도 브라우저가 authorize 화면에 머무르지 않고 실제 redirect 체인을 더 안정적으로 따라가도록 했다.

## 변경 파일 목록
- `src/portal/oidcidp/route/oidc/controller.py`: quick account card를 authorize 링크로 생성하고 top-level navigation 적용
- `tests/test_oidcidp_ui.py`: quick account selection 회귀 테스트를 GET 기반으로 조정

## 검증
- WIZ project build (`clean: false`)
- `pytest tests/test_oidcidp_ui.py -q`