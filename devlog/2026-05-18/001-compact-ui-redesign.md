# Test IdP compact UI redesign

## 요청

- 리뷰 ID: `xnfihbfxsxagxqmykckjojfemmcjoifw`
- 제목: 디자인 변경
- 원문 요청: "지금은 너무 대시보드같은 느낌의 이도저도 아닌 디자인이야. 디자인을 전체적으로 싹 갈아엎어서 컴팩트하고 깔끔한 디자인으로 갈아엎어줘. 기능은 유지가 되어야 해."

## 변경 내용

- 공통 top navigation을 얇은 흰색 헤더와 compact segmented navigation으로 재구성했다.
- 랜딩 화면의 큰 그라데이션 hero와 카드형 현황판을 제거하고, 간결한 제품 소개, 프로토콜 진입 영역, admin 상태 strip, 기본 계정/임시 계정 영역으로 재배치했다.
- SAML/OIDC 페이지의 상단 hero와 탭을 작은 작업 헤더와 compact tab으로 정리했다.
- 임시 테스트 계정 목록을 큰 안내 카드 중심에서 toolbar + 제한 정보 strip + dense table 형태로 변경하고 기존 생성/편집/삭제/연장/영구 전환 액션을 유지했다.
- 로그인 화면을 동일한 compact visual language로 맞추고 로그인 진행 상태를 버튼에 반영했다.
- 템플릿 구조와 보존 액션을 확인하는 pytest 테스트를 추가했다.

## 변경 파일

- `src/app/layout.topnav/view.pug`
- `src/app/layout.topnav/view.ts`
- `src/app/page.access/view.pug`
- `src/app/page.access/view.ts`
- `src/app/page.landing/view.pug`
- `src/app/page.oidc/view.pug`
- `src/app/page.oidc/view.ts`
- `src/app/page.saml/view.pug`
- `src/app/page.saml/view.ts`
- `src/portal/idpcore/app/temp.account.list/view.pug`
- `tests/test_compact_design_templates.py`
- `devlog.md`
- `devlog/2026-05-18/001-compact-ui-redesign.md`

## 검증

- `/root/miniconda3/envs/test-idp/bin/python -m pytest tests/test_compact_design_templates.py --tb=short -q`
  - 결과: 4 passed
- `git diff --check`
  - 결과: 문제 없음
- `/root/miniconda3/envs/test-idp/bin/wiz project build --project=main`
  - 결과: EsBuild complete, project build completed

## 참고

- WIZ MCP의 현재 workspace status는 `/opt/app/project/main`을 가리켰지만 해당 경로가 없어 project info/build를 수행하지 못했다. 로컬 WIZ CLI로 `/root/workspace/test-idp/project/main` 프로젝트 빌드를 검증했다.
- `src/angular/index.pug`에는 ReviewOps SDK 삽입 관련 기존 변경이 워크트리에 남아 있었고, 본 작업에서는 의도적으로 수정하지 않았다.
