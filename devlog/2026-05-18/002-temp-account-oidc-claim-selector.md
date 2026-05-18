# Overview temporary account OIDC claim selector

## 요청

- 리뷰 ID: `fnmasqhpoiblifzupexkbbsscqzdwylr`
- 제목: overview 임시 계정 편집 기능 개선
- 원문 요청: "현재 Overview 화면의 임시 계정 편집에서는 SAML Attributes는 클릭해서 바로 적용할 수 있음. 근데 OIDC Claims에는 적용이 되지 않아 불편함. OID 속성 선택에서 목록을 누르면 OIDC Claims에도 적용이 되도록 기능 추가 필요. 그리고 임시 계정 편집 부분을 2단으로 나누어서 왼쪽에는 현재 label, input들, 오른쪽에는 OID 속성 선택 부분을 위치시켜줘."

## 변경 내용

- 임시 계정 폼의 OID 속성 선택 버튼 클릭 시 SAML Attributes JSON과 OIDC Claims JSON을 함께 갱신하도록 변경했다.
- SAML friendly name/alias를 OIDC claim key로 매핑했다. 예: `uid` → `preferred_username`, `mail` → `email`, `displayName` → `name`, `memberOf` → `groups`.
- 임시 계정 생성/편집 폼을 데스크톱에서 2단 그리드로 배치하고, 왼쪽에는 기존 입력 필드와 JSON editor, 오른쪽에는 OID 속성 선택 패널을 배치했다.
- OID 선택 동작과 2단 레이아웃을 확인하는 정적 pytest를 추가했다.

## 변경 파일

- `src/portal/idpcore/app/temp.account.form/view.ts`
- `src/portal/idpcore/app/temp.account.form/view.pug`
- `tests/test_temp_account_form_oid_selector.py`
- `devlog.md`
- `devlog/2026-05-18/002-temp-account-oidc-claim-selector.md`

## 검증

- `/root/miniconda3/envs/test-idp/bin/python -m pytest tests/test_temp_account_form_oid_selector.py --tb=short -q`
  - 결과: 3 passed
- `/root/miniconda3/envs/test-idp/bin/python -m pytest tests/test_temp_account_form_oid_selector.py tests/test_compact_design_templates.py --tb=short -q`
  - 결과: 7 passed
- `git diff --check`
  - 결과: 문제 없음
- `wiz_project_build` MCP
  - 결과: 현재 MCP 환경에서 `wiz` 명령을 찾지 못해 실패
- `/root/miniconda3/envs/test-idp/bin/wiz project build --project=main`
  - 결과: EsBuild complete, project build completed
