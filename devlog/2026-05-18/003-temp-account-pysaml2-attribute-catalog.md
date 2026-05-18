# Temporary account pysaml2 attribute catalog

## 요청

- 리뷰 ID: `fnmasqhpoiblifzupexkbbsscqzdwylr`
- 제목: overview 임시 계정 편집 기능 개선
- 원문 요청: "그냥 OID 속성 선택 기능 자체를 없애버리고 현재 목록에 있는 속성들을 임시 테스트 계정 생성 시 기본적으로 전부 만들어서 SAML, OIDC 속성에 전부 적용하도록 해줘. 대신 OID 속성 선택 부분에는 pysaml2 패키지에서 기본적으로 지원하는 속성 목록을 가져와서 사용자가 어떤 속성이 있는지 바로 확인하고 추가할 수 있는 기능은 필요해. 각 속성들이 현재 선택된 계정에 추가가 되어있는지 SAML, OIDC 각각 뱃지 식으로 표현은 필요하고."

## 변경 내용

- 임시 테스트 계정 생성 시 test-idp 표준 SAML Attribute 전체와 대응 OIDC Claim 전체를 기본값으로 병합하도록 `idpcore` 생성 흐름을 변경했다.
- `saml2.attributemaps`의 기본 pysaml2 attribute map을 읽어 지원 속성 카탈로그를 생성하는 API를 추가했다.
- pysaml2 attribute map의 SAML Name/NameFormat을 보존하도록 SAML attribute 정규화와 SAML Response 생성의 `NameFormat` 처리를 확장했다.
- 임시 계정 편집 폼의 오른쪽 패널을 pysaml2 지원 속성 목록으로 교체하고, 각 항목에 현재 JSON editor 기준 `SAML 있음/없음`, `OIDC 있음/없음` 배지를 표시하도록 변경했다.
- 속성 추가 버튼은 선택한 pysaml2 속성을 SAML Attributes와 OIDC Claims editor에 함께 추가한다.
- 관련 README와 pytest 검증을 갱신했다.

## 변경 파일

- `src/portal/idpcore/README.md`
- `src/portal/idpcore/app/temp.account.form/view.ts`
- `src/portal/idpcore/app/temp.account.form/view.pug`
- `src/portal/idpcore/model/struct.py`
- `src/portal/idpcore/model/struct/user.py`
- `src/portal/idpcore/route/core/controller.py`
- `src/portal/samlidp/model/struct/process.py`
- `tests/test_idpcore.py`
- `tests/test_temp_account_form_oid_selector.py`
- `devlog.md`
- `devlog/2026-05-18/003-temp-account-pysaml2-attribute-catalog.md`

## 검증

- `/root/miniconda3/envs/test-idp/bin/python -m py_compile src/portal/idpcore/model/struct.py src/portal/idpcore/model/struct/user.py src/portal/idpcore/route/core/controller.py src/portal/samlidp/model/struct/process.py`
  - 결과: 통과
- `/root/miniconda3/envs/test-idp/bin/python -m pytest tests/test_temp_account_form_oid_selector.py --tb=short -q`
  - 결과: 4 passed
- `/root/miniconda3/envs/test-idp/bin/python -m pytest tests/test_temp_account_form_oid_selector.py tests/test_compact_design_templates.py --tb=short -q`
  - 결과: 8 passed
- `/root/miniconda3/envs/test-idp/bin/python -m pytest tests/test_idpcore.py --tb=short -q`
  - 결과: 26 passed
- `git diff --check`
  - 결과: 문제 없음
- `/root/miniconda3/envs/test-idp/bin/wiz project build --project=main`
  - 결과: EsBuild complete, project build completed

## 참고

- WIZ MCP의 프로젝트 경로는 `/opt/app/project/main`을 가리키지만 해당 환경에서 `wiz` 명령을 찾지 못해, 로컬 WIZ CLI로 빌드를 검증했다.
- 기존 2026-05-18 002 작업의 OID 선택 동작은 이번 요청에 따라 pysaml2 카탈로그 기반 패널로 대체되었다.
