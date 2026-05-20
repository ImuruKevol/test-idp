# Quick Create 프리셋 선택과 eduPerson 속성 payload 추가

- 날짜: 2026-05-20
- 작업 ID: 001
- 리뷰 ID: ihjnwhrlppqnhapsihuszhvjyrzfaumx

## 사용자 원 요청

작업 시작해줘. Quick Create 시 기본 속성만 넣고 있어 일반, 연구소, 기관, 학교 등 3~4가지 프리셋을 제공하고, 연구소/기관/학교에서 많이 쓰는 eduPersonPrincipalName, eduPersonEntitlement 등 eduPerson 계열 속성을 Quick Create에서 선택할 수 있게 해달라는 요청.

## 변경 파일

- `src/portal/idpcore/app/temp.account.list/view.ts`
- `src/portal/idpcore/app/temp.account.list/view.pug`
- `tests/test_compact_design_templates.py`
- `devlog.md`
- `devlog/2026-05-20/001-quick-create-presets.md`

## 작업 내용

- Quick Create에 일반, 연구소, 학교, 기관 4개 프리셋 선택 상태와 UI를 추가했다.
- 연구소/학교/기관 프리셋 생성 시 eduPersonPrincipalName, eduPersonAffiliation, eduPersonScopedAffiliation, eduPersonEntitlement SAML OID와 OIDC claim payload를 포함하도록 구성했다.
- 생성 완료 안내에 사용한 프리셋명을 표시하도록 했다.
- 템플릿 테스트에 Quick Create 프리셋과 eduPerson 속성 검증을 추가했다.

## 확인 결과

- `/root/miniconda3/envs/test-idp/bin/python -m pytest tests/test_compact_design_templates.py tests/test_idpcore.py::TestIdpcoreUserAPI::test_user_create_temporary_applies_all_default_attribute_catalog` 실행: 6 passed
- `/root/miniconda3/envs/test-idp/bin/wiz project build --project=main` 실행: 성공
