# GitHub 공개 전 민감 정보 및 불필요 산출물 정리

## 사용자 원 요청

github에 올릴건데, 쓸데없는 내용이나 불필요한 데이터, 민감한 정보 등이 포함되어있지 않은지 확인해줘.

## 변경 파일

- `.gitignore`
  - live 화면 캡처 산출물 재추가 방지를 위해 `docs/screenshots/` 무시 규칙 추가.
- `README.md`
  - 화면 캡처 섹션 제거.
  - AI 생성 표기 제거.
  - 공개 문서의 고정 admin 비밀번호 문구를 제거하고 `TEST_IDP_ADMIN_PASSWORD` 기반 설정 안내로 변경.
- `docs/test-idp-design.md`
  - 설계 문서의 샘플 계정 비밀번호 예시 제거.
- `src/portal/idpcore/README.md`
  - 관리자 계정 문서에서 고정 비밀번호를 제거하고 환경 변수 기반 초기 설정 안내 추가.
- `src/portal/idpcore/model/struct/user.py`
  - admin seed 비밀번호를 고정값 대신 `TEST_IDP_ADMIN_PASSWORD` 또는 임의 생성값으로 설정.
- `src/portal/idpcore/app/temp.account.list/view.ts`
  - Quick Create 임시 계정의 고정 비밀번호를 요청마다 생성되는 값으로 변경.
- `src/portal/oidcidp/app/authorize.check/view.ts`
  - OIDC quick create 임시 계정의 고정 비밀번호를 요청마다 생성되는 값으로 변경.
- `docs/screenshots/`
  - live 데이터와 임시 계정 정보가 포함된 캡처 파일 삭제.
- `devlog.md`
- `devlog/2026-05-20/004-github-publish-sanitization.md`

## 확인 결과

- 공개 대상 파일 목록에서 `data/`, `metadata/`, `config/`, `build/`, `bundle/`, `node_modules/`, `docs/screenshots/`, `.db`, `.pem`, `.png` 파일이 포함되지 않음을 확인.
- README와 주요 문서/소스에서 고정 admin 비밀번호, 고정 테스트 비밀번호, AI 생성 표기, private key 본문 패턴이 남아있지 않음을 확인.
- 잔여 검색 결과는 테스트 fixture의 더미 비밀번호와 private key 파일명을 생성/참조하는 코드 경로뿐이며, 실제 키 또는 운영 데이터는 포함되지 않음.
- `git diff --check` 통과.
- `/root/miniconda3/envs/test-idp/bin/python -m pytest tests/test_idpcore.py tests/test_oidcidp_ui.py tests/test_compact_design_templates.py` 실행 결과: 42 passed.
