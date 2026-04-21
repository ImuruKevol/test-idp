# 강제 seed의 admin 비밀번호 초기화 문제 수정 및 초기 비밀번호 안내 제거

- **ID**: 008
- **날짜**: 2026-04-14
- **유형**: 버그 수정

## 작업 요약
강제 seed 호출 시 기존 admin 계정이 있어도 샘플 비밀번호로 다시 덮어쓰던 문제를 수정했다.
seed 및 seed-force 라우트를 관리자 전용으로 제한하고, 로그인 화면과 SAML 로그인 프롬프트의 하드코딩된 초기 비밀번호 안내 문구를 제거했으며, 테스트가 실제 admin 비밀번호를 보존하도록 복구 fixture를 추가했다.

## 변경 파일 목록
- `src/portal/idpcore/model/struct/user.py`: force seed 시 기존 admin 비밀번호 해시를 보존하도록 수정
- `src/portal/idpcore/route/core/controller.py`: seed / seed-force를 admin 전용으로 제한
- `src/app/page.access/view.pug`: 로그인 화면의 초기 비밀번호 안내 문구 제거
- `src/portal/samlidp/route/saml/controller.py`: SAML 로그인 프롬프트의 초기 비밀번호 문구를 일반 안내로 변경
- `tests/conftest.py`: 테스트 전후 admin 비밀번호를 백업/복구하는 fixture 추가 및 autouse seed를 non-force로 변경
- `tests/test_idpcore.py`: seed 권한 제한 및 force seed 비밀번호 유지 회귀 테스트 추가
- `tests/test_samlidp.py`: 프롬프트 로그인 테스트가 실비밀번호를 복구 가능한 fixture를 사용하도록 수정
- `src/portal/idpcore/README.md`: seed 라우트 정책과 force seed 비밀번호 유지 동작 문서화

## 검증
- `pytest tests/test_idpcore.py tests/test_samlidp.py tests/test_security.py` → 75 passed
- WIZ project build (`clean: false`) 완료