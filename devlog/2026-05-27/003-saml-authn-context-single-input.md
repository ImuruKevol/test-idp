# 003. SAML AuthnContextClassRef 입력 영역 중복 제거

## 사용자 원 요청

AuthnContextClassRef 입력 영역은 중복으로 있을 필요 없이 한 번만 있으면 된다는 요청.

## 변경 파일

- `src/portal/samlidp/app/login.check/view.pug`
- `src/portal/samlidp/route/saml/controller.py`
- `tests/test_samlidp.py`
- `devlog.md`
- `devlog/2026-05-27/003-saml-authn-context-single-input.md`

## 작업 내용

- `/saml/logincheck`의 AuthnContextClassRef 입력을 공통 설정 블록 하나로 통합했다.
- 실제 SAML 로그인 계정 선택 화면의 빠른 계정 선택과 관리자 로그인 영역이 하나의 AuthnContextClassRef 입력값을 공유하도록 폼을 하나로 정리했다.
- 중복 입력 필드가 하나만 렌더링되는지 확인하는 테스트 조건을 추가했다.

## 검증 결과

- `/root/miniconda3/envs/test-idp/bin/python -m py_compile src/portal/samlidp/route/saml/controller.py tests/test_samlidp.py` 통과
- `/root/miniconda3/envs/test-idp/bin/wiz project build --project=main` 통과
- `systemctl restart wiz.test-idp` 실행
- `./tests/run_tests.sh test_samlidp.py -k "prompt_allows or prompt_preserves or logincheck_template"`: 3 passed
- `./tests/run_tests.sh test_samlidp.py`: 34 passed
