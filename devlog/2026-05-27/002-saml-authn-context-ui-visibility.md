# 002. SAML 로그인 화면 AuthnContextClassRef 설정 노출 개선

## 사용자 원 요청

`/saml/logincheck` 화면에서 관련 내용을 찾을 수 없고, SAML 로그인 과정 중 로그인할 사용자를 선택하는 화면에서 AuthnContextClassRef를 직접 입력하거나 선택할 수 있도록 해달라는 요청.

## 변경 파일

- `src/portal/samlidp/app/login.check/view.pug`
- `src/portal/samlidp/route/saml/controller.py`
- `src/portal/samlidp/README.md`
- `tests/test_samlidp.py`
- `devlog.md`
- `devlog/2026-05-27/002-saml-authn-context-ui-visibility.md`

## 작업 내용

- `/saml/logincheck`의 SP Initiated 첫 화면과 IdP Initiated 화면에 `SAMLResponse AuthnContextClassRef` 입력 영역을 노출했다.
- REFEDS MFA/SFA 및 기본 PasswordProtectedTransport 빠른 선택 버튼을 같은 화면에 배치했다.
- 실제 `/api/saml/sso` 계정 선택 화면에 AuthnContextClassRef 입력과 REFEDS 선택 버튼을 추가했다.
- 빠른 테스트 계정 선택 폼과 관리자 로그인 폼 모두에서 입력한 AuthnContextClassRef가 SAMLResponse 생성까지 전달되도록 폼 구조를 조정했다.
- 화면 노출 및 계정 선택 흐름 반영을 검증하는 테스트를 추가했다.

## 검증 결과

- `/root/miniconda3/envs/test-idp/bin/python -m py_compile src/portal/samlidp/route/saml/controller.py tests/test_samlidp.py` 통과
- `/root/miniconda3/envs/test-idp/bin/wiz project build --project=main` 통과
- `systemctl restart wiz.test-idp` 실행
- `./tests/run_tests.sh test_samlidp.py -k "authn_context or prompt_allows or prompt_preserves or logincheck_template"`: 6 passed
- `./tests/run_tests.sh test_samlidp.py`: 34 passed
