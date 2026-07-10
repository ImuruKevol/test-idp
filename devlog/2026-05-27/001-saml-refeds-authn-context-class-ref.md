# 001. SAML REFEDS AuthnContextClassRef 입력 및 응답 반영 추가

## 사용자 원 요청

SAML SP를 연동하여 테스트할 때 REFEDS AuthnContextClassRef를 강제 포함하는 입력 경로가 없어 확인할 수 없다. OIDC의 `acr_values`처럼 SAML 테스트에서도 별도 설정 입력 경로가 필요하다.

## 변경 파일

- `src/portal/samlidp/model/struct/process.py`
- `src/portal/samlidp/route/saml/controller.py`
- `src/portal/samlidp/app/login.check/api.py`
- `src/portal/samlidp/app/login.check/view.ts`
- `src/portal/samlidp/app/login.check/view.pug`
- `src/portal/samlidp/README.md`
- `tests/test_samlidp.py`
- `devlog.md`
- `devlog/2026-05-27/001-saml-refeds-authn-context-class-ref.md`

## 작업 내용

- SAMLResponse 생성 시 `authn_context_class_ref` 입력값을 `AuthnContextClassRef` XML 요소에 반영하도록 변경했다.
- 입력값이 없으면 AuthnRequest의 `RequestedAuthnContext` 첫 번째 값을 사용하고, 요청값도 없으면 기존 `PasswordProtectedTransport` 값을 유지하도록 했다.
- Login Check 화면에 AuthnContextClassRef 입력과 REFEDS MFA/SFA 빠른 선택 버튼을 추가했다.
- `/api/saml/sso`, `/api/saml/sso-respond`, Login Check `build_response` API에서 `authn_context_class_ref`를 받을 수 있게 했다.
- `/api/saml/sso` 프롬프트 흐름에서 AuthnContextClassRef hidden state가 유지되도록 했다.

## 검증 결과

- `/root/miniconda3/envs/test-idp/bin/python -m py_compile src/portal/samlidp/model/struct/process.py src/portal/samlidp/route/saml/controller.py src/portal/samlidp/app/login.check/api.py tests/test_samlidp.py` 통과
- `/root/miniconda3/envs/test-idp/bin/wiz project build --project=main` 통과
- `systemctl restart wiz.test-idp` 실행
- `./tests/run_tests.sh test_samlidp.py -k "refeds or prompt_preserves or build_response or parse_authn_request"`: 6 passed
- `./tests/run_tests.sh test_samlidp.py`: 32 passed
