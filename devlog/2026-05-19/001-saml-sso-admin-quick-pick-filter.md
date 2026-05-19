# SAML SSO 빠른 계정 선택에서 admin 계정 제외

## 사용자 요청

작업 진행해줘.

리뷰 ID `qgyofqnktmotojjhnsbtpdukxneayivy`: `/api/saml/sso` 화면에서 빠른 테스트 계정 선택에 admin 계정도 같이 나오고 있음. 보이면 안됨.

## 변경 내용

- `/api/saml/sso` 프롬프트의 빠른 테스트 계정 선택 카드에서 `role=admin` 또는 `username=admin` 사용자를 제외했다.
- `selected_user_id`를 직접 전달해 admin 계정을 빠른 선택하려는 요청도 차단하도록 검증을 추가했다.
- admin 이메일이 프롬프트 화면에 노출되지 않도록 로그인 입력 placeholder를 `admin`으로 축소했다.
- SAML SSO 프롬프트의 admin 숨김 및 직접 선택 차단 회귀 테스트를 추가했다.

## 변경 파일

- `src/portal/samlidp/route/saml/controller.py`
- `tests/test_samlidp.py`
- `devlog.md`
- `devlog/2026-05-19/001-saml-sso-admin-quick-pick-filter.md`

## 검증 결과

- `/root/miniconda3/envs/test-idp/bin/wiz project build --project=main` 통과
- `/root/miniconda3/envs/test-idp/bin/wiz service restart test-idp` 실행
- `/root/miniconda3/envs/test-idp/bin/python -m pytest tests/test_samlidp.py -k "sso_endpoint_prompts_for_login_when_unauthenticated or sso_endpoint_rejects_admin_quick_selection"` → 2 passed
- `/root/miniconda3/envs/test-idp/bin/python -m pytest tests/test_samlidp.py` → 28 passed
