# SAML SSO 로그인 프롬프트 추가

- **ID**: 002
- **날짜**: 2026-04-13
- **유형**: 기능 추가

## 작업 요약
서비스가 `/api/saml/sso`로 AuthnRequest를 보냈을 때 세션이 없는 경우, 더 이상 임의 사용자로 바로 SAMLResponse를 생성하지 않도록 수정했다. 대신 같은 route에서 계정 선택 카드와 ID/PW 로그인 폼을 함께 렌더링해 사용자가 로그인 주체를 직접 선택할 수 있게 했다.

프롬프트 화면은 초기 AuthnRequest에서 파싱한 `transaction_id`, `sp_entity_id`, `acs_url`, `request_id`, `relay_state`를 hidden input으로 유지하고, 사용자가 계정을 선택하거나 자격 증명을 입력하면 같은 route로 재제출하여 SAMLResponse를 생성한다. 빠른 테스트를 위해 활성 사용자 목록 기반 one-click 로그인도 제공한다.

## 변경 파일 목록

- `src/portal/samlidp/route/saml/controller.py` - SSO route에 미인증 로그인/계정선택 프롬프트와 재개 처리 로직 추가
- `tests/test_samlidp.py` - 미인증 프롬프트 렌더링과 프롬프트 기반 로그인 후 SAMLResponse 생성 회귀 테스트 추가