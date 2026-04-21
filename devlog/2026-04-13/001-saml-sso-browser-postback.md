# SAML SSO route 브라우저 POST back 수정

- **ID**: 001
- **날짜**: 2026-04-13
- **유형**: 버그 수정

## 작업 요약
`/api/saml/sso`가 AuthnRequest를 파싱한 뒤 JSON만 반환하던 문제를 수정했다. 이제 실제 브라우저 요청에서는 기본 테스트 계정으로 SAMLResponse를 생성하고, ACS URL로 auto-submit HTML form을 내려 서비스가 정상적으로 응답을 수신하도록 바꿨다.

또한 일부 SP가 `Issuer`를 문자열 `None`으로 보내는 경우를 위해, 등록된 SP 메타데이터의 ACS URL과 매칭하여 `sp_entity_id`를 보정하도록 process 계층을 강화했다. 이 값은 트랜잭션 저장에도 반영되어 이후 세션 추적과 SLO 흐름에서도 일관되게 사용된다.

## 변경 파일 목록

- `src/portal/samlidp/route/saml/controller.py` - 실제 SSO route가 JSON 대신 ACS auto-submit HTML을 응답하도록 수정, 기본 테스트 계정/프리셋 선택 로직 추가
- `src/portal/samlidp/model/struct/process.py` - `Issuer=None` 정규화, ACS URL 기반 SP entity ID 보정, 트랜잭션 업데이트 보강
- `tests/test_samlidp.py` - 실제 route가 HTML form POST를 생성하는지와 ACS 기반 entity 보정이 동작하는지 검증 추가