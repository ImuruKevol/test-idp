# OIDC Provider 메타데이터와 endpoint 복사 버튼 확장

- **ID**: 011
- **날짜**: 2026-04-14
- **유형**: UI 개선

## 작업 요약
OIDC Provider 화면에서 issuer, discovery endpoint, JWKS URI, 각 endpoint contract 값, 최근 RP의 client_id를 개별적으로 복사할 수 있도록 copy 버튼을 추가했다.
기존 복사 완료 피드백 패턴을 그대로 재사용해 각 항목별로 `복사됨` 상태가 보이도록 정리했다.

## 변경 파일 목록
- `src/portal/oidcidp/app/provider.publish/view.html`: issuer/discovery/jwks uri/authorization/token/userinfo/end session/client_id 복사 버튼 추가

## 검증
- WIZ project build (`clean: false`) 완료