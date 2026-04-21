# SAML/OIDC 인증 제거 및 SP 24시간 자동 만료 구현

- **ID**: 008
- **날짜**: 2026-03-31
- **유형**: 기능 추가 / 버그 수정

## 작업 요약
SAML/OIDC 페이지에서 로그인 요구 사항을 완전히 제거하여 비로그인 사용자도 접근 가능하도록 수정.
SP 등록 시 24시간 자동 만료(expires) 기능을 추가하여, 목록 조회 시 만료된 SP를 자동 정리하고 UI에 남은 시간을 표시.

## 변경 파일 목록

### 인증 제거 (page.saml, page.oidc)
- `src/app/page.saml/view.ts` — `service.auth.loading && !service.auth.status` 리다이렉트 코드 제거
- `src/app/page.oidc/view.ts` — 동일하게 인증 리다이렉트 코드 제거

### DB 스키마 변경
- `src/portal/samlidp/model/db/saml_sp_registry.py` — `expires` (DateTimeField, null=True, index) 필드 추가

### 비즈니스 로직 (Struct)
- `src/portal/samlidp/model/struct/registry.py` — `cleanup_expired()` 메서드 추가, `list()` 호출 시 만료 SP 자동 정리, `register()` 시 expires = now + 24h 설정, `PROTECTED_SAML_SP_ENTITY_IDS` 보호 지원

### API 계층
- `src/portal/samlidp/app/sp.register/api.py` — `_serialize_row()` 헬퍼로 expires isoformat 변환 통합
- `src/portal/samlidp/route/saml/controller.py` — sp-list, sp-register, sp-get에 expires 직렬화 추가, `sp-cleanup-expired` 엔드포인트 신규

### 프론트엔드 (SP Register UI)
- `src/portal/samlidp/app/sp.register/view.ts` — `getTimeRemaining()`, `isExpiringSoon()` 메서드 추가
- `src/portal/samlidp/app/sp.register/view.pug` — SP 목록에 만료 배지, 등록 결과에 만료 알림 배너, 상세 페이지에 만료 카드 추가

### 테스트
- `tests/test_samlidp.py` — `test_register_sp`에 expires 필드 검증 추가, `test_sp_list_has_expires`, `test_sp_cleanup_expired_route` 2개 신규 테스트 추가 (59개 총 통과)
