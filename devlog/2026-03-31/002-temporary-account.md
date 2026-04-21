# 24시간 임시 테스트 계정 생성 기능 구현

- **ID**: 002
- **날짜**: 2026-03-31
- **유형**: 기능 추가

## 작업 요약
idp_user 모델에 임시 계정 필드(is_temporary, expires, created_by, saml_attributes, oidc_claims)를 추가하고, User Struct에 임시 계정 전용 메서드(create_temporary, list_temporary, list_active, cleanup_expired)를 구현했다. idpcore route API에 임시 계정 CRUD 엔드포인트를 추가하고, Angular UI 컴포넌트(temp.account.form, temp.account.list)를 생성했다. 인증 로직에서 만료된 임시 계정을 자동 제외하도록 authenticate()를 수정했다.

## 변경 파일 목록

### Portal: idpcore - DB Model
- `src/portal/idpcore/model/db/idp_user.py` — is_temporary, expires, created_by, saml_attributes, oidc_claims 필드 추가

### Portal: idpcore - Struct
- `src/portal/idpcore/model/struct/user.py` — create_temporary, list_temporary, list_permanent, list_active, cleanup_expired 메서드 추가, authenticate() 만료 체크 추가

### Portal: idpcore - Route
- `src/portal/idpcore/route/core/controller.py` — users-temporary, user-create-temporary, user-update, user-delete, cleanup-expired 엔드포인트 추가

### Portal: idpcore - UI Components
- `src/portal/idpcore/app/temp.account.form/` — 임시 계정 생성/편집 폼 (아이디, 비밀번호, 표시이름, 이메일, Profile JSON, SAML Attributes JSON, OIDC Claims JSON)
- `src/portal/idpcore/app/temp.account.list/` — 임시 계정 목록, 만료 상태 표시, 편집/삭제/cleanup 액션
