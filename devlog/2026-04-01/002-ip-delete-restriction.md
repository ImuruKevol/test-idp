# IP 기반 삭제 제한 및 보안 제한 UI 표시

- **ID**: 002
- **날짜**: 2026-04-01
- **유형**: 기능 추가

## 작업 요약
SP 및 임시 계정 삭제 시 admin 로그인 또는 등록한 IP에서만 삭제할 수 있도록 IP 기반 접근 제어를 구현했다.
또한 SP 등록/임시 계정 생성 화면에 보안 제한 안내 배너(SP 50개, XML 256KB, 등록 횟수 제한, 삭제 권한 안내)를 추가했다.

## 변경 파일 목록

### DB 스키마
- `src/portal/samlidp/model/db/saml_sp_registry.py` — `created_by_ip` 컬럼 추가
- `src/portal/idpcore/model/db/idp_user.py` — `created_by_ip` 컬럼 추가

### DB 마이그레이션
- `src/portal/idpcore/model/struct.py` — `_migrate_columns()` 추가 (ALTER TABLE로 기존 DB에 created_by_ip 컬럼 추가)
- `src/portal/samlidp/model/struct.py` — `_migrate_columns()` 추가 (ALTER TABLE로 기존 DB에 created_by_ip 컬럼 추가)

### 백엔드 모델
- `src/portal/samlidp/model/struct/registry.py` — `register()`에 `created_by_ip` 파라미터 추가, `can_delete()` 메서드 추가
- `src/portal/idpcore/model/struct/user.py` — `create_temporary()`에 `created_by_ip` 파라미터 추가, `can_delete()` 메서드 추가, `create()`에 `created_by_ip` 필드 처리 추가

### 백엔드 라우트
- `src/portal/samlidp/route/saml/controller.py` — sp-list에 `can_delete` 플래그 추가, sp-register에 IP 전달, sp-get에 `can_delete` 추가, sp-delete에 IP/admin 권한 검증 (403 반환), `_is_admin()` 및 `_serialize_sp()` 헬퍼 추가
- `src/portal/idpcore/route/core/controller.py` — users-temporary에 `can_delete` 플래그 추가, user-create-temporary에 IP 전달, user-delete에 IP/admin 권한 검증 (403 반환), `_is_admin()` 및 `_add_can_delete()` 헬퍼 추가

### 앱 API
- `src/portal/samlidp/app/sp.register/api.py` — list에 `can_delete` 추가, register에 IP 전달, get에 `can_delete` 추가, delete에 IP/admin 권한 검증 (403 반환)

### 프론트엔드 UI
- `src/portal/samlidp/app/sp.register/view.pug` — 보안 제한 안내 배너 추가, 삭제 버튼 조건부 표시 (`can_delete`), 삭제 불가 시 잠금 아이콘, 상세 뷰에 등록 IP 표시
- `src/portal/samlidp/app/sp.register/view.ts` — 삭제 시 403 에러 처리 추가
- `src/portal/idpcore/app/temp.account.list/view.pug` — 보안 제한 안내 배너 추가, 삭제 버튼 조건부 표시 (`can_delete`), 삭제 불가 시 잠금 아이콘
- `src/portal/idpcore/app/temp.account.list/view.ts` — 삭제 시 403 에러 처리 추가

### 테스트
- `tests/test_security.py` — `TestDeleteRestriction` 클래스 추가 (7개 테스트): SP can_delete 플래그, admin 삭제 가능, IP 추적 저장, 임시 계정 can_delete 플래그, admin 임시 계정 삭제 가능
