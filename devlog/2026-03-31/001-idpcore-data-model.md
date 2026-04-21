# idpcore 공통 데이터 모델과 저장소 구현

- **ID**: 001
- **날짜**: 2026-03-31
- **유형**: 기능 추가

## 작업 요약
idpcore 패키지의 공통 DB 모델(idp_user, idp_attribute_preset, idp_debug_payload, idp_audit_log)과 Struct 계층을 완성하고, 샘플 데이터 seed 기능을 검증했다. samlidp/oidcidp 패키지에서 idpcore를 참조할 수 있도록 연결하고, REST API route를 통해 CRUD와 seed를 검증했다.

## 변경 파일 목록

### Config
- `config/database.py` — SQLite DB 경로를 WIZ root 기준 `project/main/data/` 하위로 수정

### Portal: idpcore
- `src/portal/idpcore/model/db/idp_user.py` — 테스트 사용자 DB 모델 (FN-0001에서 작성됨, 검증 완료)
- `src/portal/idpcore/model/db/idp_attribute_preset.py` — 속성 프리셋 DB 모델 (FN-0001에서 작성됨, 검증 완료)
- `src/portal/idpcore/model/db/idp_debug_payload.py` — 디버그 페이로드 DB 모델 (FN-0001에서 작성됨, 검증 완료)
- `src/portal/idpcore/model/db/idp_audit_log.py` — 감사 로그 DB 모델 (FN-0001에서 작성됨, 검증 완료)
- `src/portal/idpcore/model/struct.py` — Composite Struct 싱글톤 (FN-0001에서 작성됨, 검증 완료)
- `src/portal/idpcore/model/struct/user.py` — User Sub-Struct + seed_samples (FN-0001에서 작성됨, 검증 완료)
- `src/portal/idpcore/model/struct/attribute_preset.py` — AttributePreset Sub-Struct + seed_defaults (FN-0001에서 작성됨, 검증 완료)
- `src/portal/idpcore/model/struct/debug_payload.py` — DebugPayload Sub-Struct (FN-0001에서 작성됨, 검증 완료)
- `src/portal/idpcore/model/struct/audit.py` — Audit Sub-Struct (FN-0001에서 작성됨, 검증 완료)
- `src/portal/idpcore/route/core/` — idpcore REST API route 생성 (info, seed, users, presets)
- `src/portal/idpcore/README.md` — 패키지 API 문서 작성

### Portal: samlidp / oidcidp
- `src/portal/samlidp/model/struct.py` — core(idpcore) 참조 추가, ORM/session 연결
- `src/portal/oidcidp/model/struct.py` — core(idpcore) 참조 추가, ORM/session 연결

### System
- `bcrypt` pip 패키지 설치 (season ORM dbbase 의존성)
