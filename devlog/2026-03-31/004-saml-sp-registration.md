# SAML SP 등록과 IdP 메타데이터 배포 구현

- **ID**: 004
- **날짜**: 2026-03-31
- **유형**: 기능 추가

## 작업 요약
samlidp 패키지에 SP 메타데이터 등록(파싱/검증/저장)과 IdP 메타데이터 생성·배포 기능을 구현. DB 모델, Struct(registry/metadata), Route API, Portal 컴포넌트(sp.register/idp.metadata)를 전면 작성하고 page.saml에 통합.

## 변경 파일 목록

### DB 모델
- `src/portal/samlidp/model/db/saml_sp_registry.py`: 신규 — SP 레지스트리 테이블 정의 (entity_id, acs_url, slo_url, nameid_formats, certificates, flags 등)

### Struct
- `src/portal/samlidp/model/struct.py`: _init_tables 추가, registry/metadata 프로퍼티 연결
- `src/portal/samlidp/model/struct/registry.py`: 신규 — SP XML 메타데이터 파싱·검증·등록·삭제 로직
- `src/portal/samlidp/model/struct/metadata.py`: 신규 — IdP 키페어 생성, 메타데이터 XML 빌드, 엔드포인트 정보 제공

### Route
- `src/portal/samlidp/route/saml/controller.py`: /api/saml/<path:path> — metadata, idp-info, sp-list, sp-register, sp-get, sp-delete, sp-metadata-raw 엔드포인트

### Portal App
- `src/portal/samlidp/app/sp.register/`: 신규 — SP 등록 컴포넌트 (XML 업로드/붙여넣기, 목록, 상세, 삭제)
- `src/portal/samlidp/app/idp.metadata/`: 신규 — IdP 메타데이터 배포 컴포넌트 (엔드포인트 요약, XML 복사/다운로드)

### Source App
- `src/app/page.saml/view.pug`: scaffold → 실제 Portal 컴포넌트 (register=sp.register, publish=idp.metadata) 통합

### 라이브러리
- signxml pip 패키지 설치

### 빌드·서비스
- 클린 빌드 수행
- 서비스 재시작 (새 route 추가)
