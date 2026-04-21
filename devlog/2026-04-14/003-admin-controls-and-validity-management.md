# 관리자 비밀번호 변경, 만료 데이터 연장·영구 전환, 헤더 브랜드 아이콘 반영

- **ID**: 003
- **날짜**: 2026-04-14
- **유형**: 기능 추가

## 작업 요약
상단 좌측 브랜드 영역에 새 SVG favicon을 실제 아이콘으로 노출하도록 반영했다.
관리자 전용 랜딩 패널에 현재 관리자 계정 비밀번호 변경 기능을 추가하고, 테스트 계정·SAML SP·OIDC RP에 대해 만료 연장과 무기한 전환을 지원하도록 백엔드와 화면을 확장했다.

## 변경 파일 목록
### 레이아웃 / 관리자 화면
- `src/app/layout.topnav/view.pug`: 좌측 상단 브랜드 배지에 SVG favicon 이미지 추가
- `src/app/page.landing/api.py`: 관리자 비밀번호 변경 API, 만료 현황 집계 추가
- `src/app/page.landing/view.ts`: 관리자 비밀번호 변경 상태 및 만료 요약 상태 추가
- `src/app/page.landing/view.pug`: 관리자 제어 패널, 비밀번호 변경 폼, 만료 데이터 이동 링크 추가

### 공통 계정 / 만료 관리 API
- `src/portal/idpcore/model/struct/user.py`: 임시 계정 TTL 조회, 만료 연장, 무기한 전환, 만료 판별 공개 메서드 추가
- `src/portal/idpcore/route/core/controller.py`: 관리자 전용 임시 계정 연장·무기한 전환 route 추가 및 audit 기록
- `src/portal/idpcore/app/temp.account.list/view.ts`: 관리자 연장/무기한 액션 추가
- `src/portal/idpcore/app/temp.account.list/view.pug`: 임시 계정 상태 배지와 관리자 액션 버튼 추가

### SAML / OIDC 만료 관리
- `config/idp.py`: SAML SP / OIDC RP 기본 TTL 상수 추가
- `src/portal/samlidp/model/struct/registry.py`: 자동 정리 의존 제거, 만료 연장·무기한 전환 메서드 추가
- `src/portal/samlidp/app/sp.register/api.py`: 관리자 전용 연장·무기한 전환 API 추가
- `src/portal/samlidp/app/sp.register/view.ts`: 관리자 액션 및 만료 상태 계산 추가
- `src/portal/samlidp/app/sp.register/view.pug`: 만료 상태 UI와 관리자 액션 버튼 추가
- `src/portal/oidcidp/model/db/oidc_rp_client.py`: RP expires 컬럼 추가
- `src/portal/oidcidp/model/struct.py`: expires 컬럼 마이그레이션 추가
- `src/portal/oidcidp/model/struct/registry.py`: RP TTL, 만료 판별, 연장·무기한 전환 로직 추가
- `src/portal/oidcidp/app/rp.register/api.py`: 관리자 전용 연장·무기한 전환 API 추가
- `src/portal/oidcidp/app/rp.register/view.ts`: 관리자 액션 및 만료 상태 계산 추가
- `src/portal/oidcidp/app/rp.register/view.html`: RP 유효 시간 배지, 상세 카드, 관리자 액션 버튼 추가

### 테스트 / 검증
- `tests/test_idpcore.py`: 관리자 비밀번호 변경/복구, 임시 계정 만료 연장·무기한 전환 테스트 추가
- `tests/test_samlidp.py`: SAML SP 만료 연장·무기한 전환 테스트 추가
- `tests/test_oidcidp_ui.py`: OIDC RP expires 검증 및 연장·무기한 전환 테스트 추가

## 검증
- `pytest tests/test_idpcore.py tests/test_samlidp.py tests/test_saml_slo.py tests/test_oidcidp_ui.py` → 73 passed
- WIZ project build (`clean: true`, 이후 `clean: false`) 완료