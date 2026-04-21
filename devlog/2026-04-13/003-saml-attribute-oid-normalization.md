# SAML Attribute OID 정규화 및 입력 UI 개선

- **ID**: 003
- **날짜**: 2026-04-13
- **유형**: 기능 추가 | 버그 수정

## 작업 요약
SAMLResponse의 Attribute Name이 `uid`, `mail`, `displayName` 같은 friendly name과 basic NameFormat으로 내려가던 문제를 수정했다. 이제 공통 OID 카탈로그를 기준으로 사용자 속성, 기본 프리셋, response override를 모두 OID URN으로 정규화하고, XML에는 `attrname-format:uri`와 FriendlyName을 함께 기록한다.

또한 임시 계정 편집 화면과 SAML login.check 디버그 화면에 OID 속성 선택 보조 UI를 추가해, 사용자가 표준 OID를 직접 선택하거나 friendly name/custom key를 입력해도 저장 및 응답 생성 시 OID 기반으로 일관되게 처리되도록 했다.

## 변경 파일 목록

### Core 정규화
- `src/portal/idpcore/model/struct.py` - SAML OID 카탈로그, friendly/custom key → OID URN 변환, 기존 사용자/프리셋 데이터 자동 정규화 추가
- `src/portal/idpcore/model/struct/user.py` - 사용자 `saml_attributes` 저장/수정 시 OID 정규화 적용
- `src/portal/idpcore/model/struct/attribute_preset.py` - SAML 프리셋 payload 정규화와 기본 preset의 OID URN 키 적용
- `src/portal/idpcore/route/core/controller.py` - `/api/idpcore/saml-attribute-catalog` 엔드포인트 추가

### SAML Response 생성
- `src/portal/samlidp/model/struct/process.py` - Attribute XML을 OID URN + URI NameFormat으로 출력, FriendlyName 보강, custom override friendly name 유지

### UI
- `src/portal/idpcore/app/temp.account.form/view.ts`
- `src/portal/idpcore/app/temp.account.form/view.pug`
  - 공통 OID 카탈로그 로드, 클릭 삽입형 SAML Attribute 선택 UI 추가
- `src/portal/idpcore/app/temp.account.list/view.ts`
- `src/portal/idpcore/app/temp.account.list/view.pug`
  - Quick Create 기본 SAML 속성을 OID URN 기준으로 변경, 안내 문구 갱신
- `src/portal/samlidp/app/login.check/view.ts`
- `src/portal/samlidp/app/login.check/view.pug`
  - Attribute Override용 OID 선택 UI 추가

### 문서 및 테스트
- `src/portal/idpcore/README.md` - SAML OID 카탈로그 및 정규화 동작 문서화
- `tests/test_idpcore.py` - 사용자 SAML 속성 OID 정규화와 카탈로그 route 테스트 추가
- `tests/test_samlidp.py` - SAMLResponse Attribute OID 출력 및 custom override 정규화 회귀 테스트 추가

### 검증
- 일반 빌드 수행
- `pytest tests/test_idpcore.py tests/test_samlidp.py tests/test_saml_slo.py` 65개 통과