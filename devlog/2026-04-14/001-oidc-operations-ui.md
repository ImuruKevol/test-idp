# OIDC 운영 화면군과 RP/discovery/authorize/logout 시뮬레이션 UI 구현

- **ID**: 001
- **날짜**: 2026-04-14
- **유형**: 기능 추가

## 작업 요약
OIDC 페이지를 SAML과 동일한 탭 구조의 실제 운영 화면으로 전환했다. RP 등록/목록, discovery/JWKS 배포, authorize 시뮬레이션, logout 시뮬레이션을 각각 portal app으로 구현하고, OIDC 패키지 모델 계층에 RP registry, provider metadata/JWKS, UI 시뮬레이션 preview 로직을 추가했다.

RP 등록 정보는 oidcidp 저장소에 보관되며, authorize/logout 화면은 idpcore 사용자/claim preset 및 debug history와 연동된다. 클린 빌드 후 tests/test_idpcore.py, tests/test_oidcidp_ui.py를 실행해 OIDC 화면용 app api와 공용 preset 동작을 검증했다.

## 변경 파일 목록

### Page
- `src/app/page.oidc/view.pug` — OIDC 스캐폴드 문구를 제거하고 실제 portal app 4종을 탭에 연결

### Portal: oidcidp model
- `src/portal/oidcidp/model/struct.py` — registry/provider/preview 진입점과 테이블 초기화 추가
- `src/portal/oidcidp/model/db/oidc_rp_client.py` — OIDC RP 등록 정보 저장용 DB 모델 추가
- `src/portal/oidcidp/model/struct/registry.py` — RP 등록/조회/삭제, 정책 정규화 로직 구현
- `src/portal/oidcidp/model/struct/provider.py` — issuer, discovery, JWKS, id_token 서명용 키 생성/관리 로직 구현
- `src/portal/oidcidp/model/struct/preview.py` — authorize/logout 시뮬레이션, claim 릴리즈 계산, debug history 기록 구현

### Portal: oidcidp apps
- `src/portal/oidcidp/app/rp.register/api.py` — RP 등록/목록 bootstrap/get/delete API 추가
- `src/portal/oidcidp/app/rp.register/view.ts` — 목록/등록/상세 상태 관리 구현
- `src/portal/oidcidp/app/rp.register/view.html` — RP 운영 콘솔 UI 구현
- `src/portal/oidcidp/app/provider.publish/api.py` — provider info/discovery/JWKS 조회 API 추가
- `src/portal/oidcidp/app/provider.publish/view.ts` — 게시 화면 데이터 로딩/복사/다운로드 로직 구현
- `src/portal/oidcidp/app/provider.publish/view.html` — discovery/JWKS 게시 UI 구현
- `src/portal/oidcidp/app/authorize.check/api.py` — authorize bootstrap/history/simulate API 추가
- `src/portal/oidcidp/app/authorize.check/view.ts` — authorize 시뮬레이션 입력/임시 사용자 생성/결과 상태 관리 구현
- `src/portal/oidcidp/app/authorize.check/view.html` — authorize request, consent, token/userinfo preview UI 구현
- `src/portal/oidcidp/app/logout.check/api.py` — logout bootstrap/history/simulate API 추가
- `src/portal/oidcidp/app/logout.check/view.ts` — logout 시뮬레이션 상태 관리 구현
- `src/portal/oidcidp/app/logout.check/view.html` — end session URL, hint decode, redirect 검증 UI 구현

### Documentation / Test
- `src/portal/oidcidp/README.md` — 현재 OIDC 패키지 역할과 portal/model 진입점 설명으로 갱신
- `tests/test_oidcidp_ui.py` — RP 등록, discovery/JWKS, authorize/logout 시뮬레이션 검증 테스트 추가