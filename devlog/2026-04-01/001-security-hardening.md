# 종합 보안 강화

- **ID**: 001
- **날짜**: 2026-04-01
- **유형**: 보안 강화

## 작업 요약
비로그인 공개 테스트 IdP 서비스에 대한 종합적인 보안 감사를 수행하고, 13개 취약점을 식별하여 10개 카테고리의 보안 패치를 적용했다. 기존 59개 테스트를 유지하면서 17개의 보안 전용 테스트를 추가하여 총 76개 테스트가 모두 통과한다.

## 식별된 취약점 및 수정 사항

### CRITICAL

1. **XXE Injection (XML External Entity)**
   - 위치: `process.py` (parse_authn_request, parse_logout_request), `registry.py` (parse_metadata)
   - 수정: `etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)` 적용

2. **Rate Limiting 부재**
   - 수정: `rate_limiter.py` 모델 생성 (in-memory, IP 기반, sliding window)
   - 적용: 로그인(10회/5분), 임시계정생성(10회/5분), SP등록(5회/5분), SSO/SLO파싱(30회/1분), seed-force(3회/5분), user-delete(10회/5분)

### HIGH

3. **Password Hash 노출**
   - 위치: `core/controller.py`, `login.check/api.py`, `logout.check/api.py`
   - 수정: `_sanitize_user()` 헬퍼로 모든 API 응답에서 `password_hash` 필드 제거

4. **XML 페이로드 크기 제한 없음**
   - 수정: `MAX_XML_SIZE = 256KB` 검증을 XML 파싱 전에 수행

### MEDIUM

5. **Path Traversal in debug-raw**
   - 수정: `get_debug_raw()` 키값에 `^[a-zA-Z0-9_\-]+$` 정규식 검증 적용

6. **Header Injection in Content-Disposition**
   - 수정: `sp-metadata-raw`의 파일명에서 특수문자를 `_`로 치환

7. **Login Brute-Force 무제한**
   - 수정: rate_limiter로 IP당 10회/5분 제한

8. **Cleanup-on-Read DoS**
   - 수정: `registry.list()`에 60초 쓰로틀 적용하여 매 요청마다 cleanup 실행 방지

9. **Mass Assignment**
   - 수정: `user-create-temporary`와 `user-update`에 필드 화이트리스트 적용
   - 임시계정: username, password, email, display_name, profile, saml_attributes, oidc_claims
   - 업데이트: + role 추가

10. **SP 등록 수량 제한**
    - 수정: `MAX_SP_COUNT = 50`으로 전체 SP 등록 수 제한

## 변경 파일 목록

### 보안 모델 (신규)
- `src/portal/idpcore/model/struct/rate_limiter.py` — IP 기반 in-memory 레이트 리미터 (sys 모듈에 상태 저장)

### XML 파싱 보안
- `src/portal/samlidp/model/struct/process.py` — XXE 방지 파서, XML 크기 제한, Path Traversal 검증
- `src/portal/samlidp/model/struct/registry.py` — XXE 방지 파서, XML 크기 제한, SP 수량 제한, 클린업 쓰로틀

### API 보안
- `src/portal/idpcore/route/core/controller.py` — 비밀번호 해시 제거, Mass Assignment 화이트리스트, 레이트리밋, rate-limit-reset 엔드포인트
- `src/portal/samlidp/route/saml/controller.py` — SP 등록·SSO·SLO 레이트리밋, Header Injection 수정
- `src/app/page.access/api.py` — 로그인 레이트리밋
- `src/portal/samlidp/app/login.check/api.py` — password_hash 제거
- `src/portal/samlidp/app/logout.check/api.py` — password_hash 제거

### 테스트
- `tests/test_security.py` — 17개 보안 테스트 (XXE, 크기제한, Path Traversal, Mass Assignment, password_hash, 레이트리밋)
- `tests/conftest.py` — reset_rate_limits 픽스처, WizClient.reset_rate_limits() 메서드 추가
