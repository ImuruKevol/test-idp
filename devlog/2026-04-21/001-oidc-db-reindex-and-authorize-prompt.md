# OIDC RP 인덱스 복구와 authorize 로그인 프롬프트 추가

- **ID**: 001
- **날짜**: 2026-04-21
- **유형**: 버그 수정

## 작업 요약
OIDC RP 삭제 시 `database disk image is malformed`가 발생하던 원인을 확인한 결과, `oidcidp.db` 파일 자체 손상은 아니고 `model_expires` 인덱스 불일치였다.
현재 DB는 `REINDEX`로 복구했고, 이후 같은 문제가 재발해도 OIDC RP registry가 인덱스 손상을 감지하면 자동으로 저장소를 복구한 뒤 재시도하도록 보강했다.

또한 등록된 서비스에서 `/api/oidc/authorize`를 호출할 때 세션이 없으면 JSON `login_required`만 반환하던 동작을 개선해, SAML과 같은 계정 선택/관리자 로그인 프롬프트 HTML을 먼저 보여준 뒤 authorize 흐름을 이어갈 수 있게 했다.

## 변경 파일 목록
- `src/portal/oidcidp/model/struct.py`: OIDC 저장소 손상 메시지 판별과 `REINDEX` 기반 복구 헬퍼 추가
- `src/portal/oidcidp/model/struct/registry.py`: RP list/get/register/update/delete 시 저장소 복구 후 재시도 래퍼 추가
- `src/portal/oidcidp/route/oidc/controller.py`: authorize 로그인 프롬프트, 빠른 사용자 선택, 관리자 로그인 재개 처리 추가
- `tests/test_oidcidp_ui.py`: RP 삭제 검증과 미인증 authorize 프롬프트 회귀 테스트 추가

## 검증
- `sqlite3 data/oidcidp.db 'PRAGMA integrity_check;'` → `ok`
- `pytest tests/test_oidcidp_ui.py -q`
- WIZ project build (`clean: false`) 완료