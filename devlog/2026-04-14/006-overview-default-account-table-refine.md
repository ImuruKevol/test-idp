# Overview 기본 계정 목록에서 admin 제외 및 테이블형 재배치

- **ID**: 006
- **날짜**: 2026-04-14
- **유형**: 버그 수정

## 작업 요약
Overview의 기본 테스트 계정 섹션에서 관리용 admin 계정을 목록에서 제외했다.
기본 테스트 계정 목록을 카드형에서 임시 테스트 계정과 유사한 테이블형 섹션으로 재구성하고, 임시 테스트 계정 섹션 바로 위로 이동했다.

## 변경 파일 목록
- `src/app/page.landing/api.py`: Overview 기본 계정 응답에서 admin 제외
- `src/app/page.landing/view.ts`: 상태 요약 문구 조정
- `src/app/page.landing/view.pug`: 기본 테스트 계정 섹션을 테이블형으로 변경하고 임시 테스트 계정 위로 이동
- `tests/test_idpcore.py`: Landing 기본 계정 목록에서 admin 제외 검증 반영

## 검증
- `pytest tests/test_idpcore.py tests/test_samlidp.py tests/test_saml_slo.py tests/test_oidcidp_ui.py` → 74 passed
- WIZ project build (`clean: false`) 완료