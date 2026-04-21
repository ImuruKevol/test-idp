# Overview 기본 계정 카드 추가 및 5번째 샘플 계정 반영

- **ID**: 005
- **날짜**: 2026-04-14
- **유형**: 기능 추가

## 작업 요약
Overview 화면에 임시 테스트 계정과 별도로 기본 테스트 계정 목록 카드를 추가했다.
기본 샘플 계정 요구사항을 5개로 맞추기 위해 `carol` 계정을 추가하고, 랜딩 API/화면/테스트를 함께 갱신했다.

## 변경 파일 목록
- `config/idp.py`: 보호 샘플 계정 목록에 `carol` 추가
- `src/portal/idpcore/model/struct.py`: core 초기화 시 기본 샘플 계정/프리셋 seed 보장
- `src/portal/idpcore/model/struct/user.py`: `carol` 기본 계정 추가
- `src/app/page.landing/api.py`: Overview용 기본 계정 목록 응답 추가
- `src/app/page.landing/view.ts`: defaultAccounts 상태 추가 및 로드
- `src/app/page.landing/view.pug`: 기본 계정 5개 카드 추가
- `src/portal/idpcore/README.md`: 기본 샘플 계정 표 갱신
- `tests/conftest.py`: 테스트 클래스 시작 전 샘플 계정 강제 초기화
- `tests/test_idpcore.py`: 기본 계정 5개, `carol`, Overview 응답 검증 추가

## 검증
- `pytest tests/test_idpcore.py tests/test_samlidp.py tests/test_saml_slo.py tests/test_oidcidp_ui.py` → 74 passed
- WIZ project build (`clean: false`) 완료