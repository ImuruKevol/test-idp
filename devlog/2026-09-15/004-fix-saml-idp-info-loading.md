# SAML IdP 정보 로딩 오류 수정

## 작업 정보

| 항목 | 내용 |
| --- | --- |
| 날짜 | 2026-09-15 |
| 리뷰 ID | `kqlabukdqlnoqctcbhrcbjdtnpssffou` |
| 선택 AI 모델 | `gpt-5.6-sol` |
| 실제 AI 모델 | `gpt-5.6-sol` |
| 추론 수준 | `xhigh` |

## 사용자 원본 요청

```text
- SAML에서 IdP 정보가 "IdP 정보를 불러오지 못했습니다." 라고 뜸
-
```

## 참고 자료

- 실행 중 로그: IdP 정보 API가 이전에 읽힌 Metadata 모델에서 새 목록 메서드를 찾지 못해 500을 반환한 사실을 확인했다.
- 리뷰 첨부 체크리스트: SAML 표준 정보와 호환 시험 상태 표시 요구를 유지했다.
- 프로젝트 지침: WIZ API, Pug·Angular 렌더링, 테스트와 빌드 규칙을 적용했다.

## 작업 정의 및 주요 개발 항목

1. IdP 기본 정보와 저장된 실행 설정 조회가 서로 영향을 주지 않도록 API 처리를 보강했다.
2. 실행 중 모델이 새 목록 메서드를 아직 읽지 못한 경우 기존 메서드로 목록을 구성하도록 했다.
3. Metadata XML 조회가 실패해도 이미 받은 IdP 기본 정보는 유지하도록 화면 로딩을 분리했다.

## 파일 변경

- `src/portal/samlidp/app/idp.metadata/api.py`: 실행 중 모델과 호환되는 저장 설정 목록 조회 및 오류 격리.
- `src/portal/samlidp/app/idp.metadata/view.ts`: IdP 정보와 Metadata XML 독립 로딩.
- `tests/test_reviewops_profiles.py`: 이전 모델 형태를 사용한 IdP 정보 API 회귀 검사.

## 검증 및 배포 결과

- 대상 테스트: `28 passed`.
- 전체 테스트: `52 passed`.
- 변경 Python 파일 `py_compile`: 통과.
- `git diff --check`: 통과.
- `wiz project build --project=main`: 일반 빌드 성공.
- 실행 중 API 확인: IdP 정보 `HTTP 200`, Entity ID 확인, 저장 설정 3건 확인.
- Metadata XML API 확인: `HTTP 200`, XML 생성 확인.
- 실행 중 캐시를 현재 빌드로 갱신했으며 서비스 재시작은 수행하지 않았다.

## 남은 리스크

- 브라우저 화면 조작 검사는 수행하지 않았다.
- 공개 API의 응답과 실행 로그로 오류 해소를 확인했다.
