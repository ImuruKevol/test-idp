# OIDC·SAML 작업 화면 UX 개편

## 작업 정보

| 항목 | 내용 |
| --- | --- |
| 날짜 | 2026-09-15 |
| 리뷰 ID | `kqlabukdqlnoqctcbhrcbjdtnpssffou` |
| 선택 AI 모델 | `gpt-5.6-sol` |
| 실제 AI 모델 | `gpt-5.6-sol` |
| 추론 수준 | `max` |

## 사용자 원본 요청

```text
- 실행 프로필이라는 기능이 생겼는데, 이걸 뭐 어떻게 하는건지 모르겠음. 설정이 너무 헷갈리게 되어있음.
- SAML, OIDC 상세 화면들의 UX, 레이아웃들이 너무 헷갈리고, 메뉴 구성이나 위치 등이 너무 뒤죽박죽임. 디자인, 스타일, 레이아웃 등은 전부 갈아엎어도 되니까 UX를 고려하여 개선할 것.
```

## 참고 자료

- 리뷰 첨부 체크리스트: 표준 방식 우선 제공, 호환 방식 지원 및 상세 화면의 명시적 구분 요구를 확인했다.
- 프로젝트 지침: Pug 문법, 상태 변경 후 렌더링, 요청 중 상태 표시, 왼쪽 요약과 오른쪽 상세 탭 구성을 적용했다.

## 작업 정의 및 주요 개발 항목

1. OIDC와 SAML을 동일한 4단계 작업 메뉴로 정리하고 현재 위치와 권장 순서를 표시했다.
2. 실행 설정을 선택 기능으로 설명하고 이름, 용도별 시작값, 주요 값, 고급 값의 순서로 다시 구성했다.
3. RP와 SP 상세를 왼쪽 요약 및 작업 버튼, 오른쪽 상세 탭으로 분리했다.
4. 로그인과 로그아웃 화면의 기본 흐름을 단계형으로 배치하고 고급 입력과 원문을 접었다.
5. 표준 및 호환 시험 상태를 저장 결과와 상세 화면에서 구분하고 설정 불러오기 API를 추가했다.

## 파일 변경

- `src/app/page.{oidc,saml}/`: 번호형 작업 메뉴, 현재 화면, 반응형 좌우 레이아웃.
- `src/app/layout.topnav/view.pug`, `src/app/page.landing/view.pug`: 폭과 화면 문구 정리.
- `src/portal/oidcidp/app/provider.publish/`: 안내형 실행 설정, 시작값 선택, 불러오기·저장·초기화 상태.
- `src/portal/oidcidp/app/rp.register/`: 등록 안내와 상세 요약·Callback·Claim 탭.
- `src/portal/oidcidp/app/{authorize.check,logout.check}/view.html`: 단계형 입력, 주요 결과 우선 배치, 고급 값 접기.
- `src/portal/samlidp/app/idp.metadata/`: 안내형 실행 설정과 설정 불러오기, 연결 정보 재배치.
- `src/portal/samlidp/app/{sp.register,login.check,logout.check}/`: 상세 탭, SSO 시작 방식, SLO 작업 선택 화면.
- `src/portal/samlidp/model/struct/metadata.py`: 저장된 응답 설정의 표준·호환 상태 계산.
- `tests/test_protocol_console_ux.py`, `tests/test_reviewops_profiles.py`: 메뉴·화면 구조·상태 표시·렌더링 및 저장 설정 회귀 검사.

## 검증 및 배포 결과

- `/root/miniconda3/envs/test-idp/bin/python -m pytest -q tests`: `45 passed`.
- 변경 Python 파일 `py_compile`: 통과.
- `git diff --check`: 통과.
- 변경 화면의 금지 용어 및 `ngModelChange` 누락 검사: 통과.
- `wiz project build --project=main --clean`: 클린 빌드 성공.
- 배포와 서비스 재시작은 수행하지 않았다.

## 남은 리스크

- 실제 브라우저 크기별 화면과 키보드 이동은 확인하지 않았다.
- 공개 런타임과 외부 RP·SP 연동에는 아직 반영하지 않았다.
- 클린 빌드의 npm 감사 결과에 기존 의존성 취약점 60건이 남아 있다.
