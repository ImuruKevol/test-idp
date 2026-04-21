# 샘플 코드 정리, 인증 검증 및 통합 테스트 작성

- **ID**: 006
- **날짜**: 2026-03-31
- **유형**: 리팩토링 | 테스트

## 작업 요약
FN-0002~0006 구현 후 남아있던 사용하지 않는 샘플 코드(post 패키지, dashboard/members/mypage 페이지 등)를 전체 삭제하고, page.access 로그인을 idpcore 기반으로 전환했다. 모든 페이지의 controller/auth 설정을 검증한 뒤, idpcore 18개 + samlidp 20개 = 총 38개 통합 테스트를 작성하여 전체 통과를 확인했다.

## 변경 파일 목록

### 삭제 (샘플 코드 정리)
- `src/portal/post/` — 전체 삭제 (샘플 블로그 패키지)
- `src/app/page.posts/` — 게시글 목록 페이지
- `src/app/page.posts.item/` — 게시글 상세 페이지
- `src/app/page.dashboard/` — 대시보드 페이지
- `src/app/page.members/` — 회원 관리 페이지
- `src/app/page.mypage/` — 마이페이지
- `src/app/component.nav.sidebar/` — 사이드바 네비게이션
- `src/app/layout.sidebar/` — 사이드바 레이아웃
- `src/model/db/user.py` — 구 bcrypt 기반 유저 DB 모델
- `src/model/struct/user.py` — 구 유저 Struct

### 수정
- `src/model/struct.py` — user 프로퍼티 제거, 패키지 동적 로딩만 유지
- `src/app/page.access/api.py` — idpcore 기반 인증으로 전환
- `src/app/page.access/view.ts` — username/password 필드로 변경
- `src/app/page.access/view.pug` — IdP 테마 로그인 UI
- `src/app/layout.topnav/view.pug` — 로그인/로그아웃 버튼 추가

### 신규 (테스트)
- `tests/conftest.py` — WizClient 테스트 헬퍼 클래스
- `tests/test_idpcore.py` — idpcore 통합 테스트 (18개)
- `tests/test_samlidp.py` — samlidp 통합 테스트 (20개)
- `tests/run_tests.sh` — 테스트 실행 스크립트
