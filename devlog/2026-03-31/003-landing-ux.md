# 공통 레이아웃과 랜딩 UX 구현

- **ID**: 003
- **날짜**: 2026-03-31
- **유형**: 기능 추가

## 작업 요약
page.landing의 viewuri를 `/landing`에서 `/`로 변경하고, api.py를 추가하여 idpcore 시스템 상태(계정 수, 프리셋 수, 임시 계정 활성 수 등)를 동적으로 표시하도록 구현. Hero 영역, SAML/OIDC CTA 카드, 임시 계정 관리 컴포넌트를 배치하여 운영용 랜딩 페이지를 완성.

## 변경 파일 목록

### page.landing
- `app.json`: viewuri `/landing` → `/`, controller `base` 확인
- `api.py`: 신규 생성 — `load()` 함수로 idpcore struct의 info + temporary_active 카운트 반환
- `view.ts`: 동적 `loadInfo()` 메서드 추가, summary 배열 바인딩
- `view.pug`: Hero(SAML/OIDC CTA), System Status 카드(동적 summary), SAML/OIDC/임시계정 3컬럼 카드 레이아웃으로 전면 재작성

### 빌드
- 클린 빌드 수행 (새 api.py 함수 추가)
