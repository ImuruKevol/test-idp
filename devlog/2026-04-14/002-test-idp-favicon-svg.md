# Test IdP용 SVG favicon 제작 및 head favicon 링크 교체

- **ID**: 002
- **날짜**: 2026-04-14
- **유형**: 기능 추가

## 작업 요약
기존 기본 ico 중심 favicon 구성을 Test IdP 서비스 성격에 맞는 SVG favicon으로 교체했다. SAML을 상징하는 오렌지 노드, OIDC를 상징하는 스카이 노드, 중앙의 흰색 허브를 조합한 아이콘을 새로 만들고 Angular index head에서 이 SVG를 우선 favicon으로 사용하도록 연결했다.

브라우저/플랫폼 호환을 위해 기존 ico는 shortcut icon 및 apple-touch-icon fallback으로 유지했다. 빌드를 다시 수행해 생성된 index.html과 build 자산 폴더에 새 SVG favicon이 반영되는 것을 확인했다.

## 변경 파일 목록
- `src/assets/brand/test-idp-favicon.svg` - Test IdP용 신규 SVG favicon 추가
- `src/angular/index.pug` - favicon 링크를 SVG 우선, ico fallback 구조로 변경
- `devlog.md` - 2026-04-14 작업 요약 행 추가