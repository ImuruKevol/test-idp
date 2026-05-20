# Test IdP README 한영 재작성 및 1920x1080 화면 캡처 추가

## 사용자 원 요청

현재 README는 샘플 프로젝트 때 그대로 남아있어. 이걸 날리고 현재 Test IdP라는 성격에 맞도록 다시 작성을 해야해. 이 서비스에서 제공하는 기능, 구조 등을 README에 깔끔하게 작성해줘. 한글, 영어를 모두 작성해줘. playwright같은걸 사용해서 1920x1080 크기의 다양한 스크린샷도 찍어서 첨부하면 좋을 것 같아.

## 변경 파일

- `README.md`
  - 기존 WIZ Sample Project 설명을 제거하고 Test IdP 서비스 소개, 기능, 화면 구조, 프로토콜 엔드포인트, 프로젝트 구조, 저장소, 개발/테스트 메모를 한글과 영어로 다시 작성.
- `docs/screenshots/test-idp-overview.png`
  - Overview 및 임시 테스트 계정 화면 1920x1080 캡처.
- `docs/screenshots/test-idp-saml-register.png`
  - SAML SP 등록 화면 1920x1080 캡처.
- `docs/screenshots/test-idp-saml-metadata.png`
  - SAML IdP metadata 배포 화면 1920x1080 캡처.
- `docs/screenshots/test-idp-oidc-register.png`
  - OIDC RP 등록 화면 1920x1080 캡처.
- `docs/screenshots/test-idp-oidc-discovery.png`
  - OIDC Discovery/JWKS 화면 1920x1080 캡처.
- `devlog.md`
- `devlog/2026-05-20/002-readme-refresh.md`

## 확인 결과

- Playwright Chromium으로 `https://debug-idp.nanoha.kr/`, `/saml/register`, `/saml/publish`, `/oidc/register`, `/oidc/publish`를 1920x1080 viewport로 캡처.
- `file docs/screenshots/*.png`로 모든 PNG가 1920 x 1080임을 확인.
- `rg -n "WIZ Sample Project|admin@example.com|post package|page.posts" README.md`로 샘플 프로젝트 잔여 문구가 없음을 확인.
- `/root/miniconda3/envs/test-idp/bin/python -m pytest tests` 실행 결과: 117 passed.
