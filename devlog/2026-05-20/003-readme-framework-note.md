# README WIZ Framework 정보 추가 및 캡처 도구 문구 정리

## 사용자 원 요청

이 프로젝트는 WIZ Framework(Version: season==2.5.2)를 사용하여 개발되었다는 언급을 추가하고, github 링크도 달아줘. https://github.com/season-framework/wiz
README maintenance는 삭제하고, Playwright를 이용해서 캡쳐했다는 쓸데없는 문구들은 삭제해줘.

## 변경 파일

- `README.md`
  - 한글/영문 소개부에 WIZ Framework와 `season==2.5.2` 버전, GitHub 링크를 추가.
  - 스크린샷 섹션의 캡처 도구 설명 문구를 삭제.
  - `README maintenance` 섹션과 캡처 갱신 명령 예시를 삭제.
- `devlog.md`
- `devlog/2026-05-20/003-readme-framework-note.md`

## 확인 결과

- `rg -n "WIZ Framework|season==2\\.5\\.2|github\\.com/season-framework/wiz" README.md`로 한글/영문 양쪽 추가 확인.
- `rg -n "Playwright|README maintenance|captured|캡처했습니다|screenshot --browser" README.md` 결과 없음.
- `git diff --check` 통과.
- `/root/miniconda3/envs/test-idp/bin/python -m pytest tests/test_compact_design_templates.py` 실행 결과: 5 passed.
