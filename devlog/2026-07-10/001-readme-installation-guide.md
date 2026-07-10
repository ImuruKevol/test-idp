# README WIZ 설치 및 실행 가이드 추가

- **ID**: 001
- **날짜**: 2026-07-10
- **유형**: 문서 업데이트
- **리뷰 ID**: wbkpbiswxerdlzcsxhiyafopkhanulpj

## 사용자 원문 요청

> readme에 installation을 추가로 작성해줘.  
> readme에는 WIZ(https://github.com/season-framework/wiz)의 구조 및 커맨드 등을 참고하여 설치 방법 및 실행 방법 위주로 작성이 되어야 해. readme의 설치 방법만 쭉 따라하면 구성할 수 있도록 쉽고 직관적으로 작성이 되어야 해.

## 작업 요약

WIZ 공식 저장소의 워크스페이스 구조와 `wiz create`, `wiz project create`, `wiz project build`, `wiz run` CLI 흐름을 기준으로 README의 한글·영문 설치 및 실행 절차를 작성했다. 새 환경에서 복사만 하면 SQLite namespace가 모두 준비되도록 DB 설정 샘플을 실제 idpcore, samlidp, oidcidp 구성과 일치시켰다.

## 변경 파일 목록

- `README.md`
  - 시스템 요구사항, Python 가상환경과 의존성, WIZ 워크스페이스 생성, Git 프로젝트 가져오기, DB 설정, 관리자 비밀번호, 빌드·실행 순서를 한글과 영문으로 추가했다.
  - 자주 사용하는 WIZ 명령과 명령 실행 위치를 정리하고, 구조도를 WIZ 워크스페이스부터 `project/main/src`까지 보이도록 확장했다.
  - 특정 서버의 Miniconda 절대경로로 고정되어 있던 테스트 명령을 일반 가상환경용 명령으로 변경했다.
- `config-sample/database.py`
  - 복사 직후 사용할 수 있도록 `base`, `idpcore`, `samlidp`, `oidcidp` SQLite namespace와 WIZ 워크스페이스 기준 경로를 정의했다.
- `tests/test_readme_installation.py`
  - README의 필수 설치·실행 단계와 DB 설정 샘플의 전체 namespace를 검증하는 회귀 테스트를 추가했다.
- `devlog.md`
  - 이번 작업 요약 행을 추가했다.
- `devlog/2026-07-10/001-readme-installation-guide.md`
  - 요청 원문, 변경 내용, 검증 결과를 기록했다.

## 확인 결과

- WIZ 공식 GitHub 저장소의 최신 `main` README와 한국어 CLI 문서에서 워크스페이스 구조 및 명령 형식을 대조했다.
- PyPI에서 `season==2.5.2` 배포와 Python 3.8 이상 요구사항을 확인했다.
- `/root/miniconda3/envs/test-idp/bin/python -m pytest tests/test_readme_installation.py -q`: `2 passed`
- `/root/miniconda3/envs/test-idp/bin/python -m pytest tests -q`: `126 passed`
- `git diff --check`: 통과

## 남은 리스크

- README의 전체 설치 절차를 빈 운영체제에서 처음부터 재실행하지는 않았다. OS·Python·Node.js 배포판에 따라 네이티브 SAML 패키지 설치 과정이 달라질 수 있어 Ubuntu/Debian과 macOS 준비 사항을 구분해 안내했다.
