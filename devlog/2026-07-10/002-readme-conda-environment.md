# README Conda 환경 구성 전환

- **ID**: 002
- **날짜**: 2026-07-10
- **유형**: 문서 업데이트
- **리뷰 ID**: wbkpbiswxerdlzcsxhiyafopkhanulpj

## 사용자 원문 요청

> 내가 좀 수정을 해놨는데, 참고하고.  
> 그리고 python은 왠만하면 conda를 사용해서 구성하는 식으로 수정해줘.

## 작업 요약

현재 README 편집 내용을 유지하면서 Python 설치 절차를 `venv` 대신 Miniconda 기반으로 변경했다. `test-idp` Conda 환경에 Python 3.12를 설치하고, 환경을 활성화한 뒤 WIZ와 프로젝트 의존성을 설치·실행하도록 한글과 영문 절차를 함께 맞췄다.

## 변경 파일 목록

- `README.md`
  - 준비 사항에 Miniconda/Anaconda를 명시하고 Conda 버전 확인 절차를 추가했다.
  - `python3 -m venv`와 `.venv` 활성화 명령을 `conda create` 및 `conda activate`로 교체했다.
  - 재실행 절차와 macOS 안내도 Conda 환경을 기준으로 수정했다.
- `tests/test_readme_installation.py`
  - Conda 환경 생성·활성화 명령을 필수로 검증하고 기존 `venv` 명령이 남지 않도록 회귀 조건을 추가했다.
- `devlog.md`
  - 이번 후속 작업 요약 행을 추가했다.
- `devlog/2026-07-10/002-readme-conda-environment.md`
  - 요청 원문, 변경 내용, 검증 결과를 기록했다.

## 확인 결과

- Conda 공식 환경 관리 문서와 현재 CLI 도움말에서 `conda create --name` 및 `conda activate` 사용법을 대조했다.
- `/root/miniconda3/envs/test-idp/bin/python -m pytest tests/test_readme_installation.py -q`: `2 passed`
- `git diff --check`: 통과

## 남은 리스크

- 새 운영체제에 Miniconda부터 설치하는 전체 절차는 직접 재실행하지 않았다. Conda 초기화 방식과 SAML 네이티브 라이브러리 패키지명은 OS 및 사용 셸에 따라 달라질 수 있다.
