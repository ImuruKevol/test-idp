# admin 비밀번호 변경 시 idpcore DB 자동 초기화

- **ID**: 003
- **날짜**: 2026-07-10
- **유형**: 버그 수정
- **리뷰 ID**: wbkpbiswxerdlzcsxhiyafopkhanulpj

## 사용자 원문 요청

> 내가 readme를 좀 수정했어.  
> 근데 새 서버에 설치하니까 아래 에러가 발생했어.  
> `(debug-idp) root@mini4:~/workspace/debug-idp# python project/main/scripts/change_admin_password.py`  
> `[ERROR] DB 파일을 찾을 수 없습니다: /root/workspace/debug-idp/project/main/data/idpcore.db`

## 작업 요약

새 설치에서는 idpcore 모델이 아직 로드되지 않아 SQLite DB와 admin 계정이 생성되기 전이라는 원인을 확인했다. 비밀번호 변경 스크립트가 DB 또는 admin 계정 부재를 감지하면 WIZ 프로젝트의 idpcore 모델을 먼저 로드해 테이블과 seed 계정을 초기화한 뒤 비밀번호를 변경하도록 수정했다.

## 변경 파일 목록

- `scripts/change_admin_password.py`
  - DB 및 admin 계정 존재 여부 검사와 WIZ 모델 기반 자동 초기화를 추가했다.
  - 초기화·SQLite 오류를 사용자에게 구체적으로 안내하고 종료 코드를 반환하도록 정리했다.
- `README.md`
  - 사용자가 수정한 설치 흐름을 유지하면서 환경변수 방식과 대화형 스크립트 방식을 선택할 수 있도록 로컬 설정 절차를 명확히 했다.
  - 신규 DB에서 변경 스크립트가 자동 초기화한다는 내용을 한글·영문으로 반영했다.
- `requirements.txt`
  - README의 WIZ 버전과 달리 설치 과정에서 `season==2.5.1`로 되돌아가던 핀을 `season==2.5.2`로 맞췄다.
- `tests/test_change_admin_password_script.py`
  - DB가 없는 상태에서 초기화 후 비밀번호 변경까지 성공하는 회귀 테스트를 추가했다.
- `tests/test_readme_installation.py`
  - 현재 README의 Conda/WIZ 설치 명령, 대화형 비밀번호 변경 절차, requirements 버전 일치를 검증하도록 갱신했다.
- `devlog.md`
  - 이번 작업 요약 행을 추가했다.
- `devlog/2026-07-10/003-admin-password-db-bootstrap.md`
  - 요청 원문, 변경 내용, 검증 결과를 기록했다.

## 확인 결과

- `/root/miniconda3/envs/test-idp/bin/python -m pytest tests/test_change_admin_password_script.py tests/test_readme_installation.py -q`: `4 passed`
- 실제 현재 WIZ 프로젝트에서 초기화 함수를 실행하고 `database_has_admin: True`를 확인했다.
- `git diff --check`: 통과

## 남은 리스크

- 별도의 신규 서버에서 전체 설치 절차를 다시 수행하지는 않았다. 자동 초기화에는 `project/main/config/database.py`와 requirements 설치가 선행되어야 하며, 누락 시 스크립트가 해당 확인 항목을 오류로 안내한다.
