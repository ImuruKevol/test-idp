# admin 계정 패스워드 갱신

- 날짜: 2026-08-18
- ID: 001
- 요청: "이 서비스의 admin 계정 패스워드를 지정한 값으로 바꿔줘" (민감값 마스킹)

## 변경 파일

- `project/main/data/idpcore.db`
- `project/main/devlog.md`
- `project/main/devlog/2026-08-18/001-admin-password-update.md`

## 작업 내용

- `project/main/scripts/change_admin_password.py`를 실행해 `idp_user.username = 'admin'` 행의 `password_hash`를 새 값의 SHA256 해시로 갱신했다.
- 비밀번호 원문은 문서에 기록하지 않았다.

## 검증

- 변경 스크립트가 `[OK] admin 패스워드가 변경되었습니다.`로 종료됨을 확인했다.
- `project/main/data/idpcore.db`에서 admin 계정의 `password_hash`가 입력값의 SHA256 해시와 일치함을 별도 검증 스크립트로 확인했다.
