# GitHub 공개용 MIT 라이센스 파일 추가

## 사용자 원 요청

github에 올리기 위한 라이센스 파일을 추가해줘. MIT 라이센스로 하면 되고, 내 개인정보는 아래를 참고해줘.
email: kwon3286@season.co.kr
name: 권태욱 (Taewook Kwon)
nickname: ImuruKevol

## 변경 파일

- `LICENSE`
  - MIT License 전문 추가.
  - 저작권자 정보를 `권태욱 (Taewook Kwon, ImuruKevol) <kwon3286@season.co.kr>`로 표기.
- `tests/test_license_file.py`
  - LICENSE 파일이 MIT 문구와 요청받은 저작권자 정보를 포함하는지 확인하는 테스트 추가.
- `devlog.md`
- `devlog/2026-05-20/005-mit-license.md`

## 확인 결과

- `LICENSE` 파일이 프로젝트 루트에 새로 추가됨.
- `/root/miniconda3/envs/test-idp/bin/python -m pytest tests/test_license_file.py` 실행 결과: 1 passed.
- `git diff --check` 통과.
