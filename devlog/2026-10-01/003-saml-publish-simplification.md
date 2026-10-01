# SAML Publish 화면 단순화

## 사용자 원본 요청

```text
/saml/publish 화면이 너무 복잡해. 단순화해줘
```

## 변경 내용

1. 기본 화면의 목적을 `Metadata URL 연결`과 `Quick Federation 생성` 두 가지로 축소했다.
2. Metadata URL을 가장 먼저 노출하고 복사·열기 액션을 같은 카드에 배치했다.
3. SSO/SLO 수동 endpoint와 signing/encryption 인증서 상세·PEM은 접이식 영역으로 이동했다.
4. 저장된 Federation 목록은 개수만 요약하고 필요할 때 펼쳐 복사·열기·삭제하도록 변경했다.
5. 실행 설정 전체를 `고급 테스트 실행 설정`으로 접어 일반 SSO 사용자에게 기본 노출하지 않는다.
6. 원문 XML과 unsigned/bad-signature 시험을 별도 접이식 `Metadata XML·호환 시험` 영역으로 이동했다.
7. 실행 설정 alias를 선택한 경우에도 정확한 query가 포함된 `metadata_url`을 모델에서 제공한다.

## 변경 파일

- `src/portal/samlidp/app/idp.metadata/view.pug`
- `src/portal/samlidp/model/struct/metadata.py`
- `tests/test_protocol_console_ux.py`
- `devlog.md`

## 검증 결과

- `/root/miniconda3/envs/test-idp/bin/python -m pytest -q tests` → `82 passed`
- `/root/miniconda3/envs/test-idp/bin/wiz project build --project=main` → 성공
- 화면 구조 테스트에서 Metadata → Quick Federation → 고급 실행 설정 → XML 시험 순서와 접이식 구성을 검증했다.
- 서비스 재시작과 배포는 수행하지 않았다.

## 환경 메모

- WIZ MCP workspace가 current project를 존재하지 않는 `/opt/app/project/main`으로 매핑해 실제 current project인 `/root/workspace/test-idp/project/main`에서 파일 도구와 WIZ CLI로 변경·검증했다.
