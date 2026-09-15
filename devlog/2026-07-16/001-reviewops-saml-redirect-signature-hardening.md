- 결과: OASIS SAML 2.0 HTTP-Redirect 바인딩의 URL 인코딩 원문 서명 규칙을 적용하고, SP·IdP 시작 SLO를 HTTP-POST와 HTTP-Redirect 모두 실제 브라우저로 왕복하도록 보강했다.
- 격리: ReviewOps profile별 signing/attribute 설정과 임시 SP를 분리해 운영 기본값을 오염시키지 않고 각 variant를 실제 Assertion·Logout 메시지로 검증한다.
- 검증: Debug IdP 테스트 29건, 운영 KeyCloud SAML 고정 회귀 15/15, WIZ 빌드·재시작·HTTP 200을 확인했다.

# ReviewOps SAML Redirect 원문 서명과 SLO 바인딩 보강

## 작업 정보

| 항목 | 내용 |
| --- | --- |
| 날짜 | 2026-07-16 |
| ID | 001 |
| 리뷰 ID | `fygelmwdjvbdvvocsaxcisplmchawhrh` |
| 대상 | `https://debug-idp.nanoha.kr` |
| 기준 | OASIS SAML 2.0 Bindings 3.4.4.1, Profiles 4.4, Core |

## 원문 요청사항

```text
기존 결함은 알면서 왜 안고쳐? RFC 표준 문서, OASIS 표준 프로필 등을 참고하여 결함을 수정해줘.
Debug SP, Debug IdP 수정이 필요하면 .codex/AGENTS.md를 참고해서 직접 수정하면 돼.

그리고 뭔가 진행이 되고 있으면 콘솔에 뭐라도 표시를 해서 진행이 되고 있다는걸 알려줘야 해.
```

## 변경 내용

- HTTP-Redirect LogoutRequest/LogoutResponse를 DEFLATE·Base64 처리하고 `SAMLRequest` 또는 `SAMLResponse`, 선택적 `RelayState`, `SigAlg`의 정확한 URL 인코딩 octet string 순서로 RSA-SHA256 서명한다.
- 수신 Redirect LogoutResponse는 파싱 후 재인코딩한 값이 아니라 실제 raw query substring을 사용해 서명을 검증하고, 누락·변조·잘못된 issuer·destination·InResponseTo·RelayState를 거부한다.
- HTTP-POST는 XML Signature와 Reference digest를 검증하고, Redirect는 query signature를 검증하도록 바인딩별 책임을 분리했다.
- IdP 시작 SLO는 선택한 바인딩으로 실제 LogoutRequest를 전송하고 돌아온 LogoutResponse 검증 결과를 브라우저 화면과 API 증적으로 남긴다.
- SP 시작 SLO는 요청 바인딩에 맞춰 서명된 Success LogoutResponse를 POST form 또는 Redirect URL로 반환한다.
- IsPassive에 인증 세션이 없으면 로그인 화면 대신 서명된 `Responder/NoPassive` Response를 반환하며, ForceAuthn은 기존 세션 재사용을 막는다.
- ReviewOps profile별 Response/Assertion 서명, Attribute 누락·값 override, 임시 SP·federation metadata를 격리하고 cleanup API로 제거한다.
- SAML IssueInstant·Conditions 계산의 UTC 시각을 timezone-aware 값으로 생성해 Python 3.14 deprecation warning과 향후 호환성 위험을 제거했다.

## 변경 파일

- `src/portal/samlidp/model/struct/metadata.py`
- `src/portal/samlidp/model/struct/process.py`
- `src/portal/samlidp/route/saml/controller.py`
- `tests/test_reviewops_saml_browser_flows.py`
- `tests/test_reviewops_saml_federation_and_omit.py`
- `devlog.md`
- `devlog/2026-07-16/001-reviewops-saml-redirect-signature-hardening.md`

## 확인 결과

| 확인 항목 | 결과 |
| --- | --- |
| Python 테스트 | 29 passed, warning 없음 |
| 운영 SAML 고정 회귀 | 15/15 통과, POST·Redirect SLO와 Passive-after-logout 포함 |
| 전체 headed 연동 | KeyCloud 설정 121/121, 실제 플로우 22/22 통과 |
| 임시 데이터 | Debug IdP ReviewOps OIDC RP·SAML SP 각 0건 |
| 형식 검사 | `git diff --check` 통과 |
| WIZ 빌드 | 일반 빌드 성공 |
| 서비스 | `wiz.test-idp` active, 공개 HTTP 200 |

## 남은 리스크

- ReviewOps profile API는 테스트 전용 공개 endpoint이므로 profile 이름을 추측할 수 있더라도 운영 기본 설정과 분리된 상태를 계속 유지해야 한다.
