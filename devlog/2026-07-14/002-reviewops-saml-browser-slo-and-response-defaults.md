- SP·IdP 시작 SLO를 POST/Redirect 실제 브라우저 왕복으로 제공하고 반환 응답을 엄격히 검증한다.
- 비로그인 IsPassive 요청에 서명된 `NoPassive` 응답을 보내며 profile별 Response/Assertion 서명 기본값을 제공한다.
- 단위 테스트 21개, WIZ 일반 빌드, 양방향 실서비스 SSO/SLO smoke를 통과했다.

# ReviewOps SAML 브라우저 SLO·응답 설정 보강

## 요청 원문

> 각 모든 설정들에 대해 임시 RP·SP·OP·IdP들로 모두 전부 실제 인증에 대한 검증을 진행해야해. 설정만 하고 인증을 진행하는지 확인해줘. 그리고 어떤 플로우의 경우는 해당 설정을 한 후 여러 검증 케이스들을 모두 확인해야하는 경우도 있고(refresh token, token-exchange 등), 여러 모든 경우의 수를 모두 검증하는지 확인하고 보강해줘. 당연하지만 표준 RFC 문서에 있는 플로우들도 모두 실제 인증 검증을 해야하고.

## 변경 파일

| 파일 | 변경 내용 |
|---|---|
| `src/portal/samlidp/model/struct/process.py` | 서명 위치·직렬화 수정, `NoPassive`, LogoutResponse 엄격 검증, Redirect 쿼리 서명 검증 |
| `src/portal/samlidp/model/struct/metadata.py` | profile별 Response/Assertion 서명 기본값 저장·조회·초기화 |
| `src/portal/samlidp/route/saml/controller.py` | SP/IdP 시작 SLO POST·Redirect 브라우저 전달, 결과 poll, profile 설정 API |
| `tests/test_reviewops_profiles.py` | profile 격리와 응답 서명 기본값 계약 |
| `tests/test_reviewops_saml_browser_flows.py` | `NoPassive`, POST/Redirect LogoutResponse 서명·상관관계 검증 |

## 확인 결과

- `/root/miniconda3/envs/test-idp/bin/python -m pytest -q tests/test_reviewops_profiles.py tests/test_reviewops_saml_browser_flows.py`: `21 passed`.
- `/root/miniconda3/envs/test-idp/bin/wiz project build --project=main`: 일반 빌드 성공.
- 실제 브라우저에서 SAML SSO와 SP 시작 SLO POST/Redirect, IdP 시작 SLO POST/Redirect, 로그아웃 후 `NoPassive`를 확인했다.
- IdP 시작 POST LogoutResponse의 XML 서명과 Redirect LogoutResponse의 쿼리 서명을 각각 검증했다.
- Response/Assertion 서명 조합을 실제 인증으로 실행해 Response 서명 조합은 성공하고 unsigned Response 조합은 Debug SP 정책에 따라 거부되는 것을 확인했다.

## 남은 위험

- Debug SP는 현재 Response 서명을 필수로 검증하므로 Assertion만 서명한 응답도 거부한다. Assertion-only 허용 시나리오는 별도 SP 정책 profile이 필요하다.
- Assertion 암호화 응답 생성 기능은 이번 Debug IdP 보강 범위에 포함하지 않았으며 KeyCloud IdP의 암호화 설정으로 검증한다.
