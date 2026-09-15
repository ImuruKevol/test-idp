# OIDC end_session과 SAML SLO 표준 흐름 보강

## 작업 정보

| 항목 | 내용 |
| --- | --- |
| 날짜 | 2026-09-15 |
| 리뷰 ID | `kqlabukdqlnoqctcbhrcbjdtnpssffou` |
| 선택 AI 모델 | `gpt-5.6-sol` |
| 실제 AI 모델 | `gpt-5.6-sol` |
| 추론 수준 | `xhigh` |

## 사용자 원본 요청

```text
end_session이라던가 slo라던가도 제대로 지원하도록 해줘
```

## 참고 자료

- OpenID Connect RP-Initiated Logout 1.0: end_session 요청값, 사용자 확인, callback 정확 일치, state 반환 기준.
- OASIS SAML 2.0 Profiles/Bindings: SLO SessionIndex, 메시지 무결성, HTTP-POST/HTTP-Redirect, RelayState, DEFLATE 및 query signature 기준.
- 기존 OIDC·SAML registry, 세션, 실제 route, 로그아웃 확인 화면과 회귀 테스트.

## 작업 정의 및 주요 개발 항목

1. OIDC end_session 요청을 GET/POST로 받고 `id_token_hint`, `logout_hint`, `client_id`, `post_logout_redirect_uri`, `state`, `ui_locales`를 검증한다.
2. 등록 callback만 사용하고 사용자 확인 후 IdP 세션을 종료한다. 신뢰하지 못한 힌트와 callback은 복귀에 사용하지 않는다.
3. SAML SLO에서 SP·IdP 시작 흐름, Binding별 endpoint와 ResponseLocation, 요청·응답 검증, 연결 세션 종료를 보강한다.
4. HTTP-Redirect 전송 시 XML signature를 제거하고 DEFLATE 후 query signature를 적용한다.
5. 비표준 SLO 입력은 호환 시험 표시와 경고를 제공한다.

## 파일 변경

- `src/portal/oidcidp/model/struct/flow.py`, `preview.py`, `route/oidc/controller.py`: end_session 검증, 확인 화면, 안전한 redirect와 세션 종료.
- `src/portal/oidcidp/app/logout.check/*`, `README.md`: logout_hint/ui_locales 입력과 실제 end_session 열기, 사용법 반영.
- `src/portal/samlidp/model/struct/process.py`, `registry.py`, `route/saml/controller.py`: SLO endpoint 선택, signature·시간·RelayState 검증, 유효 응답 이후 세션 종료.
- `src/portal/samlidp/app/logout.check/*`, `app/sp.register/view.pug`, `README.md`: Binding 선택, SP 전송, ResponseLocation 및 호환 상태 표시.
- `tests/test_reviewops_logout_protocols.py`, `tests/test_reviewops_saml_browser_flows.py`, `tests/test_modernization_protocol_features.py`: end_session·SLO 회귀 검사.

## 검증 및 배포 결과

- 대상 테스트: `33 passed`.
- 전체 테스트: `62 passed`.
- Python 문법 검사와 `git diff --check`: 통과.
- `wiz project build --project=main`: 일반 빌드 성공.
- 공개 OIDC logout 확인 화면, discovery의 `end_session_endpoint`, SAML Metadata의 HTTP-POST/HTTP-Redirect SLO endpoint를 확인했다.
- 서비스 캐시를 안전한 GET 요청으로 갱신했으며 서비스 재시작과 별도 배포는 수행하지 않았다.

## 남은 리스크

- 실제 외부 RP/SP를 사용한 브라우저 전체 왕복은 수행하지 않았다.
- Front-Channel Logout 및 Back-Channel Logout은 이번 RP-Initiated Logout 범위에 포함하지 않았다.
