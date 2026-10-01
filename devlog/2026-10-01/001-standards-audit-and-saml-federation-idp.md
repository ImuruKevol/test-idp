# OIDC·SAML 표준 전수 감사와 SAML Federation IdP 보강

## 사용자 원본 요청

```text
이 서비스는 각종 SP/RP들을 검증할 수 있는 디버깅용 IdP야. 일단 이 IdP에서 제공하는 기능들을 전수조사해서 표준 RFC, 표준 프로필 등에 문제되는 기능은 없는지, 없는 기능은 없는지 분석하고 보강해줘.

그리고 나서 이 서비스 자체에서 SAML Federation IdP 기능을 제공할 수 있도록 해줘.
```

## 조사 기준

- OpenID Connect Core/Discovery/RP-Initiated Logout
- RFC 6749, 7523, 7636, 9207, 9700
- OASIS SAML 2.0 Core, Bindings, Profiles, Metadata 및 Metadata Interoperability Profile
- XML Signature 1.1, XML Encryption 1.1
- 실제 route, Discovery/Metadata 광고값, RP/SP registry 선택지, 정상/호환 실행 설정, 전체 자동 테스트

## 구현 내용

1. OIDC Discovery와 RP 등록 기능을 실제 endpoint 구현에 맞췄다. 정상 프로필은 Authorization Code, Refresh Token, PKCE S256 및 실제 response mode만 광고하며 미구현 implicit/hybrid/client credentials 등록을 거부한다.
2. `offline_access` + 명시적 consent에 대해 refresh token을 발급하고, 축소 scope 교환, 1회 회전, 원자적 동시 사용 차단, 재사용 탐지 시 하위 token 계열 폐기를 구현했다.
3. 검증된 redirect URI로 authorize 오류를 전달하고 consent 승인/거부 화면 흐름을 보강했다.
4. SP metadata의 중복 ID, SAML 2.0 protocol, POST ACS Binding/index/isDefault, 중첩 aggregate `validUntil` 상속 및 signature scope를 검증한다.
5. IdP metadata에 `validUntil`/`cacheDuration`을 추가하고 SAML metadata media type, ETag/304, bounded cache를 적용했다.
6. 기본 IdP와 저장된 실행 설정별 alias를 모아 root 하나에 서명하는 Federation `EntitiesDescriptor` feed와 federation-info API를 구현했다. entity 상한, profile filter, trust-anchor certificate fingerprint 및 Publish UI를 추가했다.
7. 구현 범위, 호환 시험 기능, 의도적인 미지원 선택 프로필과 운영상 신뢰 경계를 표준 준수 문서에 기록했다.

## 변경 파일

- `README.md`, `docs/standards-compliance.md`
- `src/portal/oidcidp/README.md`
- `src/portal/oidcidp/model/db/oidc_token_log.py`
- `src/portal/oidcidp/model/struct.py`
- `src/portal/oidcidp/model/struct/{flow,provider,registry}.py`
- `src/portal/oidcidp/route/oidc/controller.py`
- `src/portal/samlidp/README.md`
- `src/portal/samlidp/app/idp.metadata/view.pug`
- `src/portal/samlidp/model/struct/{metadata,process,registry}.py`
- `src/portal/samlidp/route/saml/controller.py`
- `tests/test_reviewops_saml_federation_and_omit.py`
- `tests/test_standards_completion.py`
- 로컬 `config/idp.py`(Git 제외): metadata validity/cache/federation name 운영값

## 검증 결과

- 기준선 전체 테스트: `68 passed`
- 최종 전체 테스트: `/root/miniconda3/envs/test-idp/bin/python -m pytest -q tests` → `75 passed`
- Python compileall: 통과
- `git diff --check`: 통과
- `/root/miniconda3/envs/test-idp/bin/wiz project build --project=main`: 성공
- 실제 RSA 인증서로 Federation aggregate root signature 검증, child 무서명, 만료/cache 속성 및 base+alias 집계를 자동 테스트했다.
- refresh token 회전, 재사용 거부와 하위 token 폐기, 미구현 RP flow 거부, SP metadata protocol/Binding/상위 만료 검증을 자동 테스트했다.
- 서비스 재시작과 배포는 수행하지 않았다.

## 남은 운영 경계

- 외부 상용 SP/RP 및 federation 운영자와의 실제 브라우저 상호운용 시험은 배포 환경에서 별도로 수행해야 한다.
- 자동 key rollover, MDQ, registration authority/entity category 정책, Artifact/ECP, OIDC PAR/JAR/JARM/DPoP/mTLS 등은 현재 범위 밖이며 Discovery/Metadata에서 지원 기능으로 광고하지 않는다.
- WIZ MCP가 현재 프로젝트를 존재하지 않는 `/opt/app/project/main`으로 매핑하여 파일 API는 사용할 수 없었고, 실제 current project인 `/root/workspace/test-idp/project/main`에서 파일 도구와 WIZ CLI로 구현·검증했다.
