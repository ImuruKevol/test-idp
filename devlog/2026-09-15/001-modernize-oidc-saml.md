# OIDC·SAML 표준 기능과 운영 화면 보강

## 작업 정보

| 항목 | 내용 |
| --- | --- |
| 날짜 | 2026-09-15 |
| 리뷰 ID | `kqlabukdqlnoqctcbhrcbjdtnpssffou` |
| 실제 AI 모델 | `gpt-5.6-sol` |
| 추론 수준 | `xhigh` |

## 사용자 원본 요청

```text
아래 사항들을 준수하여 작업 시작.

- 불필요한 설명은 자제할 것.
- 가독성 및 UX를 최우선으로 생각하여 화면을 구성할 것.
- 쓸데없이 어려운 "계약", "게이트" 등 단어는 절대 쓰지 말되, SAML, OIDC에서 고유 단어들은 그대로 사용해야 함.
```

## 참고 자료

- `debug-idp-modernization-checklist-2026-09-15.md`: 프로필 격리, OIDC OP, SAML IdP, 오류 변형, SLO, 암호화, 외부 연동 점검 목록.
- RFC 7523·7636·8725, OpenID Connect Core/RP-Initiated Logout, OASIS SAML 2.0, XML Encryption 1.1을 구현 기준으로 확인했다.

## 작업 정의 및 주요 개발 항목

1. OIDC client 인증 5종, PKCE S256, JWT assertion 검증·재사용 방지, ID Token/JWKS 알고리즘과 Claim을 보강했다.
2. 실행별 Claim·subject·시간·오류 변형과 Discovery 변형을 제공하고, 표준 방식과 호환 방식을 상세 화면에서 구분했다.
3. SAML Metadata 서명·조직/담당자·AlgorithmSupport, AuthnRequest/SLO 검증, 서명된 Assertion 암호화를 보강했다.
4. 민감값 기본 숨김, 1회 secret 표시, 관리자 전용 원문 조회, 가독성 중심 설정 화면을 적용했다.
5. 프로토콜 회귀 테스트와 WIZ 일반 빌드를 실행했다.

## 파일 변경

- `src/portal/oidcidp/model/struct/{provider,registry,flow,preview}.py`: OIDC 키·토큰·client 인증·프로필·민감값 처리.
- `src/portal/oidcidp/route/{oidc,oidc-discovery}/controller.py`: authorize/token/userinfo/logout/discovery 흐름과 프로필 API.
- `src/portal/oidcidp/app/{provider.publish,rp.register,authorize.check,logout.check}/`: 표준/호환 표시, 설정·상세 UI, 민감값 숨김.
- `src/portal/oidcidp/README.md`: 운영 화면 설명 용어 정리.
- `src/portal/samlidp/model/struct/{metadata,registry,process}.py`: Metadata, SP 인증서, 요청 검증, Response/EncryptedAssertion/SLO.
- `src/portal/samlidp/route/saml/controller.py`: 브라우저 SSO/SLO, 프로필·Metadata API, 관리자 원문 조회.
- `src/portal/samlidp/app/{idp.metadata,login.check,logout.check,sp.register}/`: SAML 설정·결과·호환성 UI.
- `tests/test_modernization_protocol_features.py`: OIDC JWT/PKCE/서명, SAML Metadata/암호화/SLO 검증 회귀.
- `tests/test_reviewops_profiles.py`: Metadata endpoint 순서 기대값 갱신.

## 검증 및 배포 결과

- `/root/miniconda3/envs/test-idp/bin/python -m pytest -q tests`: `39 passed`.
- 변경 Python 파일 `py_compile`: 통과.
- `git diff --check`: 통과.
- OIDC/SAML 화면 소스의 금지 용어 검색: 없음.
- `wiz project build --project=main`: 일반 빌드 성공.
- SAML Metadata XML Signature, EncryptedAssertion 7×3 알고리즘 조합, SLO 서명 필수/호환 허용을 자동 테스트로 확인했다.
- 배포·서비스 재시작은 수행하지 않았다.

## 남은 리스크

- 공개 URL은 현재 실행 중인 이전 런타임을 가리켜 이번 빌드 결과가 반영되지 않았다.
- KeyCloud callback, 교차 프로토콜, 외부 연쇄 로그아웃, key rollover, 3회 반복·2개 프로필 병렬 실행은 실제 외부 환경에서 확인하지 않았다.
- 비표준 호환 방식은 상세 화면에 표시하지만 운영 사용 여부는 관리자가 판단해야 한다.
