# Quick Federation과 SAML metadata credential 보강

## 사용자 원본 요청

```text
Federatino IdP 기능에 대해서는 최대한 간편하게 여러 개의 IdP를 만들고 묶어서 구성할 수 있도록 해줘. 어차피 동작을 확인하는게 우선이야.

그리고 메타데이터의 sign, encrypt 각각의 인증서에 대한 기능, 표준을 확실하게 확인하고 보강해줘.
```

## 표준 확인

- OASIS SAML 2.0 Metadata 및 Metadata Interoperability Profile의 `KeyDescriptor`/`use`/X.509 key-container 규칙을 확인했다.
- SAML Metadata Profile for Algorithm Support의 content encryption과 key transport algorithm 게시·선호 순서 규칙을 확인했다.
- W3C XML Signature 1.1과 XML Encryption 1.1의 RSA-OAEP Digest/MGF 기본값, AES-GCM, RSA1_5 보안 경계를 확인했다.

## 구현 내용

1. Publish 화면에 이름, IdP 개수, 기본 IdP 포함 여부와 `standard`/`encrypted`/`mixed` 프리셋만으로 최대 20개 IdP alias와 이름 있는 Federation 묶음을 만드는 Quick Federation UI/API를 추가했다.
2. 묶음별 `?federation=<name>` metadata URL, 목록·복사·열기·묶음 삭제를 제공한다. 묶음 삭제 시 alias 설정은 보존해 재조합할 수 있다.
3. 같은 이름으로 빠른 생성을 다시 실행하면 alias 개수와 프리셋을 재구성하도록 했다.
4. 기존 signing key를 보존하면서 별도 RSA encryption keypair를 생성하고 KeyUsage를 목적에 맞게 제한했다. Metadata에는 각각 독립된 `KeyDescriptor use="signing"`/`use="encryption"`로 게시한다.
5. IdP 수신 capability에는 실제 구현한 AES-128/192/256-GCM과 RSA-OAEP만 게시하고, 현대 OAEP URI에 SHA-256 Digest/MGF1-SHA256 파라미터를 명시했다.
6. LogoutRequest `EncryptedID`를 IdP encryption private key로 복호화한다. RSA-OAEP 1.1의 생략된 Digest/MGF는 표준 기본값 SHA-1/MGF1-SHA1로 처리하고, 구형 `rsa-oaep-mgf1p`의 고정 MGF 규칙을 적용한다. 내장 및 형제 `EncryptedKey`를 모두 지원한다.
7. SP metadata의 signing/encryption certificate와 `EncryptionMethod`를 역할별로 파싱·보존한다. 비-RSA encryption key, 약한 키, `use` 생략, 동일 키 재사용을 진단한다.
8. Publish 화면에 두 인증서의 용도, fingerprint, key type/size, 유효기간과 PEM을 각각 표시한다.

## 변경 파일

- `README.md`, `docs/standards-compliance.md`, `devlog.md`
- `src/portal/samlidp/README.md`
- `src/portal/samlidp/app/idp.metadata/{api.py,view.pug,view.ts}`
- `src/portal/samlidp/app/sp.register/view.pug`
- `src/portal/samlidp/model/struct/{metadata,process,registry}.py`
- `src/portal/samlidp/route/saml/controller.py`
- `tests/test_modernization_protocol_features.py`
- `tests/test_reviewops_profiles.py`
- `tests/test_reviewops_saml_federation_and_omit.py`
- `tests/test_standards_completion.py`

## 검증 결과

- `/root/miniconda3/envs/test-idp/bin/python -m pytest -q tests` → `81 passed`
- 실제 RSA keypair로 signing/encryption 공개키 분리와 encryption KeyUsage를 검증했다.
- Federation aggregate root signature와 이름별 entity 집계, 프리셋 재구성을 검증했다.
- OASIS SAML Metadata XSD와 XML Encryption 1.1 XSD를 함께 로드해 생성 metadata의 schema 적합성을 검증했다.
- RSA-OAEP SHA-256 명시형, XML Encryption 기본 SHA-1 생략형, 구형 `rsa-oaep-mgf1p` 및 EncryptedKey 두 배치를 검증했다.
- `/root/miniconda3/envs/test-idp/bin/python -m compileall -q src tests` → 통과
- `git diff --check` → 통과
- `/root/miniconda3/envs/test-idp/bin/wiz project build --project=main` → 성공
- 서비스 재시작과 배포는 수행하지 않았다.

## 운영 경계

- debug IdP의 자동 인증서 rollover orchestration은 구현하지 않았다. federation 소비자와의 trust-anchor 변경은 별도 운영 절차가 필요하다.
- X.509 certificate의 날짜/path/revocation은 metadata 수신 후 TLS PKI처럼 재평가하지 않는다. 신뢰된 metadata 서명과 `validUntil`이 배포 신뢰 경계다.
- WIZ MCP workspace가 current project를 존재하지 않는 `/opt/app/project/main`으로 매핑해 실제 current project인 `/root/workspace/test-idp/project/main`에서 파일 도구와 WIZ CLI로 구현·검증했다.
