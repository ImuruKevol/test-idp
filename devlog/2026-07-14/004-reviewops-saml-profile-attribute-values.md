# ReviewOps 프로필별 SAML 속성 값 주입 보강

- **요약**: 프로필별 `attribute_values`를 실제 SAML 인증 응답에 반영하고, OID 형식·값 개수·길이·제어 문자를 엄격히 검증했다.
- **결과**: 단일·다중 AttributeValue, 계정 값 덮어쓰기, `omit_attributes` 우선순위, 프로필 격리와 초기화를 자동 테스트 및 공개 엔드포인트에서 확인했다.
- **운영 영향**: 기존 프로필을 지정하지 않은 SAML 동작은 그대로 유지하며, 테스트 값이나 프로필 payload는 애플리케이션 로그에 기록하지 않는다.

- **ID**: 004
- **날짜**: 2026-07-14
- **유형**: 기능 추가, 테스트 보강

## 사용자 원본 요청

현재 ReviewOps 작업에서 SAML 외부 IdP mapping의 bypass/overwrite/append를 실제 인증 callback으로 검증할 수 있도록, 기존 profile-scoped `/api/saml/reviewops-profile-config`에 안전한 JSON `attribute_values`를 추가하고 프로필 격리·정규화·GET readback·clear·계약 테스트·빌드·재시작·공개 스모크까지 검증해 달라는 요청.

## 변경 내용

- `attribute_values`는 `urn:oid:<숫자 OID>` 키와 문자열 또는 문자열 배열 값만 허용한다.
- 프로필별 설정 파일에 `sign_response`, `sign_assertion`, `omit_attributes`와 함께 격리 저장하고 GET에서 동일 envelope로 조회한다.
- 실제 `/api/saml/sso` callback과 `/api/saml/sso-respond`에서 프로필 값을 Assertion Attribute에 마지막 우선순위로 적용한다.
- 동일 Attribute가 `omit_attributes`에도 있으면 누락 설정이 최종 우선한다.
- 최대 Attribute 32개, Attribute당 값 16개, 값당 2,048자 제한과 빈 값·제어 문자 거부를 적용했다.
- clear 응답과 이후 GET에서 `attribute_values: {}` 및 `configured: false` 복귀를 보장했다.

## 변경 파일

- `src/portal/samlidp/model/struct/metadata.py`: 설정 정규화, 격리 저장·조회·초기화 계약 추가
- `src/portal/samlidp/model/struct/process.py`: 실제 Assertion 생성 시 프로필 Attribute 값 반영
- `src/portal/samlidp/route/saml/controller.py`: JSON 객체 입력, SSO callback 전파, GET readback 연결
- `tests/test_reviewops_profiles.py`: 기본 응답 계약 갱신
- `tests/test_reviewops_saml_federation_and_omit.py`: 격리·제한·실제 XML 주입·우선순위 테스트 추가
- `devlog.md`: 작업 요약 행 추가

## 검증 결과

- `/root/miniconda3/envs/test-idp/bin/python -m pytest -q tests`: **27 passed**
- Python 문법 컴파일: **통과**
- WIZ 일반 빌드 `wiz project build --project=main`: **통과**
- `wiz.test-idp` 재시작 및 `systemctl is-active`: **active**
- 공개 API POST → GET readback → 잘못된 OID 거부 → clear → 기본값 복귀: **통과**
- 공개 `/api/saml/sso` 브라우저 callback에서 설정한 단일·다중 OID AttributeValue가 서명된 Assertion XML에 포함됨: **통과**
- 애플리케이션 로그에서 스모크 프로필명·테스트 AttributeValue가 기록되지 않음: **확인**

## 응답 계약

- 성공 envelope: `{"code": 200, "data": {"data": {"reviewops_profile": "...", "sign_response": true, "sign_assertion": true, "omit_attributes": [], "attribute_values": {...}, "configured": true}}}`
- 검증 실패 envelope: HTTP transport는 WIZ 규약상 200이며 본문의 `code`가 400이고 `data.message`에 거부 사유를 제공한다.
- clear envelope: `attribute_values`는 빈 객체로 복귀하고 `cleared`가 `true`가 된다.

## 남은 주의사항

- `attribute_values`는 테스트 fixture 데이터용이며 비밀번호·토큰·개인 비밀값을 입력하면 안 된다.
- Assertion raw debug XML은 기존 Debug IdP 기능에 따라 저장될 수 있으므로 실제 비밀값을 테스트 Attribute로 사용하지 않는다.
