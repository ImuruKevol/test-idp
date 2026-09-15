# ReviewOps federation metadata와 Assertion 속성 누락 검증 보강

- profile별 IdP EntityDescriptor 하나를 담는 별도 federation metadata endpoint를 추가했다.
- profile 설정에 제한된 `omit_attributes` 목록을 추가하고 실제 Assertion Attribute 생성에서 제외했다.
- 기존 단일 metadata endpoint와 다른 profile의 응답 설정에는 영향을 주지 않도록 격리했다.

## 사용자 원문 요청

```text
추가로 가능하면 Debug IdP에 profile-bound federation metadata endpoint도 구현해 주세요(EntitiesDescriptor 안에 해당 profile의 EntityDescriptor 1개, 예: /api/saml/federation-metadata?reviewops_profile=...). KeyCloud의 임시 federation IdP create/filter/refresh 실제 검증에 사용하며, 기존 single metadata에는 영향 없어야 합니다. Debug IdP 테스트/build/devlog/public smoke까지 포함해 주세요.

Debug IdP profile config를 수정할 때 선택적으로 omit_attributes(SAML Attribute Name 목록, profile-local)도 지원 가능하면 추가해 주세요. KeyCloud 외부 IdP required mapping negative를 실제 Assertion 누락으로 검증한 뒤 clear할 목적입니다. 허용 길이/개수 제한과 profile isolation, 테스트/clear를 포함하세요.
```

## 변경 파일

- `src/portal/samlidp/model/struct/metadata.py`
  - profile 필수 federation XML 생성기를 추가해 `EntitiesDescriptor` 직하에 해당 profile IdP 하나만 포함했다.
  - `omit_attributes`를 최대 32개, 항목당 512자로 제한하고 중복 제거·profile 저장·clear 계약에 포함했다.
- `src/portal/samlidp/model/struct/process.py`
  - friendly name/OID/URN을 SAML catalog의 canonical Name으로 해석하고 지정 속성만 Assertion에서 제외했다.
- `src/portal/samlidp/route/saml/controller.py`
  - `/api/saml/federation-metadata` XML endpoint를 추가했다.
  - profile config의 JSON 문자열 배열 입력과 실제 브라우저 SSO·직접 응답 생성 경로 전파를 추가했다.
- `tests/test_reviewops_profiles.py`
  - 기존 response defaults 기대값에 빈 `omit_attributes` 기본 계약을 반영했다.
- `tests/test_reviewops_saml_federation_and_omit.py`
  - federation entity 단일성, 기존 metadata 불변, profile 격리·제한·clear, 실제 Assertion 누락 회귀를 추가했다.

## 확인 결과

- `/root/miniconda3/envs/test-idp/bin/python -m pytest -q tests`: `26 passed`.
- `/root/miniconda3/envs/test-idp/bin/wiz project build --project=main`: 일반 빌드 성공.
- `systemctl restart wiz.test-idp`: 재시작 후 `active` 확인.
- 공개 HTTPS에서 profile config/get, federation XML의 단일 entity·profile endpoint, 기존 single metadata 불변, clear 후 빈 목록 복귀를 확인했다.
- profile 없는 federation 요청은 WIZ 응답 `code=400`으로 거부됨을 확인했다.

## 남은 리스크

- KeyCloud의 federation create/filter/refresh와 required mapping 실패 화면까지 이어지는 종단 간 결과는 ReviewOps runner에서 최종 확인해야 한다.
- `omit_attributes`는 실제 Assertion `Attribute@Name` 기준이며, runner는 가능하면 KeyCloud mapping에 저장된 canonical URN을 전달해야 한다.
