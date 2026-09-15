- 변경: OIDC ID Token·Access Token의 `iat`·`exp`를 서버 시간대와 무관한 Unix epoch로 발급하도록 수정했다.
- 원인: KST 서버에서 naive `utcnow().timestamp()`가 UTC 시각을 다시 현지 시각으로 해석해 토큰이 9시간 전에 발급된 것으로 기록됐다.
- 검증: 고정 epoch를 사용한 회귀 테스트로 두 토큰의 발급·만료 시각을 확인한다.

# OIDC 토큰 epoch 시간대 오류 수정

## 요청 내용

ReviewOps 실서비스 인증에서 Debug IdP가 발급한 ID Token이 즉시 만료된 것으로 거부되는 결함을 RFC·OIDC 규격에 맞게 수정한다.

## 변경 파일

- `src/portal/oidcidp/model/struct/provider.py`
- `tests/test_reviewops_profiles.py`
- `devlog.md`

## 확인 결과

- `time.time()` 기반 NumericDate를 사용해 서버의 `TZ` 설정과 무관하게 `iat`와 `exp`가 계산된다.
- ID Token 600초, Access Token 3600초 TTL 회귀 테스트를 추가했다.
