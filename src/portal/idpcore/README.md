# idpcore package

test-idp의 공통 코어 패키지. SAML과 OIDC 양쪽에서 공유하는 데이터 모델과 비즈니스 로직을 제공한다.

---

## 주요 기능

- 테스트 사용자 관리 (관리자 계정 + 임시 테스트 계정)
- 속성/클레임 프리셋 관리 (SAML Attribute, OIDC Claims 템플릿)
- SAML Attribute OID 카탈로그 및 friendly name → OID URN 정규화
- 디버그 페이로드 인덱스 (Raw XML/JWT 저장 추적)
- 감사 로그 (인증·등록·삭제 이벤트 기록)

---

## DB 모델

| 테이블 | 파일 | 설명 |
| ------- | ------ | ------ |
| `idp_user` | `model/db/idp_user.py` | 테스트 사용자 계정 |
| `idp_attribute_preset` | `model/db/idp_attribute_preset.py` | 프로토콜별 속성 프리셋 |
| `idp_debug_payload` | `model/db/idp_debug_payload.py` | 디버그 Raw 데이터 인덱스 |
| `idp_audit_log` | `model/db/idp_audit_log.py` | 감사 로그 |

---

## Struct API

### 진입점

```python
core = wiz.model("portal/idpcore/struct")
```

싱글톤 인스턴스. 초기화 시 모든 테이블을 자동 생성(`create_table(safe=True)`).

### 공통 메서드

```python
core.info()               # 패키지 상태 및 테이블별 카운트
core.seed(force=False)    # 관리자 계정 + 기본 프리셋 초기화 (force=True: 기존 데이터 덮어쓰기)
core.now()                # 현재 시각 문자열 (YYYY-MM-DD HH:MM:SS)
core.hash_password(pw)    # SHA256 해시
core.normalize_json(v)    # 문자열/None → dict/list 안전 변환
core.db(name)             # ORM Wrapper 직접 접근
```

### core.user (User Sub-Struct)

```python
core.user.list(role="", orderby="created", order="ASC")
core.user.get(id=None, username=None)
core.user.create(data)           # username, password 필수
core.user.update(data, id=None, username=None)
core.user.delete(id=None, username=None)
core.user.authenticate(username, password)  # 성공 시 user dict, 실패 시 None
core.user.seed_samples(force=False)
```

### core.attribute_preset (AttributePreset Sub-Struct)

```python
core.attribute_preset.list(protocol="")
core.attribute_preset.get(id=None, protocol="", name="")
core.attribute_preset.create(data)         # protocol, name 필수
core.attribute_preset.update(data, id=None, protocol="", name="")
core.attribute_preset.delete(id=None, protocol="", name="")
core.attribute_preset.seed_defaults(force=False)
```

### core.debug_payload (DebugPayload Sub-Struct)

```python
core.debug_payload.list(protocol="", category="", target_type="", target_id="", limit=50)
core.debug_payload.get(id=None, key=None)
core.debug_payload.create(data)            # key 자동 생성 가능
core.debug_payload.update(data, id=None, key=None)
core.debug_payload.delete(id=None, key=None)
```

### core.audit (Audit Sub-Struct)

```python
core.audit.list(protocol="", action="", status="", actor_id="", target_type="", target_id="", limit=100)
core.audit.get(id)
core.audit.create(data)                    # action 필수
core.audit.log(action, **kwargs)           # 편의 메서드
core.audit.delete(id)
```

---

## Route API

| 엔드포인트 | 설명 |
| ---------- | ------ |
| `GET /api/idpcore/info` | 패키지 상태 및 카운트 |
| `GET /api/idpcore/seed` | 샘플 데이터 초기화 (admin only) |
| `GET /api/idpcore/seed-force` | 샘플 데이터 강제 초기화 (admin only, 기존 admin 비밀번호 유지) |
| `GET /api/idpcore/users` | 사용자 목록 |
| `GET /api/idpcore/saml-attribute-catalog` | 표준/커스텀 SAML OID 속성 목록 |
| `GET /api/idpcore/pysaml2-attribute-catalog` | pysaml2 기본 attribute map 기반 지원 속성 목록 |
| `GET /api/idpcore/presets?protocol=saml` | 프리셋 목록 (protocol 필터) |

---

## 관리자 계정

관리자 계정은 seed 과정에서 생성되며, 초기 비밀번호는 `TEST_IDP_ADMIN_PASSWORD` 환경 변수로 지정할 수 있다. 환경 변수가 없으면 임의의 강한 값으로 생성되므로 배포 환경에서 직접 설정하거나 관리자 화면에서 즉시 변경한다. 공개 문서에 운영 비밀번호를 기록하지 않는다.

| username | role | email |
| -------- | ---- | ----- |
| admin | admin | `admin@test-idp.local` |

## 기본 속성 프리셋

**SAML**: minimal, eduPerson-basic, eduPerson-full, custom-json  
**OIDC**: openid-basic, profile, email, groups, academic-profile

임시 계정 생성 시 test-idp 표준 SAML Attribute와 대응 OIDC Claim이 기본값으로 채워진다.
SAML preset과 사용자 `saml_attributes`는 저장 시 표준 OID URN 또는 pysaml2 attribute map의 Name으로 정규화된다. friendly name(`uid`, `mail`, `displayName`)이나 임의 커스텀 키를 넣어도 응답 생성 전 공통 카탈로그 기준으로 변환된다.

---

## 다른 패키지에서 참조

```python
# samlidp/oidcidp struct.py에서
self.core = wiz.model("portal/idpcore/struct")
self.core.user.list()
self.core.attribute_preset.list(protocol="saml")
```
