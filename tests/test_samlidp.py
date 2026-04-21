"""Tests for samlidp package: SP registration, IdP metadata, SSO flow."""
import base64
import datetime
import json
import re
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from conftest import WizClient, ADMIN_SESSION


SAMPLE_SP_XML = """<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://pytest-sp.example.com/metadata">
  <md:SPSSODescriptor
      AuthnRequestsSigned="true"
      WantAssertionsSigned="true"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://pytest-sp.example.com/acs"
        index="0"
        isDefault="true"/>
    <md:SingleLogoutService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://pytest-sp.example.com/slo"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>"""


SAMPLE_AUTHN_REQUEST = """<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_pytest_req_001"
    Version="2.0"
    IssueInstant="2026-03-31T12:00:00Z"
    AssertionConsumerServiceURL="https://pytest-sp.example.com/acs"
    Destination="https://idp.test-idp.local/api/saml/sso">
  <saml:Issuer>https://pytest-sp.example.com/metadata</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
</samlp:AuthnRequest>"""


UID_URN = "urn:oid:0.9.2342.19200300.100.1.1"
MAIL_URN = "urn:oid:0.9.2342.19200300.100.1.3"
DISPLAY_NAME_URN = "urn:oid:2.16.840.1.113730.3.1.241"


@pytest.fixture
def client():
    return WizClient(session_data=ADMIN_SESSION)


@pytest.fixture
def anon_client():
    return WizClient()


def _get_admin_user_id(client):
    resp = client.route("/api/idpcore/user", data={"username": "admin"})
    body = client.assert_ok(resp)
    return body["data"]["data"]["id"]


def _get_saml_preset_id(client, name="minimal"):
    resp = client.route("/api/idpcore/presets", data={"protocol": "saml"})
    body = client.assert_ok(resp)
    preset = next(p for p in body["data"]["data"] if p["name"] == name)
    return preset["id"]


def _ensure_sample_sp(client):
    resp = client.app_api("portal.samlidp.sp.register", "register", {"xml": SAMPLE_SP_XML})
    client.assert_ok(resp)


def _extract_hidden_input_value(html_text, name):
    match = re.search(rf'name="{re.escape(name)}" value="([^"]*)"', html_text)
    assert match is not None, f"{name} hidden input not found"
    return match.group(1)


def _extract_sso_prompt_state(html_text):
    keys = [
        "transaction_id",
        "sp_entity_id",
        "acs_url",
        "request_id",
        "relay_state",
        "nameid_format",
        "preset_id",
        "sign_response",
        "sign_assertion",
        "session_index",
    ]
    return {key: _extract_hidden_input_value(html_text, key) for key in keys}


class TestIdpMetadata:
    """Test IdP metadata generation and info."""

    def test_metadata_xml(self, anon_client):
        """IdP 메타데이터 XML 조회"""
        resp = anon_client.route("/api/saml/metadata")
        assert resp.status_code == 200
        assert "EntityDescriptor" in resp.text
        assert "IDPSSODescriptor" in resp.text
        assert "SingleSignOnService" in resp.text

    def test_metadata_contains_signing_cert(self, anon_client):
        """메타데이터에 서명 인증서 포함"""
        resp = anon_client.route("/api/saml/metadata")
        assert "X509Certificate" in resp.text
        assert "KeyDescriptor" in resp.text

    def test_idp_info_json(self, anon_client):
        """IdP 정보 JSON 조회"""
        resp = anon_client.route("/api/saml/idp-info")
        body = anon_client.assert_ok(resp)
        info = body["data"]["data"]
        assert "entity_id" in info
        assert "sso_post" in info
        assert "slo_post" in info
        assert "certificate" in info

    def test_idp_entity_id_format(self, anon_client):
        """EntityID가 메타데이터 URL 형식"""
        resp = anon_client.route("/api/saml/idp-info")
        body = anon_client.assert_ok(resp)
        entity_id = body["data"]["data"]["entity_id"]
        assert "/api/saml/metadata" in entity_id


class TestSPRegistration:
    """Test SP metadata registration."""

    def test_register_sp(self, client):
        """SP 메타데이터 등록"""
        resp = client.app_api("portal.samlidp.sp.register", "register", {
            "xml": SAMPLE_SP_XML,
        })
        body = client.assert_ok(resp)
        sp = body["data"]["data"]
        assert sp["entity_id"] == "https://pytest-sp.example.com/metadata"
        assert len(sp["acs_url"]) > 0
        assert sp["acs_url"][0]["location"] == "https://pytest-sp.example.com/acs"
        assert "expires" in sp
        assert sp["expires"] is not None, "SP registration should have expires timestamp"

    def test_sp_list(self, client):
        """등록된 SP 목록 조회"""
        resp = client.app_api("portal.samlidp.sp.register", "list")
        body = client.assert_ok(resp)
        sps = body["data"]["data"]
        assert isinstance(sps, list)
        found = [s for s in sps if s["entity_id"] == "https://pytest-sp.example.com/metadata"]
        assert len(found) >= 1

    def test_sp_get(self, client):
        """SP 상세 조회"""
        resp = client.app_api("portal.samlidp.sp.register", "list")
        body = client.assert_ok(resp)
        sp = next(s for s in body["data"]["data"]
                  if s["entity_id"] == "https://pytest-sp.example.com/metadata")

        resp = client.app_api("portal.samlidp.sp.register", "get", {"id": sp["id"]})
        body = client.assert_ok(resp)
        detail = body["data"]["data"]
        assert detail["entity_id"] == "https://pytest-sp.example.com/metadata"

    def test_sp_list_via_route(self, client):
        """Route API로 SP 조회"""
        resp = client.route("/api/saml/sp-list")
        body = client.assert_ok(resp)
        sps = body["data"]["data"]
        assert isinstance(sps, list)

    def test_sp_list_has_expires(self, client):
        """SP 목록에 expires 필드 포함"""
        resp = client.app_api("portal.samlidp.sp.register", "list")
        body = client.assert_ok(resp)
        sps = body["data"]["data"]
        for sp in sps:
            assert "expires" in sp, f"SP {sp.get('entity_id')} missing expires field"

    def test_sp_cleanup_expired_route(self, client):
        """만료 SP 클린업 엔드포인트"""
        resp = client.route("/api/saml/sp-cleanup-expired")
        body = client.assert_ok(resp)
        assert "deleted" in body["data"]["data"]

    def test_sp_delete(self, client):
        """SP 삭제 후 재등록 (cleanup)"""
        # 먼저 목록에서 pytest-sp 찾기
        resp = client.app_api("portal.samlidp.sp.register", "list")
        body = client.assert_ok(resp)
        pytest_sps = [s for s in body["data"]["data"]
                      if "pytest-sp" in s.get("entity_id", "")]
        for sp in pytest_sps:
            client.app_api("portal.samlidp.sp.register", "delete", {"id": sp["id"]})

        # 재등록    
        resp = client.app_api("portal.samlidp.sp.register", "register", {
            "xml": SAMPLE_SP_XML,
        })
        client.assert_ok(resp)

    def test_sp_extend_validity_and_set_unlimited(self, client):
        xml_string = SAMPLE_SP_XML.replace(
            "https://pytest-sp.example.com/metadata",
            "https://pytest-sp-validity.example.com/metadata",
        ).replace(
            "https://pytest-sp.example.com/acs",
            "https://pytest-sp-validity.example.com/acs",
        ).replace(
            "https://pytest-sp.example.com/slo",
            "https://pytest-sp-validity.example.com/slo",
        )

        resp = client.app_api("portal.samlidp.sp.register", "register", {"xml": xml_string})
        body = client.assert_ok(resp)
        sp = body["data"]["data"]
        original_expires = datetime.datetime.fromisoformat(sp["expires"])

        try:
            resp = client.app_api("portal.samlidp.sp.register", "extend_validity", {
                "id": sp["id"],
                "ttl_hours": "24",
            })
            body = client.assert_ok(resp)
            extended = body["data"]["data"]
            extended_expires = datetime.datetime.fromisoformat(extended["expires"])
            assert extended_expires > original_expires

            resp = client.app_api("portal.samlidp.sp.register", "set_unlimited", {"id": sp["id"]})
            body = client.assert_ok(resp)
            unlimited = body["data"]["data"]
            assert unlimited["expires"] is None
        finally:
            client.app_api("portal.samlidp.sp.register", "delete", {"id": sp["id"]})


class TestSSOFlow:
    """Test SAML SSO flow: parse AuthnRequest → build SAMLResponse."""

    def test_parse_authn_request(self, client):
        """AuthnRequest 파싱"""
        encoded = base64.b64encode(SAMPLE_AUTHN_REQUEST.encode("utf-8")).decode("utf-8")
        resp = client.app_api("portal.samlidp.login.check", "parse_request", {
            "SAMLRequest": encoded,
            "binding": "POST",
            "RelayState": "test_relay_state",
        })
        body = client.assert_ok(resp)
        parsed = body["data"]["data"]
        assert parsed["request_id"] == "_pytest_req_001"
        assert parsed["issuer"] == "https://pytest-sp.example.com/metadata"
        assert parsed["acs_url"] == "https://pytest-sp.example.com/acs"
        assert parsed["relay_state"] == "test_relay_state"
        assert parsed["nameid_format"] == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

    def test_build_response(self, client):
        """SAMLResponse 생성"""
        # AuthnRequest 파싱
        encoded = base64.b64encode(SAMPLE_AUTHN_REQUEST.encode("utf-8")).decode("utf-8")
        resp = client.app_api("portal.samlidp.login.check", "parse_request", {
            "SAMLRequest": encoded,
            "binding": "POST",
            "RelayState": "test_relay",
        })
        parsed = client.assert_ok(resp)["data"]["data"]

        admin_id = _get_admin_user_id(client)
        preset_id = _get_saml_preset_id(client, "minimal")

        resp = client.app_api("portal.samlidp.login.check", "build_response", {
            "user_id": admin_id,
            "sp_entity_id": parsed["issuer"],
            "acs_url": parsed["acs_url"],
            "request_id": parsed["request_id"],
            "relay_state": parsed["relay_state"],
            "transaction_id": parsed["transaction_id"],
            "nameid_format": parsed["nameid_format"],
            "preset_id": preset_id,
            "sign_response": "true",
            "sign_assertion": "true",
        })
        body = client.assert_ok(resp)
        result = body["data"]["data"]

        # Response XML 검증
        assert result["response_xml"]
        assert "<samlp:Response" in result["response_xml"]
        assert "<saml:Assertion" in result["response_xml"]
        assert "admin@test-idp.local" in result["response_xml"]  # NameID

        # Base64 인코딩
        assert result["response_b64"]
        decoded = base64.b64decode(result["response_b64"]).decode("utf-8")
        assert "<samlp:Response" in decoded

        # 메타데이터
        assert result["nameid_value"] == "admin@test-idp.local"
        assert result["signed_response"] is True
        assert result["signed_assertion"] is True
        assert result["session_index"]
        assert result["acs_url"] == "https://pytest-sp.example.com/acs"

    def test_response_contains_attributes(self, client):
        """Response에 Attribute 포함 확인"""
        encoded = base64.b64encode(SAMPLE_AUTHN_REQUEST.encode("utf-8")).decode("utf-8")
        resp = client.app_api("portal.samlidp.login.check", "parse_request", {
            "SAMLRequest": encoded, "binding": "POST",
        })
        parsed = client.assert_ok(resp)["data"]["data"]

        admin_id = _get_admin_user_id(client)
        preset_id = _get_saml_preset_id(client, "minimal")

        resp = client.app_api("portal.samlidp.login.check", "build_response", {
            "user_id": admin_id,
            "sp_entity_id": parsed["issuer"],
            "acs_url": parsed["acs_url"],
            "request_id": parsed["request_id"],
            "transaction_id": parsed["transaction_id"],
            "nameid_format": parsed["nameid_format"],
            "preset_id": preset_id,
            "sign_response": "true",
            "sign_assertion": "true",
        })
        body = client.assert_ok(resp)
        result = body["data"]["data"]
        attrs = result.get("attributes", {})

        assert UID_URN in attrs
        assert attrs[UID_URN] == "admin"
        assert MAIL_URN in attrs
        assert attrs[MAIL_URN] == "admin@test-idp.local"
        assert DISPLAY_NAME_URN in attrs
        assert attrs[DISPLAY_NAME_URN] == "Admin Tester"

        xml = result["response_xml"]
        assert f'Name="{UID_URN}"' in xml
        assert 'FriendlyName="uid"' in xml
        assert f'Name="{MAIL_URN}"' in xml
        assert 'FriendlyName="mail"' in xml
        assert 'NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"' in xml
        assert '<saml:Attribute Name="uid"' not in xml

    def test_response_normalizes_override_attribute_names_to_oids(self, client):
        """friendly/custom override key도 OID URN으로 정규화한다."""
        encoded = base64.b64encode(SAMPLE_AUTHN_REQUEST.encode("utf-8")).decode("utf-8")
        resp = client.app_api("portal.samlidp.login.check", "parse_request", {
            "SAMLRequest": encoded, "binding": "POST",
        })
        parsed = client.assert_ok(resp)["data"]["data"]

        admin_id = _get_admin_user_id(client)

        resp = client.app_api("portal.samlidp.login.check", "build_response", {
            "user_id": admin_id,
            "sp_entity_id": parsed["issuer"],
            "acs_url": parsed["acs_url"],
            "request_id": parsed["request_id"],
            "transaction_id": parsed["transaction_id"],
            "nameid_format": parsed["nameid_format"],
            "attribute_overrides": json.dumps({
                "mail": "override@test-idp.local",
                "customFlag": "enabled",
            }),
            "sign_response": "true",
            "sign_assertion": "true",
        })
        body = client.assert_ok(resp)
        result = body["data"]["data"]
        attrs = result.get("attributes", {})

        assert attrs[MAIL_URN] == "override@test-idp.local"
        custom_keys = [key for key in attrs if key.startswith("urn:oid:1.3.6.1.4.1.55555.100.")]
        assert len(custom_keys) == 1
        assert attrs[custom_keys[0]] == "enabled"
        assert f'Name="{custom_keys[0]}"' in result["response_xml"]
        assert 'FriendlyName="customFlag"' in result["response_xml"]

    def test_response_xml_signature(self, client):
        """Response XML에 디지털 서명 포함"""
        encoded = base64.b64encode(SAMPLE_AUTHN_REQUEST.encode("utf-8")).decode("utf-8")
        resp = client.app_api("portal.samlidp.login.check", "parse_request", {
            "SAMLRequest": encoded, "binding": "POST",
        })
        parsed = client.assert_ok(resp)["data"]["data"]

        admin_id = _get_admin_user_id(client)

        resp = client.app_api("portal.samlidp.login.check", "build_response", {
            "user_id": admin_id,
            "sp_entity_id": parsed["issuer"],
            "acs_url": parsed["acs_url"],
            "request_id": parsed["request_id"],
            "transaction_id": parsed["transaction_id"],
            "nameid_format": parsed["nameid_format"],
            "sign_response": "true",
            "sign_assertion": "true",
        })
        body = client.assert_ok(resp)
        xml = body["data"]["data"]["response_xml"]

        assert "<ds:Signature" in xml
        assert "<ds:SignatureValue>" in xml
        assert "<ds:X509Certificate>" in xml

    def test_different_nameid_format(self, client):
        """다른 NameID 형식으로 Response 생성"""
        encoded = base64.b64encode(SAMPLE_AUTHN_REQUEST.encode("utf-8")).decode("utf-8")
        resp = client.app_api("portal.samlidp.login.check", "parse_request", {
            "SAMLRequest": encoded, "binding": "POST",
        })
        parsed = client.assert_ok(resp)["data"]["data"]

        admin_id = _get_admin_user_id(client)

        # persistent NameID
        resp = client.app_api("portal.samlidp.login.check", "build_response", {
            "user_id": admin_id,
            "sp_entity_id": parsed["issuer"],
            "acs_url": parsed["acs_url"],
            "request_id": parsed["request_id"],
            "transaction_id": parsed["transaction_id"],
            "nameid_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            "sign_response": "true",
            "sign_assertion": "true",
        })
        body = client.assert_ok(resp)
        result = body["data"]["data"]
        assert result["nameid_format"] == "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
        # persistent → user ID
        assert result["nameid_value"]


class TestLoginCheckAPI:
    """Test login.check portal app APIs."""

    def test_sp_list(self, client):
        resp = client.app_api("portal.samlidp.login.check", "sp_list")
        body = client.assert_ok(resp)
        assert isinstance(body["data"]["data"], list)

    def test_user_list(self, client):
        resp = client.app_api("portal.samlidp.login.check", "user_list")
        body = client.assert_ok(resp)
        users = body["data"]["data"]
        assert isinstance(users, list)
        assert len(users) >= 1
        assert any(user["username"] == "admin" for user in users)

    def test_preset_list(self, client):
        resp = client.app_api("portal.samlidp.login.check", "preset_list")
        body = client.assert_ok(resp)
        presets = body["data"]["data"]
        assert isinstance(presets, list)

    def test_tx_list(self, client):
        resp = client.app_api("portal.samlidp.login.check", "tx_list")
        body = client.assert_ok(resp)
        txs = body["data"]["data"]
        assert isinstance(txs, list)


class TestSAMLRoute:
    """Test SAML route endpoints directly."""

    def test_sso_endpoint_prompts_for_login_when_unauthenticated(self, client, anon_client):
        """세션이 없으면 계정 선택 또는 로그인 화면을 먼저 보여준다."""
        _ensure_sample_sp(client)
        encoded = base64.b64encode(SAMPLE_AUTHN_REQUEST.encode("utf-8")).decode("utf-8")
        resp = anon_client.route("/api/saml/sso", data={
            "SAMLRequest": encoded,
            "RelayState": "route_test",
        }, method="POST")

        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("Content-Type", "")
        assert "서비스가 인증을 요청했습니다." in resp.text
        assert 'name="login_id"' in resp.text
        assert 'name="password"' in resp.text
        assert 'name="selected_user_id"' in resp.text
        assert 'name="SAMLResponse"' not in resp.text
        assert _extract_hidden_input_value(resp.text, "relay_state") == "route_test"

    def test_sso_endpoint_accepts_prompt_login_submission(self, client, anon_client, known_admin_password):
        """프롬프트에서 ID/PW를 제출하면 SAMLResponse를 생성한다."""
        client.assert_ok(client.route("/api/idpcore/seed"))
        _ensure_sample_sp(client)
        encoded = base64.b64encode(SAMPLE_AUTHN_REQUEST.encode("utf-8")).decode("utf-8")
        prompt = anon_client.route("/api/saml/sso", data={
            "SAMLRequest": encoded,
            "RelayState": "route_test",
        }, method="POST")
        state = _extract_sso_prompt_state(prompt.text)

        resp = anon_client.route("/api/saml/sso", data={
            **state,
            "login_id": "admin",
            "password": known_admin_password,
        }, method="POST")

        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("Content-Type", "")
        assert 'action="https://pytest-sp.example.com/acs"' in resp.text
        saml_response = _extract_hidden_input_value(resp.text, "SAMLResponse")
        decoded = base64.b64decode(saml_response).decode("utf-8")
        assert "<samlp:Response" in decoded
        assert "admin@test-idp.local" in decoded

    def test_sso_endpoint(self, client):
        """SSO 엔드포인트에 AuthnRequest 전송"""
        _ensure_sample_sp(client)
        encoded = base64.b64encode(SAMPLE_AUTHN_REQUEST.encode("utf-8")).decode("utf-8")
        resp = client.route("/api/saml/sso", data={
            "SAMLRequest": encoded,
            "RelayState": "route_test",
        }, method="POST")
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("Content-Type", "")
        assert 'action="https://pytest-sp.example.com/acs"' in resp.text
        assert 'name="RelayState" value="route_test"' in resp.text

        saml_response = _extract_hidden_input_value(resp.text, "SAMLResponse")
        decoded = base64.b64decode(saml_response).decode("utf-8")
        assert "<samlp:Response" in decoded
        assert 'InResponseTo="_pytest_req_001"' in decoded
        assert "admin@test-idp.local" in decoded

    def test_sso_endpoint_resolves_missing_issuer_by_acs(self, client):
        """Issuer가 비정상값일 때 등록된 ACS URL로 SP entity_id를 보정한다."""
        _ensure_sample_sp(client)
        authn_request = """<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_pytest_req_missing_issuer"
    Version="2.0"
    IssueInstant="2026-04-13T02:01:25Z"
    AssertionConsumerServiceURL="https://pytest-sp.example.com/acs"
    Destination="https://idp.test-idp.local/api/saml/sso">
  <saml:Issuer>None</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
</samlp:AuthnRequest>"""
        encoded = base64.b64encode(authn_request.encode("utf-8")).decode("utf-8")

        resp = client.route("/api/saml/sso", data={
            "SAMLRequest": encoded,
        }, method="POST")

        assert resp.status_code == 200
        saml_response = _extract_hidden_input_value(resp.text, "SAMLResponse")
        decoded = base64.b64decode(saml_response).decode("utf-8")
        assert '<saml:Audience>https://pytest-sp.example.com/metadata</saml:Audience>' in decoded
        assert 'SPNameQualifier="https://pytest-sp.example.com/metadata"' in decoded

    def test_transactions_list(self, client):
        """트랜잭션 목록"""
        resp = client.route("/api/saml/transactions")
        body = client.assert_ok(resp)
        assert isinstance(body["data"]["data"], list)
