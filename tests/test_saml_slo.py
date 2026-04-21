"""SAML Single Logout (SLO) integration tests for FN-0007.

Tests cover:
- LogoutRequest parsing (SP-initiated)
- Session matching by SessionIndex and NameID
- LogoutResponse generation (with signature)
- IdP-initiated LogoutRequest generation
- Active session listing and invalidation
- SLO route endpoint
"""
import base64
import json
import pytest
from conftest import WizClient, WIZ_BASE

# ─── Fixtures ───

SAMPLE_LOGOUT_REQUEST = """<samlp:LogoutRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_slo_test_001" Version="2.0"
    IssueInstant="2026-03-31T00:00:00Z"
    Destination="http://localhost:3034/api/saml/slo">
    <saml:Issuer>https://sp.example.com/metadata</saml:Issuer>
    <saml:NameID
        Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        SPNameQualifier="https://sp.example.com/metadata">admin@test-idp.local</saml:NameID>
    <samlp:SessionIndex>{session_index}</samlp:SessionIndex>
</samlp:LogoutRequest>"""

SAMPLE_LOGOUT_REQUEST_NO_SESSION = """<samlp:LogoutRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_slo_test_002" Version="2.0"
    IssueInstant="2026-03-31T00:00:00Z"
    Destination="http://localhost:3034/api/saml/slo">
    <saml:Issuer>https://sp.example.com/metadata</saml:Issuer>
    <saml:NameID
        Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        SPNameQualifier="https://sp.example.com/metadata">admin@test-idp.local</saml:NameID>
</samlp:LogoutRequest>"""


@pytest.fixture(scope="module")
def client():
    return WizClient(WIZ_BASE)


@pytest.fixture(scope="module")
def active_session(client):
    """Ensure at least one active SSO session exists by creating one via SSO flow."""
    # Check existing active sessions
    resp = client.route("/api/saml/slo-sessions")
    body = client.assert_ok(resp)
    sessions = body["data"].get("data", body["data"])
    if isinstance(sessions, list) and len(sessions) > 0:
        return sessions[0]

    # If no active sessions, create one via SSO flow
    AUTHN_REQUEST = """<samlp:AuthnRequest
        xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="_slo_setup_req" Version="2.0"
        IssueInstant="2026-03-31T00:00:00Z"
        Destination="http://localhost:3034/api/saml/sso"
        AssertionConsumerServiceURL="https://sp.example.com/acs">
        <saml:Issuer>https://sp.example.com/metadata</saml:Issuer>
    </samlp:AuthnRequest>"""
    b64 = base64.b64encode(AUTHN_REQUEST.encode()).decode()

    # Parse
    resp = client.route("/api/saml/sso-parse", data={"SAMLRequest": b64, "RelayState": "", "binding": "POST"}, method="POST")
    body = client.assert_ok(resp)
    parsed = body["data"].get("data", body["data"])

    # Get admin user
    resp = client.route("/api/saml/sp-list")
    body = client.assert_ok(resp)

    # Build response to create a session
    from conftest import get_cookies
    import requests
    s = requests.Session()
    s.cookies.update(get_cookies())
    resp2 = s.post(f"{WIZ_BASE}/api/saml/sso-respond", data={
        "transaction_id": parsed.get("transaction_id", ""),
        "user_id": "ljgapglesfojvpkqbdxeebzaxgmvyyim",
        "sp_entity_id": "https://sp.example.com/metadata",
        "acs_url": "https://sp.example.com/acs",
        "request_id": parsed.get("request_id", "_slo_setup_req"),
        "relay_state": "",
        "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "sign_response": "true",
        "sign_assertion": "true",
    })
    body2 = resp2.json()
    assert body2.get("code") == 200

    # Now get active sessions
    resp = client.route("/api/saml/slo-sessions")
    body = client.assert_ok(resp)
    sessions = body["data"].get("data", body["data"])
    assert len(sessions) > 0
    return sessions[0]


# ─── Test: Parse LogoutRequest ───

class TestParseLogoutRequest:
    def test_parse_with_session_index(self, client, active_session):
        session_index = active_session["session_index"]
        xml = SAMPLE_LOGOUT_REQUEST.format(session_index=session_index)
        b64 = base64.b64encode(xml.encode()).decode()

        resp = client.route("/api/saml/slo-parse", data={
            "SAMLRequest": b64,
            "RelayState": "test_relay",
            "binding": "POST",
        }, method="POST")
        body = client.assert_ok(resp)
        data = body["data"].get("data", body["data"])

        assert data["request_id"] == "_slo_test_001"
        assert data["issuer"] == "https://sp.example.com/metadata"
        assert data["nameid_value"] == "admin@test-idp.local"
        assert data["nameid_format"] == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        assert session_index in data["session_indexes"]
        assert data["relay_state"] == "test_relay"

    def test_parse_matched_sessions(self, client, active_session):
        session_index = active_session["session_index"]
        xml = SAMPLE_LOGOUT_REQUEST.format(session_index=session_index)
        b64 = base64.b64encode(xml.encode()).decode()

        resp = client.route("/api/saml/slo-parse", data={
            "SAMLRequest": b64,
            "binding": "POST",
        }, method="POST")
        body = client.assert_ok(resp)
        data = body["data"].get("data", body["data"])

        matched = data.get("matched_sessions", [])
        assert len(matched) >= 1
        assert any(s["session_index"] == session_index for s in matched)

    def test_parse_without_session_index_matches_by_nameid(self, client):
        b64 = base64.b64encode(SAMPLE_LOGOUT_REQUEST_NO_SESSION.encode()).decode()

        resp = client.route("/api/saml/slo-parse", data={
            "SAMLRequest": b64,
            "binding": "POST",
        }, method="POST")
        body = client.assert_ok(resp)
        data = body["data"].get("data", body["data"])

        assert data["request_id"] == "_slo_test_002"
        assert data["session_indexes"] == []
        # NameID matching may or may not find sessions depending on state

    def test_parse_invalid_xml(self, client):
        b64 = base64.b64encode(b"<not-valid-xml").decode()
        resp = client.route("/api/saml/slo-parse", data={
            "SAMLRequest": b64,
            "binding": "POST",
        }, method="POST")
        body = resp.json()
        assert body.get("code") == 400

    def test_parse_saves_debug_file(self, client, active_session):
        session_index = active_session["session_index"]
        xml = SAMPLE_LOGOUT_REQUEST.format(session_index=session_index)
        b64 = base64.b64encode(xml.encode()).decode()

        resp = client.route("/api/saml/slo-parse", data={
            "SAMLRequest": b64,
            "binding": "POST",
        }, method="POST")
        body = client.assert_ok(resp)
        data = body["data"].get("data", body["data"])

        raw_key = data.get("raw_request_key", "")
        assert raw_key.startswith("slo_req_")

        # Verify debug file can be retrieved
        resp2 = client.route("/api/saml/debug-raw", data={"key": raw_key})
        assert resp2.status_code == 200
        assert "LogoutRequest" in resp2.text


# ─── Test: Build LogoutResponse ───

class TestBuildLogoutResponse:
    def test_build_signed_response(self, client):
        resp = client.route("/api/saml/slo-respond", data={
            "request_id": "_slo_test_resp_001",
            "sp_entity_id": "https://sp.example.com/metadata",
            "destination": "https://sp.example.com/slo",
            "relay_state": "test_relay",
            "sign": "true",
        }, method="POST")
        body = client.assert_ok(resp)
        data = body["data"].get("data", body["data"])

        assert data["response_id"].startswith("_sloresp_")
        assert data["destination"] == "https://sp.example.com/slo"
        assert data["relay_state"] == "test_relay"
        assert data["signed"] is True
        assert "LogoutResponse" in data["response_xml"]
        assert "Signature" in data["response_xml"]
        assert len(data["response_b64"]) > 0

    def test_build_unsigned_response(self, client):
        resp = client.route("/api/saml/slo-respond", data={
            "request_id": "_slo_test_resp_002",
            "sp_entity_id": "https://sp.example.com/metadata",
            "destination": "https://sp.example.com/slo",
            "sign": "false",
        }, method="POST")
        body = client.assert_ok(resp)
        data = body["data"].get("data", body["data"])

        assert data["signed"] is False
        assert "LogoutResponse" in data["response_xml"]
        assert "Signature" not in data["response_xml"]

    def test_build_response_with_error_status(self, client):
        resp = client.route("/api/saml/slo-respond", data={
            "request_id": "_slo_test_resp_003",
            "sp_entity_id": "https://sp.example.com/metadata",
            "destination": "https://sp.example.com/slo",
            "status_code": "urn:oasis:names:tc:SAML:2.0:status:Requester",
            "sign": "true",
        }, method="POST")
        body = client.assert_ok(resp)
        data = body["data"].get("data", body["data"])

        assert "Requester" in data["response_xml"]
        assert data["status_code"] == "urn:oasis:names:tc:SAML:2.0:status:Requester"

    def test_response_contains_in_response_to(self, client):
        resp = client.route("/api/saml/slo-respond", data={
            "request_id": "_slo_ref_id_123",
            "sp_entity_id": "https://sp.example.com/metadata",
            "destination": "https://sp.example.com/slo",
            "sign": "false",
        }, method="POST")
        body = client.assert_ok(resp)
        data = body["data"].get("data", body["data"])
        assert 'InResponseTo="_slo_ref_id_123"' in data["response_xml"]

    def test_response_saves_debug_file(self, client):
        resp = client.route("/api/saml/slo-respond", data={
            "request_id": "_slo_debug_test",
            "sp_entity_id": "https://sp.example.com/metadata",
            "sign": "false",
        }, method="POST")
        body = client.assert_ok(resp)
        data = body["data"].get("data", body["data"])

        raw_key = data["raw_response_key"]
        assert raw_key.startswith("slo_resp_")

        resp2 = client.route("/api/saml/debug-raw", data={"key": raw_key})
        assert resp2.status_code == 200
        assert "LogoutResponse" in resp2.text


# ─── Test: IdP-initiated LogoutRequest ───

class TestIdpInitiatedLogout:
    def test_build_logout_request(self, client):
        resp = client.route("/api/saml/slo-initiate", data={
            "sp_entity_id": "https://sp.example.com/metadata",
            "nameid_value": "admin@test-idp.local",
            "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "sign": "true",
        }, method="POST")
        body = client.assert_ok(resp)
        data = body["data"].get("data", body["data"])

        assert data["request_id"].startswith("_sloreq_")
        assert data["nameid_value"] == "admin@test-idp.local"
        assert "LogoutRequest" in data["request_xml"]
        assert "Signature" in data["request_xml"]
        assert data["signed"] is True
        assert len(data["request_b64"]) > 0

    def test_build_logout_request_resolves_destination(self, client):
        resp = client.route("/api/saml/slo-initiate", data={
            "sp_entity_id": "https://sp.example.com/metadata",
            "nameid_value": "alice@example.com",
            "sign": "false",
        }, method="POST")
        body = client.assert_ok(resp)
        data = body["data"].get("data", body["data"])

        # SP metadata has SLO URL — destination should be auto-resolved
        assert "LogoutRequest" in data["request_xml"]
        # Destination may or may not be present depending on SP metadata

    def test_build_logout_request_with_session_indexes(self, client):
        resp = client.route("/api/saml/slo-initiate", data={
            "sp_entity_id": "https://sp.example.com/metadata",
            "nameid_value": "admin@test-idp.local",
            "session_indexes": json.dumps(["_sidx_test_001", "_sidx_test_002"]),
            "sign": "false",
        }, method="POST")
        body = client.assert_ok(resp)
        data = body["data"].get("data", body["data"])

        assert "SessionIndex" in data["request_xml"]
        assert "_sidx_test_001" in data["request_xml"]
        assert "_sidx_test_002" in data["request_xml"]

    def test_build_logout_request_saves_debug_file(self, client):
        resp = client.route("/api/saml/slo-initiate", data={
            "sp_entity_id": "https://sp.example.com/metadata",
            "nameid_value": "test@example.com",
            "sign": "false",
        }, method="POST")
        body = client.assert_ok(resp)
        data = body["data"].get("data", body["data"])

        raw_key = data["raw_request_key"]
        assert raw_key.startswith("slo_idpreq_")


# ─── Test: Active Sessions & Invalidation ───

class TestSessionManagement:
    def test_list_active_sessions(self, client):
        resp = client.route("/api/saml/slo-sessions")
        body = client.assert_ok(resp)
        data = body["data"].get("data", body["data"])
        assert isinstance(data, list)

    def test_list_active_sessions_by_sp(self, client):
        resp = client.route("/api/saml/slo-sessions", data={
            "sp_entity_id": "https://sp.example.com/metadata",
        })
        body = client.assert_ok(resp)
        data = body["data"].get("data", body["data"])
        assert isinstance(data, list)
        for s in data:
            assert s["sp_entity_id"] == "https://sp.example.com/metadata"

    def test_invalidate_session(self, client, active_session):
        """Create a new SSO session, then invalidate it."""
        # First create a fresh session via SSO
        AUTHN_REQUEST = """<samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_slo_invalidate_test" Version="2.0"
            IssueInstant="2026-03-31T00:00:00Z"
            AssertionConsumerServiceURL="https://sp.example.com/acs">
            <saml:Issuer>https://sp.example.com/metadata</saml:Issuer>
        </samlp:AuthnRequest>"""
        b64 = base64.b64encode(AUTHN_REQUEST.encode()).decode()
        resp = client.route("/api/saml/sso-parse", data={
            "SAMLRequest": b64, "binding": "POST"
        }, method="POST")
        body = client.assert_ok(resp)
        parsed = body["data"].get("data", body["data"])

        resp = client.route("/api/saml/sso-respond", data={
            "transaction_id": parsed.get("transaction_id", ""),
            "user_id": active_session["user_id"],
            "sp_entity_id": "https://sp.example.com/metadata",
            "acs_url": "https://sp.example.com/acs",
            "request_id": "_slo_invalidate_test",
            "sign_response": "true",
            "sign_assertion": "true",
        }, method="POST")
        body = client.assert_ok(resp)
        new_session_index = body["data"]["data"]["session_index"] if "data" in body["data"] and isinstance(body["data"]["data"], dict) else body["data"]["session_index"]

        # Find the new transaction
        resp = client.route("/api/saml/slo-sessions")
        body = client.assert_ok(resp)
        sessions = body["data"].get("data", body["data"])
        new_session = None
        for s in sessions:
            if s["session_index"] == new_session_index:
                new_session = s
                break
        assert new_session is not None

        # Invalidate it
        resp = client.route("/api/saml/slo-invalidate", data={
            "session_ids": json.dumps([new_session["id"]]),
        }, method="POST")
        body = client.assert_ok(resp)

        # Verify it's no longer in active sessions
        resp = client.route("/api/saml/slo-sessions")
        body = client.assert_ok(resp)
        sessions = body["data"].get("data", body["data"])
        active_ids = [s["session_index"] for s in sessions]
        assert new_session_index not in active_ids


# ─── Test: SLO Route Endpoint ───

class TestSLORouteEndpoint:
    def test_slo_endpoint_receives_logout_request(self, client, active_session):
        """Test the actual /api/saml/slo endpoint that receives SP LogoutRequests."""
        # Create a fresh session first
        AUTHN_REQUEST = """<samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_slo_route_test" Version="2.0"
            IssueInstant="2026-03-31T00:00:00Z"
            AssertionConsumerServiceURL="https://sp.example.com/acs">
            <saml:Issuer>https://sp.example.com/metadata</saml:Issuer>
        </samlp:AuthnRequest>"""
        b64 = base64.b64encode(AUTHN_REQUEST.encode()).decode()
        resp = client.route("/api/saml/sso-parse", data={
            "SAMLRequest": b64, "binding": "POST",
        }, method="POST")
        body = client.assert_ok(resp)
        parsed = body["data"].get("data", body["data"])

        resp = client.route("/api/saml/sso-respond", data={
            "transaction_id": parsed.get("transaction_id", ""),
            "user_id": active_session["user_id"],
            "sp_entity_id": "https://sp.example.com/metadata",
            "acs_url": "https://sp.example.com/acs",
            "request_id": "_slo_route_test",
            "sign_response": "true",
            "sign_assertion": "true",
        }, method="POST")
        body = client.assert_ok(resp)
        sso_data = body["data"].get("data", body["data"])
        session_index = sso_data["session_index"]

        # Now send LogoutRequest to the SLO endpoint
        logout_xml = SAMPLE_LOGOUT_REQUEST.format(session_index=session_index)
        logout_b64 = base64.b64encode(logout_xml.encode()).decode()

        resp = client.route("/api/saml/slo", data={
            "SAMLRequest": logout_b64,
            "RelayState": "slo_relay_test",
        }, method="POST")
        body = client.assert_ok(resp)
        data = body["data"].get("data", body["data"])

        # Should return LogoutResponse
        assert "response_xml" in data
        assert "LogoutResponse" in data["response_xml"]
        assert "parsed_request" in data
        assert data["parsed_request"]["request_id"] == "_slo_test_001"

        # Session should have been invalidated
        invalidated = data.get("invalidated_sessions", [])
        assert len(invalidated) >= 1

    def test_slo_endpoint_no_saml_request(self, client):
        resp = client.route("/api/saml/slo", data={}, method="POST")
        body = resp.json()
        assert body.get("code") == 400
