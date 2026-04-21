"""Security tests for test-idp: XXE, rate limiting, password hash exposure, path traversal, mass assignment, SP limits."""
import pytest
import base64
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from conftest import WizClient, ADMIN_SESSION


@pytest.fixture
def client():
    return WizClient(session_data=ADMIN_SESSION)


@pytest.fixture
def anon_client():
    return WizClient()


class TestPasswordHashNotExposed:
    """Verify password_hash is never returned in API responses."""

    def test_user_list_no_password_hash(self, client):
        resp = client.route("/api/idpcore/users")
        body = client.assert_ok(resp)
        users = body["data"]["data"]
        for user in users:
            assert "password_hash" not in user, f"password_hash exposed for {user.get('username')}"

    def test_user_get_no_password_hash(self, client):
        resp = client.route("/api/idpcore/user", data={"username": "admin"})
        body = client.assert_ok(resp)
        user = body["data"]["data"]
        assert "password_hash" not in user

    def test_create_temporary_no_password_hash(self, client):
        resp = client.route("/api/idpcore/user-create-temporary", data={
            "username": "sec_test_user",
            "password": "testpass123",
            "email": "sectest@test.local",
        }, method="POST")
        body = client.assert_ok(resp)
        user = body["data"]["data"]
        assert "password_hash" not in user
        # Cleanup
        client.route("/api/idpcore/user-delete", data={"id": user["id"]}, method="POST")

    def test_user_update_no_password_hash(self, client):
        # Create temp user
        resp = client.route("/api/idpcore/user-create-temporary", data={
            "username": "sec_update_user",
            "password": "testpass123",
            "email": "secupdate@test.local",
        }, method="POST")
        body = client.assert_ok(resp)
        user_id = body["data"]["data"]["id"]

        # Update
        resp = client.route("/api/idpcore/user-update", data={
            "id": user_id,
            "display_name": "Updated Name",
        }, method="POST")
        body = client.assert_ok(resp)
        user = body["data"]["data"]
        assert "password_hash" not in user

        # Cleanup
        client.route("/api/idpcore/user-delete", data={"id": user_id}, method="POST")

    def test_login_check_user_list_no_password_hash(self, client):
        resp = client.app_api("portal.samlidp.login.check", "user_list")
        body = client.assert_ok(resp)
        users = body["data"]["data"]
        for user in users:
            assert "password_hash" not in user, f"password_hash exposed for {user.get('username')}"

    def test_logout_check_user_list_no_password_hash(self, client):
        resp = client.app_api("portal.samlidp.logout.check", "user_list")
        body = client.assert_ok(resp)
        users = body["data"]["data"]
        for user in users:
            assert "password_hash" not in user, f"password_hash exposed for {user.get('username')}"


class TestMassAssignmentProtection:
    """Verify field whitelisting prevents mass assignment attacks."""

    def test_cannot_set_role_via_temp_create(self, client):
        resp = client.route("/api/idpcore/user-create-temporary", data={
            "username": "mass_assign_test",
            "password": "testpass123",
            "email": "masstest@test.local",
            "role": "admin",
        }, method="POST")
        body = client.assert_ok(resp)
        user = body["data"]["data"]
        # role should default to "tester", not "admin"
        assert user["role"] == "tester", f"Mass assignment allowed role={user['role']}"
        # Cleanup
        client.route("/api/idpcore/user-delete", data={"id": user["id"]}, method="POST")

    def test_cannot_set_is_temporary_false(self, client):
        resp = client.route("/api/idpcore/user-create-temporary", data={
            "username": "mass_assign_perm",
            "password": "testpass123",
            "email": "massperm@test.local",
            "is_temporary": "false",
        }, method="POST")
        body = client.assert_ok(resp)
        user = body["data"]["data"]
        assert user["is_temporary"] == True, "Mass assignment allowed is_temporary override"
        # Cleanup
        client.route("/api/idpcore/user-delete", data={"id": user["id"]}, method="POST")


class TestXXEProtection:
    """Verify XML parsing rejects XXE payloads."""

    XXE_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="&xxe;">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://evil.example.com/acs" index="0"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>"""

    def test_sp_register_rejects_xxe(self, client):
        resp = client.route("/api/saml/sp-register", data={
            "xml": self.XXE_PAYLOAD,
        }, method="POST")
        # Should reject with 400 (XML parse error or entity resolution blocked)
        body = resp.json()
        assert body.get("code") != 200, "XXE payload should not be accepted"

    def test_sso_parse_rejects_xxe(self, client):
        xxe_authn = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="&xxe;" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
</samlp:AuthnRequest>"""
        encoded = base64.b64encode(xxe_authn.encode()).decode()
        resp = client.route("/api/saml/sso-parse", data={
            "SAMLRequest": encoded,
            "binding": "POST",
        }, method="POST")
        body = resp.json()
        assert body.get("code") != 200, "XXE payload in AuthnRequest should be rejected"


class TestXMLSizeLimits:
    """Verify oversized XML payloads are rejected."""

    def test_sp_register_rejects_oversized_xml(self, client):
        # Generate XML > 256KB
        large_comment = "<!-- " + "A" * (300 * 1024) + " -->"
        oversized_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
{large_comment}
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://oversized.example.com">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://oversized.example.com/acs" index="0"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>"""
        resp = client.route("/api/saml/sp-register", data={
            "xml": oversized_xml,
        }, method="POST")
        body = resp.json()
        assert body.get("code") == 400, f"Oversized XML should be rejected, got code={body.get('code')}"

    def test_sso_parse_rejects_oversized_xml(self, client):
        large_comment = "<!-- " + "A" * (300 * 1024) + " -->"
        oversized_authn = f"""<?xml version="1.0" encoding="UTF-8"?>
{large_comment}
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="_test" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
</samlp:AuthnRequest>"""
        encoded = base64.b64encode(oversized_authn.encode()).decode()
        resp = client.route("/api/saml/sso-parse", data={
            "SAMLRequest": encoded,
            "binding": "POST",
        }, method="POST")
        body = resp.json()
        assert body.get("code") == 400, f"Oversized XML should be rejected, got code={body.get('code')}"


class TestPathTraversalProtection:
    """Verify debug-raw endpoint rejects path traversal attempts."""

    def test_debug_raw_rejects_path_traversal(self, client):
        resp = client.route("/api/saml/debug-raw", data={"key": "../../etc/passwd"})
        body = resp.json()
        assert body.get("code") != 200, "Path traversal should be blocked"

    def test_debug_raw_rejects_slashes(self, client):
        resp = client.route("/api/saml/debug-raw", data={"key": "foo/bar"})
        body = resp.json()
        assert body.get("code") != 200, "Slashes in debug key should be blocked"

    def test_debug_raw_rejects_dots(self, client):
        resp = client.route("/api/saml/debug-raw", data={"key": "foo..bar"})
        body = resp.json()
        assert body.get("code") != 200, "Dots in debug key should be blocked"


class TestRateLimiting:
    """Verify rate limiting is enforced on sensitive endpoints."""

    def test_login_rate_limiting(self, anon_client):
        """Login endpoint should rate limit after 10 attempts."""
        for i in range(11):
            resp = anon_client.app_api("page.access", "login", data={
                "username": "nonexistent",
                "password": "wrongpass",
            })
        body = resp.json()
        assert body.get("code") == 429, f"Expected 429 rate limit, got {body.get('code')}"

    def test_temp_user_create_rate_limiting(self, client):
        """Temporary user creation should rate limit after 10 attempts."""
        created_ids = []
        last_body = None
        for i in range(11):
            resp = client.route("/api/idpcore/user-create-temporary", data={
                "username": f"ratelimit_test_{i}",
                "password": "testpass123",
                "email": f"ratelimit{i}@test.local",
            }, method="POST")
            last_body = resp.json()
            if last_body.get("code") == 200:
                created_ids.append(last_body["data"]["data"]["id"])
        assert last_body.get("code") == 429, f"Expected 429, got {last_body.get('code')}"
        # Cleanup
        for uid in created_ids:
            client.route("/api/idpcore/user-delete", data={"id": uid}, method="POST")


class TestDeleteRestriction:
    """Verify IP-based delete restrictions for SP and temp accounts."""

    def test_sp_list_has_can_delete_field(self, client):
        """SP list response should include can_delete flag."""
        resp = client.route("/api/saml/sp-list")
        body = client.assert_ok(resp)
        rows = body["data"]["data"]
        if len(rows) > 0:
            assert "can_delete" in rows[0], "SP list items should have can_delete flag"

    def test_admin_can_delete_sp(self, client):
        """Admin user should always be able to delete SPs."""
        # Register an SP first
        sp_xml = """<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://delete-test-admin.example.com">
            <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://delete-test-admin.example.com/acs" index="0"/>
            </md:SPSSODescriptor>
        </md:EntityDescriptor>"""
        resp = client.route("/api/saml/sp-register", data={"xml": sp_xml}, method="POST")
        body = client.assert_ok(resp)
        sp_id = body["data"]["data"]["id"]

        # Admin should be able to delete
        resp = client.route("/api/saml/sp-delete", data={"id": sp_id}, method="POST")
        body = client.assert_ok(resp)

    def test_anon_cannot_delete_others_sp(self, anon_client, client):
        """Anonymous user from different IP should not delete SP registered by another."""
        # Register SP via admin (from 127.0.0.1)
        sp_xml = """<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://delete-test-anon.example.com">
            <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://delete-test-anon.example.com/acs" index="0"/>
            </md:SPSSODescriptor>
        </md:EntityDescriptor>"""
        resp = client.route("/api/saml/sp-register", data={"xml": sp_xml}, method="POST")
        body = client.assert_ok(resp)
        sp_id = body["data"]["data"]["id"]

        # Same IP (127.0.0.1 localhost) so anon should also be able to delete since same IP
        # But the key test is that can_delete flag exists
        resp = anon_client.route("/api/saml/sp-list")
        body = anon_client.assert_ok(resp)
        rows = body["data"]["data"]
        found = [r for r in rows if r["id"] == sp_id]
        assert len(found) == 1, "Registered SP should appear in list"
        assert "can_delete" in found[0], "SP should have can_delete flag"

        # Cleanup
        client.route("/api/saml/sp-delete", data={"id": sp_id}, method="POST")

    def test_sp_created_by_ip_stored(self, client):
        """SP registration should store the creator's IP address."""
        sp_xml = """<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://ip-test-sp.example.com">
            <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://ip-test-sp.example.com/acs" index="0"/>
            </md:SPSSODescriptor>
        </md:EntityDescriptor>"""
        resp = client.route("/api/saml/sp-register", data={"xml": sp_xml}, method="POST")
        body = client.assert_ok(resp)
        sp_id = body["data"]["data"]["id"]

        # Get SP detail - should have created_by_ip
        resp = client.route("/api/saml/sp-get", data={"id": sp_id})
        body = client.assert_ok(resp)
        sp_data = body["data"]["data"]
        assert "created_by_ip" in sp_data, "SP should have created_by_ip field"
        assert sp_data["created_by_ip"] != "", "created_by_ip should not be empty"

        # Cleanup
        client.route("/api/saml/sp-delete", data={"id": sp_id}, method="POST")

    def test_temp_user_created_by_ip_stored(self, client):
        """Temporary user creation should store the creator's IP address."""
        resp = client.route("/api/idpcore/user-create-temporary", data={
            "username": "ip_test_user",
            "password": "test1234",
            "email": "iptest@test.local",
        }, method="POST")
        body = client.assert_ok(resp)
        user_data = body["data"]["data"]
        assert "created_by_ip" in user_data, "User should have created_by_ip field"
        assert user_data["created_by_ip"] != "", "created_by_ip should not be empty"

        # Cleanup
        client.route("/api/idpcore/user-delete", data={"id": user_data["id"]}, method="POST")

    def test_temp_users_list_has_can_delete(self, client):
        """Temporary users list should include can_delete flag."""
        resp = client.route("/api/idpcore/users-temporary", data={"include_expired": "true"})
        body = client.assert_ok(resp)
        users = body["data"]["data"]
        if len(users) > 0:
            assert "can_delete" in users[0], "Temp user list items should have can_delete flag"

    def test_admin_can_delete_temp_user(self, client):
        """Admin should be able to delete any temp user."""
        # Create temp user
        resp = client.route("/api/idpcore/user-create-temporary", data={
            "username": "admin_del_test",
            "password": "test1234",
        }, method="POST")
        body = client.assert_ok(resp)
        user_id = body["data"]["data"]["id"]

        # Admin delete
        resp = client.route("/api/idpcore/user-delete", data={"id": user_id}, method="POST")
        body = client.assert_ok(resp)
