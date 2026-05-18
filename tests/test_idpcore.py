"""Tests for idpcore package: user CRUD, attribute presets, authentication."""
import datetime

import pytest
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


class TestIdpcoreUserAPI:
    """Test idpcore user management via route API."""

    def test_user_list(self, client):
        resp = client.route("/api/idpcore/users")
        body = client.assert_ok(resp)
        users = body["data"]["data"]
        assert isinstance(users, list)
        assert len(users) >= 1
        usernames = [u["username"] for u in users]
        assert "admin" in usernames
        assert "alice" not in usernames
        assert "bob" not in usernames
        assert "carol" not in usernames
        assert "mfauser" not in usernames

    def test_user_get_by_username(self, client):
        resp = client.route("/api/idpcore/user", data={"username": "admin"})
        body = client.assert_ok(resp)
        user = body["data"]["data"]
        assert user["username"] == "admin"
        assert user["email"] == "admin@test-idp.local"
        assert user["role"] == "admin"

    def test_user_get_by_id(self, client):
        resp = client.route("/api/idpcore/user", data={"username": "admin"})
        body = client.assert_ok(resp)
        admin_id = body["data"]["data"]["id"]

        resp = client.route("/api/idpcore/user", data={"id": admin_id})
        body = client.assert_ok(resp)
        assert body["data"]["data"]["username"] == "admin"

    def test_user_create_temporary_and_delete(self, client):
        resp = client.route("/api/idpcore/user-create-temporary", data={
            "username": "pytest_temp_user",
            "password": "temppass123",
            "email": "pytest_temp@test.local",
            "display_name": "Pytest Temp User",
        }, method="POST")
        body = client.assert_ok(resp)
        user = body["data"]["data"]
        assert user["username"] == "pytest_temp_user"
        assert user["saml_attributes"]["urn:oid:0.9.2342.19200300.100.1.1"] == "pytest_temp_user"
        assert user["saml_attributes"]["urn:oid:0.9.2342.19200300.100.1.3"] == "pytest_temp@test.local"
        assert user["oidc_claims"]["preferred_username"] == "pytest_temp_user"
        assert user["oidc_claims"]["email"] == "pytest_temp@test.local"
        assert user["oidc_claims"]["groups"] == ["testers"]
        user_id = user["id"]

        resp = client.route("/api/idpcore/user-delete", data={"id": user_id}, method="POST")
        client.assert_ok(resp)

        resp = client.route("/api/idpcore/user", data={"id": user_id})
        body = resp.json()
        assert body.get("code") == 404

    def test_user_update(self, client):
        resp = client.route("/api/idpcore/user-create-temporary", data={
            "username": "pytest_update_user",
            "password": "temppass123",
            "display_name": "Before Update",
        }, method="POST")
        body = client.assert_ok(resp)
        user_id = body["data"]["data"]["id"]

        try:
            resp = client.route("/api/idpcore/user-update", data={
                "id": user_id,
                "display_name": "After Update",
                "email": "updated@test.local",
            }, method="POST")
            body = client.assert_ok(resp)
            updated = body["data"]["data"]
            assert updated["display_name"] == "After Update"
            assert updated["email"] == "updated@test.local"
        finally:
            client.route("/api/idpcore/user-delete", data={"id": user_id}, method="POST")

    def test_user_create_temporary_normalizes_saml_attribute_oids(self, client):
        import json as _json

        resp = client.route("/api/idpcore/user-create-temporary", data={
            "username": "pytest_oid_user",
            "password": "temppass123",
            "email": "pytest_oid@test.local",
            "display_name": "Pytest OID User",
            "saml_attributes": _json.dumps({
                "uid": "pytest_oid_user",
                "mail": "pytest_oid@test.local",
                "groups": ["testers"],
                "customFlag": "enabled",
            }),
        }, method="POST")
        body = client.assert_ok(resp)
        user = body["data"]["data"]
        attrs = user["saml_attributes"]
        user_id = user["id"]

        try:
            assert attrs["urn:oid:0.9.2342.19200300.100.1.1"] == "pytest_oid_user"
            assert attrs["urn:oid:0.9.2342.19200300.100.1.3"] == "pytest_oid@test.local"
            assert attrs["urn:oid:1.2.840.113556.1.2.102"] == ["testers"]
            custom_keys = [
                key for key, value in attrs.items()
                if key.startswith("urn:oid:1.3.6.1.4.1.55555.100.") and value == "enabled"
            ]
            assert len(custom_keys) == 1
            assert user["oidc_claims"]["preferred_username"] == "pytest_oid_user"
            assert user["oidc_claims"]["email"] == "pytest_oid@test.local"
            assert user["oidc_claims"]["groups"] == ["testers"]
        finally:
            client.route("/api/idpcore/user-delete", data={"id": user_id}, method="POST")

    def test_user_create_temporary_applies_all_default_attribute_catalog(self, client):
        resp = client.route("/api/idpcore/saml-attribute-catalog")
        body = client.assert_ok(resp)
        catalog = body["data"]["data"]

        resp = client.route("/api/idpcore/user-create-temporary", data={
            "username": "pytest_default_attrs",
            "password": "temppass123",
            "email": "pytest_default_attrs@test.local",
            "display_name": "Default Attrs",
        }, method="POST")
        body = client.assert_ok(resp)
        user = body["data"]["data"]
        user_id = user["id"]

        try:
            attrs = user["saml_attributes"]
            claims = user["oidc_claims"]
            for attr in catalog:
                assert attr["urn"] in attrs
            for claim in [
                "preferred_username",
                "email",
                "name",
                "given_name",
                "family_name",
                "department",
                "groups",
                "eduPersonPrincipalName",
                "eduPersonAffiliation",
                "eduPersonScopedAffiliation",
                "eduPersonEntitlement",
                "profile",
            ]:
                assert claim in claims
        finally:
            client.route("/api/idpcore/user-delete", data={"id": user_id}, method="POST")

    def test_permanent_users_list(self, client):
        resp = client.route("/api/idpcore/users-permanent")
        body = client.assert_ok(resp)
        users = body["data"]["data"]
        for u in users:
            assert not u.get("is_temporary")

    def test_temporary_users_list(self, client):
        resp = client.route("/api/idpcore/users-temporary")
        body = client.assert_ok(resp)
        users = body["data"]["data"]
        for u in users:
            assert u.get("is_temporary") in [True, "True", 1, "1"]

    def test_user_extend_validity_and_set_unlimited(self, client):
        resp = client.route("/api/idpcore/user-create-temporary", data={
            "username": "pytest_extend_user",
            "password": "temppass123",
            "display_name": "Extend User",
        }, method="POST")
        body = client.assert_ok(resp)
        user = body["data"]["data"]
        user_id = user["id"]
        original_expires = datetime.datetime.strptime(user["expires"], "%Y-%m-%d %H:%M:%S")

        try:
            resp = client.route("/api/idpcore/user-extend-validity", data={
                "id": user_id,
                "ttl_hours": "24",
            }, method="POST")
            body = client.assert_ok(resp)
            extended = body["data"]["data"]
            extended_expires = datetime.datetime.strptime(extended["expires"], "%Y-%m-%d %H:%M:%S")
            assert extended_expires > original_expires

            resp = client.route("/api/idpcore/user-set-unlimited", data={"id": user_id}, method="POST")
            body = client.assert_ok(resp)
            unlimited = body["data"]["data"]
            assert unlimited["expires"] is None
        finally:
            client.route("/api/idpcore/user-delete", data={"id": user_id}, method="POST")


class TestIdpcorePresetAPI:
    def test_preset_list_all(self, client):
        resp = client.route("/api/idpcore/presets")
        body = client.assert_ok(resp)
        presets = body["data"]["data"]
        assert isinstance(presets, list)
        assert len(presets) >= 4

    def test_saml_presets(self, client):
        resp = client.route("/api/idpcore/presets", data={"protocol": "saml"})
        body = client.assert_ok(resp)
        presets = body["data"]["data"]
        names = [p["name"] for p in presets]
        assert "minimal" in names
        for p in presets:
            assert p["protocol"] == "saml"

    def test_oidc_presets(self, client):
        resp = client.route("/api/idpcore/presets", data={"protocol": "oidc"})
        body = client.assert_ok(resp)
        presets = body["data"]["data"]
        names = [p["name"] for p in presets]
        assert "openid-basic" in names
        for p in presets:
            assert p["protocol"] == "oidc"

    def test_preset_has_attributes(self, client):
        import json as _json
        resp = client.route("/api/idpcore/presets", data={"protocol": "saml"})
        body = client.assert_ok(resp)
        minimal = next(p for p in body["data"]["data"] if p["name"] == "minimal")
        payload = minimal.get("payload", {})
        if isinstance(payload, str):
            payload = _json.loads(payload)
        assert "attributes" in payload

    def test_saml_attribute_catalog(self, client):
        resp = client.route("/api/idpcore/saml-attribute-catalog")
        body = client.assert_ok(resp)
        catalog = body["data"]["data"]
        uid = next(item for item in catalog if item["friendly_name"] == "uid")
        assert uid["urn"] == "urn:oid:0.9.2342.19200300.100.1.1"
        assert "uid" in uid["aliases"]

    def test_pysaml2_attribute_catalog(self, client):
        resp = client.route("/api/idpcore/pysaml2-attribute-catalog")
        body = client.assert_ok(resp)
        catalog = body["data"]["data"]
        assert len(catalog) > 50
        mail = next(
            item for item in catalog
            if item["friendly_name"] == "mail" and item["name"] == "urn:oid:0.9.2342.19200300.100.1.3"
        )
        assert mail["name"] == "urn:oid:0.9.2342.19200300.100.1.3"
        assert mail["oidc_claim_key"] == "email"
        assert mail["name_format"]


class TestAuthentication:
    def test_seed_requires_admin(self, anon_client):
        resp = anon_client.route("/api/idpcore/seed")
        anon_client.assert_error(resp, 403)

        resp = anon_client.route("/api/idpcore/seed-force")
        anon_client.assert_error(resp, 403)

    def test_admin_change_password_and_restore(self, client, anon_client, known_admin_password):
        original_password = known_admin_password
        new_password = "admin5678"
        changed = False

        try:
            resp = client.app_api("page.landing", "change_password", {
                "current_password": original_password,
                "new_password": new_password,
                "confirm_password": new_password,
            })
            client.assert_ok(resp)
            changed = True

            resp = anon_client.app_api("page.access", "login", {
                "username": "admin", "password": new_password,
            })
            anon_client.assert_ok(resp)
        finally:
            if changed:
                resp = client.app_api("page.landing", "change_password", {
                    "current_password": new_password,
                    "new_password": original_password,
                    "confirm_password": original_password,
                })
                client.assert_ok(resp)

    def test_login_success_admin(self, anon_client, known_admin_password):
        resp = anon_client.app_api("page.access", "login", {
            "username": "admin", "password": known_admin_password,
        })
        anon_client.assert_ok(resp)

    def test_seed_force_preserves_changed_admin_password(self, client, anon_client, known_admin_password):
        new_password = "admin91011"

        resp = client.app_api("page.landing", "change_password", {
            "current_password": known_admin_password,
            "new_password": new_password,
            "confirm_password": new_password,
        })
        client.assert_ok(resp)

        resp = client.route("/api/idpcore/seed-force")
        client.assert_ok(resp)

        resp = anon_client.app_api("page.access", "login", {
            "username": "admin", "password": new_password,
        })
        anon_client.assert_ok(resp)

    def test_login_denied_non_admin_account(self, anon_client):
        resp = anon_client.app_api("page.access", "login", {
            "username": "alice", "password": "alice1234",
        })
        anon_client.assert_error(resp, 403)

    def test_login_wrong_password(self, anon_client):
        resp = anon_client.app_api("page.access", "login", {
            "username": "admin", "password": "wrong",
        })
        anon_client.assert_error(resp, 401)

    def test_login_nonexistent_user(self, anon_client):
        resp = anon_client.app_api("page.access", "login", {
            "username": "nonexistent", "password": "x",
        })
        anon_client.assert_error(resp, 403)

    def test_login_empty_fields(self, anon_client):
        resp = anon_client.app_api("page.access", "login", {
            "username": "", "password": "",
        })
        anon_client.assert_error(resp, 400)


class TestLandingPage:
    def test_landing_load(self, anon_client):
        resp = anon_client.app_api("page.landing", "load")
        body = anon_client.assert_ok(resp)
        data = body["data"].get("data", body["data"])
        counts = data.get("counts", {})
        assert counts.get("user", 0) >= 1
        assert counts.get("attribute_preset", 0) >= 4
        default_accounts = data.get("default_accounts", [])
        assert len(default_accounts) == 0


class TestIdpcoreInfo:
    def test_info(self, client):
        resp = client.route("/api/idpcore/info")
        body = client.assert_ok(resp)
        info = body["data"]["data"]
        assert "counts" in info
        assert info["counts"]["user"] >= 1
        assert info["counts"]["attribute_preset"] >= 4
