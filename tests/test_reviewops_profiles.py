import importlib.util
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest
from lxml import etree


PROJECT = Path(__file__).resolve().parents[1]


def _load(relative_path, module_name):
    path = PROJECT / relative_path
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _request(values=None):
    values = dict(values or {})
    return SimpleNamespace(
        query=lambda key, default="": values.get(key, default),
        headers=lambda key, default="": {
            "Host": "debug-idp.nanoha.kr",
            "X-Forwarded-Proto": "https",
        }.get(key, default),
    )


def _provider(values=None):
    module = _load(
        "src/portal/oidcidp/model/struct/provider.py",
        f"reviewops_oidc_provider_{id(values)}",
    )
    config = SimpleNamespace(
        OIDC_ISSUER="https://debug-idp.nanoha.kr",
        OIDC_DISCOVERY_PATH="/.well-known/openid-configuration",
        OIDC_JWKS_PATH="/api/oidc/jwks",
        OIDC_AUTHORIZE_PATH="/api/oidc/authorize",
        OIDC_TOKEN_PATH="/api/oidc/token",
        OIDC_USERINFO_PATH="/api/oidc/userinfo",
        OIDC_LOGOUT_PATH="/api/oidc/logout",
    )
    module.wiz = SimpleNamespace(request=_request(values), config=lambda name: config)
    registry = SimpleNamespace(
        response_type_options=lambda: ["code"],
        grant_type_options=lambda: ["authorization_code"],
        auth_method_options=lambda: ["client_secret_basic"],
    )
    provider = module.Provider(SimpleNamespace(registry=registry))
    provider.jwks_public = lambda: {"keys": [{"kid": "reviewops-test"}]}
    provider.supported_scopes = lambda: ["openid"]
    provider.supported_claims = lambda: ["sub"]
    return module, provider


def test_oidc_default_profile_keeps_existing_contract():
    _, provider = _provider()
    info = provider.info()
    discovery = provider.discovery()

    assert info["issuer"] == "https://debug-idp.nanoha.kr"
    assert info["discovery_endpoint"] == "https://debug-idp.nanoha.kr/.well-known/openid-configuration"
    assert discovery["authorization_endpoint"] == "https://debug-idp.nanoha.kr/api/oidc/authorize"
    assert discovery["token_endpoint"] == "https://debug-idp.nanoha.kr/api/oidc/token"
    assert discovery["userinfo_endpoint"] == "https://debug-idp.nanoha.kr/api/oidc/userinfo"
    assert discovery["jwks_uri"] == "https://debug-idp.nanoha.kr/api/oidc/jwks"
    assert discovery["end_session_endpoint"] == "https://debug-idp.nanoha.kr/api/oidc/logout"


def test_oidc_reviewops_profile_is_stateless_and_propagated_to_every_endpoint():
    profile = "reviewops-20260714-a1"
    _, provider = _provider({"reviewops_profile": profile})
    info = provider.info()
    discovery = provider.discovery()

    assert discovery["issuer"] == f"https://debug-idp.nanoha.kr/reviewops/oidc/{profile}"
    endpoint_names = [
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "jwks_uri",
        "end_session_endpoint",
    ]
    for name in endpoint_names:
        parsed = urlparse(discovery[name])
        assert parse_qs(parsed.query) == {"reviewops_profile": [profile]}
    assert parse_qs(urlparse(info["discovery_endpoint"]).query) == {"reviewops_profile": [profile]}


def test_oidc_tokens_use_epoch_time_independent_of_server_timezone(monkeypatch):
    module, provider = _provider({"reviewops_profile": "reviewops-clock"})
    monkeypatch.setattr(module.time, "time", lambda: 2_000_000_000)
    provider.sign_jwt = lambda payload, headers=None: dict(payload)

    id_token = provider.issue_id_token("client", "subject", ttl_seconds=600)
    access_token = provider.issue_access_token("client", "subject", ttl_seconds=3600)

    assert id_token["payload"]["iat"] == 2_000_000_000
    assert id_token["payload"]["exp"] == 2_000_000_600
    assert access_token["payload"]["iat"] == 2_000_000_000
    assert access_token["payload"]["exp"] == 2_000_003_600


@pytest.mark.parametrize("value", ["UPPER", "has_underbar", "with space", "a" * 65, "-bad/"])
def test_oidc_reviewops_profile_rejects_values_outside_contract(value):
    module, _ = _provider()
    with pytest.raises(ValueError, match="reviewops_profile"):
        module.normalize_reviewops_profile(value)


def _saml_metadata(values=None):
    module = _load(
        "src/portal/samlidp/model/struct/metadata.py",
        f"reviewops_saml_metadata_{id(values)}",
    )
    season_config = SimpleNamespace(get=lambda key, default=None: default)
    module.wiz = SimpleNamespace(request=_request(values), config=lambda name: season_config)
    metadata = module.Metadata(SimpleNamespace())
    metadata._ensure_keypair = lambda: None
    metadata.get_cert_body = lambda: "REVIEWOPS_TEST_CERTIFICATE"
    return module, metadata


def _metadata_contract(xml):
    root = etree.fromstring(xml.encode("utf-8"))
    namespace = {"md": "urn:oasis:names:tc:SAML:2.0:metadata"}
    locations = [node.get("Location") for node in root.xpath(".//md:SingleSignOnService | .//md:SingleLogoutService", namespaces=namespace)]
    return root.get("entityID"), locations


class _MemoryJsonFs:
    def __init__(self):
        self.values = {}

        class _Reader:
            def __init__(self, owner):
                self.owner = owner

            def json(self, path, default=None):
                return self.owner.values.get(path, default)

        class _Writer:
            def __init__(self, owner):
                self.owner = owner

            def json(self, path, value, indent=None):
                self.owner.values[path] = value

        self.read = _Reader(self)
        self.write = _Writer(self)

    def exists(self, path):
        return path in self.values

    def files(self, filepath=""):
        return list(self.values)

    def delete(self, path):
        self.values.pop(path, None)


def test_oidc_saved_profiles_are_listed_in_name_order_with_status():
    _, provider = _provider()
    fs = _MemoryJsonFs()
    provider._fs = lambda: fs

    provider.configure_profile("zeta", {"response_variant": "expired"})
    provider.configure_profile("alpha", {"id_token_signing_alg": "RS256"})

    profiles = provider.list_profiles()
    assert [item["name"] for item in profiles] == ["alpha", "zeta"]
    assert profiles[0]["standards_status"] == "standard"
    assert profiles[1]["standards_status"] == "compatibility"
    provider.clear_profile("alpha")
    assert [item["name"] for item in provider.list_profiles()] == ["zeta"]


def test_saml_default_profile_keeps_existing_contract():
    _, metadata = _saml_metadata()
    entity_id, locations = _metadata_contract(metadata.generate_xml())

    assert entity_id == "https://debug-idp.nanoha.kr/api/saml/metadata"
    assert locations == [
        "https://debug-idp.nanoha.kr/api/saml/slo",
        "https://debug-idp.nanoha.kr/api/saml/slo",
        "https://debug-idp.nanoha.kr/api/saml/sso",
        "https://debug-idp.nanoha.kr/api/saml/sso",
    ]


def test_saml_reviewops_profile_changes_entity_and_preserves_profile_on_sso_slo():
    profile = "reviewops-20260714-b2"
    _, metadata = _saml_metadata({"reviewops_profile": profile})
    entity_id, locations = _metadata_contract(metadata.generate_xml())

    assert entity_id == f"https://debug-idp.nanoha.kr/reviewops/saml/{profile}"
    for location in locations:
        assert parse_qs(urlparse(location).query) == {"reviewops_profile": [profile]}


def test_saml_response_defaults_are_profile_isolated_and_clearable():
    _, metadata = _saml_metadata()
    fs = _MemoryJsonFs()
    metadata._cert_fs = lambda: fs

    configured = metadata.configure_response_defaults(
        "reviewops-signed-a",
        sign_response=False,
        sign_assertion=True,
    )

    assert configured["configured"] is True
    saved = metadata.response_defaults("reviewops-signed-a")
    assert saved["reviewops_profile"] == "reviewops-signed-a"
    assert saved["sign_response"] is False
    assert saved["sign_assertion"] is True
    assert saved["omit_attributes"] == []
    assert saved["attribute_values"] == {}
    assert saved["configured"] is True
    assert saved["standards_status"] == "standard"
    assert metadata.response_defaults("reviewops-signed-b")["sign_response"] is True
    assert metadata.clear_response_defaults("reviewops-signed-a")["cleared"] is True
    assert metadata.response_defaults("reviewops-signed-a")["configured"] is False


def test_saml_response_defaults_mark_compatibility_options_explicitly():
    _, metadata = _saml_metadata()
    fs = _MemoryJsonFs()
    metadata._cert_fs = lambda: fs

    configured = metadata.configure_response_defaults(
        "reviewops-legacy-a",
        sign_response=False,
        sign_assertion=False,
        response_options={
            "encrypt_assertion": True,
            "content_encryption_algorithm": "tripledes-cbc",
            "key_transport_algorithm": "rsa-1_5",
            "response_variant": "expired",
            "time_offset_seconds": -60,
            "assertion_ttl_seconds": 300,
        },
    )

    assert configured["standards_status"] == "compatibility"
    assert len(configured["standards_warnings"]) >= 4


def test_saml_saved_profiles_are_listed_in_name_order_with_status():
    _, metadata = _saml_metadata()
    fs = _MemoryJsonFs()
    metadata._cert_fs = lambda: fs

    metadata.configure_response_defaults("zeta", sign_response=False, sign_assertion=False)
    metadata.configure_response_defaults("alpha", sign_response=True, sign_assertion=True)

    profiles = metadata.list_response_profiles()
    assert [item["name"] for item in profiles] == ["alpha", "zeta"]
    assert profiles[0]["standards_status"] == "standard"
    assert profiles[1]["standards_status"] == "compatibility"
    metadata.clear_response_defaults("alpha")
    assert [item["name"] for item in metadata.list_response_profiles()] == ["zeta"]


def test_saml_idp_info_api_supports_runtime_model_without_profile_list_method():
    fs = _MemoryJsonFs()
    fs.values["reviewops-profile-zeta.json"] = {}
    fs.values["reviewops-profile-alpha.json"] = {}
    metadata = SimpleNamespace(
        info=lambda profile: {"entity_id": "https://idp.example.test/metadata"},
        _cert_fs=lambda: fs,
        response_defaults=lambda profile: {
            "standards_status": "standard",
            "standards_warnings": [],
            "sign_response": True,
            "sign_assertion": True,
            "response_variant": "standard",
        },
    )
    responses = []
    fake_wiz = SimpleNamespace(
        model=lambda name: SimpleNamespace(metadata=metadata),
        request=SimpleNamespace(query=lambda key, default="": default),
        response=SimpleNamespace(
            status=lambda code, **kwargs: responses.append((code, kwargs))
        ),
    )
    path = PROJECT / "src/portal/samlidp/app/idp.metadata/api.py"
    spec = importlib.util.spec_from_file_location("saml_idp_info_api_fallback", path)
    module = importlib.util.module_from_spec(spec)
    module.wiz = fake_wiz
    spec.loader.exec_module(module)

    module.info()

    assert responses[0][0] == 200
    assert [item["name"] for item in responses[0][1]["data"]["profiles"]] == [
        "alpha",
        "zeta",
    ]


@pytest.mark.parametrize("value", ["UPPER", "has_underbar", "with space", "a" * 65, "-bad/"])
def test_saml_reviewops_profile_rejects_values_outside_contract(value):
    module, _ = _saml_metadata()
    with pytest.raises(ValueError, match="reviewops_profile"):
        module.normalize_reviewops_profile(value)


def test_oidc_code_and_saml_response_sources_bind_the_profile():
    oidc_flow = (PROJECT / "src/portal/oidcidp/model/struct/flow.py").read_text()
    oidc_route = (PROJECT / "src/portal/oidcidp/route/oidc/controller.py").read_text()
    saml_process = (PROJECT / "src/portal/samlidp/model/struct/process.py").read_text()
    saml_route = (PROJECT / "src/portal/samlidp/route/saml/controller.py").read_text()

    assert 'code_extra["reviewops_profile"] = reviewops_profile' in oidc_flow
    assert "authorization code의 reviewops_profile이 token endpoint와 일치하지 않습니다." in oidc_flow
    assert '"reviewops_profile",' in oidc_route
    assert saml_process.count("metadata.entity_id(reviewops_profile)") >= 4
    assert 'state["reviewops_profile"] = reviewops_profile' in saml_route
    assert '"reviewops_profile": state.get("reviewops_profile", "")' in saml_route
    assert 'action == "reviewops-profile-config"' in saml_route
    assert "response_defaults[\"sign_response\"]" in saml_route
