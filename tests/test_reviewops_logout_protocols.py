import datetime
import importlib.util
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]


def load(relative, name):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Session:
    def __init__(self, values):
        self.values = dict(values)

    def get(self, key, default=""):
        return self.values.get(key, default)


def oidc_flow(verify_error=""):
    module = load("src/portal/oidcidp/model/struct/flow.py", f"logout_oidc_{id(verify_error)}")
    client = {
        "client_id": "rp-logout",
        "client_name": "Logout RP",
        "client_secret": "secret",
        "post_logout_redirect_uris": ["https://rp.example.test/logout?from=idp#done"],
        "extra": {},
        "expired": False,
        "active": True,
    }
    calls = {}

    def verify(token, **kwargs):
        calls.update(kwargs)
        if verify_error:
            raise ValueError(verify_error)
        return {
            "payload": {
                "iss": "https://idp.example.test",
                "aud": client["client_id"],
                "sub": "user-1",
                "sid": "sid-1",
                "iat": 1_900_000_000,
                "exp": 1_900_000_100,
            }
        }

    provider = SimpleNamespace(
        reviewops_profile=lambda value=None: "",
        issuer=lambda value=None: "https://idp.example.test",
        decode_without_verify=lambda token: {"payload": {"aud": client["client_id"]}},
        verify_jwt=verify,
    )
    registry = SimpleNamespace(
        get=lambda client_id: client if client_id == client["client_id"] else None,
        public_view=lambda value: {key: item for key, item in value.items() if key != "client_secret"},
    )
    struct = SimpleNamespace(
        provider=provider,
        registry=registry,
        session=Session({"id": "user-1", "oidc_sid": "sid-1", "username": "tester"}),
    )
    return module, module.Flow(struct), calls


def test_end_session_accepts_recent_expired_hint_and_returns_state_before_fragment(monkeypatch):
    module, flow, calls = oidc_flow()
    monkeypatch.setattr(module.time, "time", lambda: 2_000_000_000)
    result = flow.end_session({
        "id_token_hint": "signed-id-token",
        "post_logout_redirect_uri": "https://rp.example.test/logout?from=idp#done",
        "state": "return-state",
    })

    assert calls["allow_expired"] is True
    assert result["id_token_hint_valid"] is True
    assert result["session_match"]["sid_match"] is True
    assert result["redirect_target"] == "https://rp.example.test/logout?from=idp&state=return-state#done"
    assert result["confirmation_required"] is True


def test_end_session_never_redirects_from_an_invalid_id_token_hint():
    _, flow, _ = oidc_flow("bad signature")
    result = flow.end_session({
        "client_id": "rp-logout",
        "id_token_hint": "bad-id-token",
        "post_logout_redirect_uri": "https://rp.example.test/logout?from=idp#done",
    })

    assert result["id_token_hint_valid"] is False
    assert result["redirect_target"] == ""
    assert result["standards_status"] == "rejected"


def test_end_session_requires_exact_registered_redirect():
    _, flow, _ = oidc_flow()
    result = flow.end_session({
        "client_id": "rp-logout",
        "post_logout_redirect_uri": "https://attacker.example.test/logout",
    })
    assert result["redirect_target"] == ""
    assert "등록되지 않은" in result["redirect_validation_error"]
    assert result["standards_status"] == "rejected"


def test_slo_endpoint_uses_matching_binding_and_response_location():
    module = load("src/portal/samlidp/model/struct/process.py", "logout_saml_endpoint")
    sp = {
        "entity_id": "https://sp.example.test/metadata",
        "slo_url": [
            {
                "binding": module.BINDING_POST,
                "location": "https://sp.example.test/slo/post",
                "response_location": "https://sp.example.test/slo/post-response",
            },
            {
                "binding": module.BINDING_REDIRECT,
                "location": "https://sp.example.test/slo/redirect",
                "response_location": "",
            },
        ],
    }
    registry = SimpleNamespace(get=lambda entity_id: sp, is_expired=lambda item: False)
    process = module.Process(SimpleNamespace(registry=registry))

    post = process.resolve_slo_endpoint(sp["entity_id"], "POST", for_response=True)
    redirect = process.resolve_slo_endpoint(sp["entity_id"], "REDIRECT")
    assert post["url"].endswith("/post-response")
    assert redirect["url"].endswith("/redirect")
    assert post["standards_status"] == redirect["standards_status"] == "standard"


def test_slo_redirect_signature_rejects_duplicate_protocol_parameters():
    module = load("src/portal/samlidp/model/struct/process.py", "logout_saml_duplicate")
    process = module.Process(SimpleNamespace(registry=SimpleNamespace()))
    valid, error = process.verify_redirect_query_signature(
        "SAMLRequest=one&SAMLRequest=two&SigAlg=rsa&Signature=value",
        "SAMLRequest",
        "https://sp.example.test/metadata",
    )
    assert valid is False
    assert error == "redirect_signature_parameter_duplicated"


def test_saml_metadata_keeps_single_logout_response_location():
    module = load("src/portal/samlidp/model/struct/registry.py", "logout_saml_registry")
    registry = module.Registry(SimpleNamespace())
    metadata = """<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.test/metadata">
      <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.test/slo" ResponseLocation="https://sp.example.test/slo/response"/>
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.test/acs" index="0"/>
      </md:SPSSODescriptor>
    </md:EntityDescriptor>"""
    parsed = registry.parse_metadata(metadata)

    assert parsed["slo_endpoints"][0]["response_location"] == "https://sp.example.test/slo/response"


def test_logout_routes_require_confirmation_and_keep_invalid_slo_session():
    oidc_route = (ROOT / "src/portal/oidcidp/route/oidc/controller.py").read_text()
    saml_route = (ROOT / "src/portal/samlidp/route/saml/controller.py").read_text()

    assert "struct.flow.end_session(params)" in oidc_route
    assert 'method == "POST"' in oidc_route
    assert "_build_logout_confirmation_html" in oidc_route
    invalid_branch = saml_route.split('if result.get("valid") is True:', 1)[1].split("if not saml_request:", 1)[0]
    assert "struct.session.clear()" in invalid_branch
    assert invalid_branch.index("struct.session.clear()") < invalid_branch.index("status=400")
    assert "resolve_slo_endpoint" in saml_route


def test_logout_consoles_expose_standard_end_session_and_slo_actions():
    oidc_view = (ROOT / "src/portal/oidcidp/app/logout.check/view.html").read_text()
    oidc_code = (ROOT / "src/portal/oidcidp/app/logout.check/view.ts").read_text()
    saml_view = (ROOT / "src/portal/samlidp/app/logout.check/view.pug").read_text()
    saml_code = (ROOT / "src/portal/samlidp/app/logout.check/view.ts").read_text()

    assert "logout_hint" in oidc_view and "ui_locales" in oidc_view
    assert "openEndSession()" in oidc_code and "End session 열기" in oidc_view
    assert "idpBinding" in saml_code
    assert "sendIdpLogoutRequest()" in saml_code and "SP로 전송" in saml_view
    assert "호환 시험으로 생성됨" in saml_view


def test_slo_response_rejects_stale_issue_instant():
    module = load("src/portal/samlidp/model/struct/process.py", "logout_saml_stale")
    process = module.Process(SimpleNamespace(registry=SimpleNamespace()))
    root = module.etree.Element(
        f"{{{module.NS['samlp']}}}LogoutResponse",
        nsmap={"samlp": module.NS["samlp"], "saml": module.NS["saml"]},
        ID="_response-stale",
        Version="2.0",
        IssueInstant=(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        InResponseTo="_request-1",
        Destination="https://idp.example.test/slo",
    )
    issuer = module.etree.SubElement(root, f"{{{module.NS['saml']}}}Issuer")
    issuer.text = "https://sp.example.test/metadata"
    status = module.etree.SubElement(root, f"{{{module.NS['samlp']}}}Status")
    code = module.etree.SubElement(status, f"{{{module.NS['samlp']}}}StatusCode")
    code.set("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")
    process._debug_fs = lambda: SimpleNamespace(write=lambda *args: None)
    encoded = module.base64.b64encode(module.etree.tostring(root)).decode()

    result = process.parse_logout_response(
        encoded,
        expected={
            "request_id": "_request-1",
            "sp_entity_id": "https://sp.example.test/metadata",
            "relay_state": "",
            "response_destination": "https://idp.example.test/slo",
        },
    )
    assert result["issue_instant_valid"] is False
    assert result["valid"] is False
