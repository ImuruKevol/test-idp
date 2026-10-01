import base64
import datetime
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLSigner, XMLVerifier, methods


ROOT = Path(__file__).resolve().parents[1]
NS = {
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "xenc": "http://www.w3.org/2001/04/xmlenc#",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


def load(relative, name):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def b64u(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


class MemoryJsonFs:
    def __init__(self):
        self.values = {}

    def exists(self, path):
        return path in self.values

    class Reader:
        def __init__(self, owner):
            self.owner = owner

        def json(self, path, default=None):
            return self.owner.values.get(path, default)

    class Writer:
        def __init__(self, owner):
            self.owner = owner

        def json(self, path, value, indent=None):
            self.owner.values[path] = value

    @property
    def read(self):
        return self.Reader(self)

    @property
    def write(self):
        return self.Writer(self)


def client_assertion(secret, client_id, audience, now, jti):
    header = b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64u(json.dumps({
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "iat": now,
        "exp": now + 120,
        "jti": jti,
    }).encode())
    value = f"{header}.{payload}"
    signature = b64u(hmac.new(secret.encode(), value.encode(), hashlib.sha256).digest())
    return f"{value}.{signature}"


def test_client_secret_jwt_is_verified_and_replay_is_rejected(monkeypatch):
    module = load("src/portal/oidcidp/model/struct/flow.py", "modern_oidc_flow")
    now = 2_000_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    fs = MemoryJsonFs()
    client = {
        "client_id": "rp-client-jwt",
        "client_secret": "strong-test-secret",
        "token_endpoint_auth_method": "client_secret_jwt",
        "extra": {},
        "expired": False,
        "active": True,
    }
    provider = SimpleNamespace(
        reviewops_profile=lambda value=None: "",
        info=lambda: {
            "issuer": "https://idp.example.test",
            "token_endpoint": "https://idp.example.test/api/oidc/token",
        },
        _fs=lambda: fs,
    )
    registry = SimpleNamespace(get=lambda client_id: client)
    flow = module.Flow(SimpleNamespace(provider=provider, registry=registry))
    assertion = client_assertion(
        client["client_secret"],
        client["client_id"],
        provider.info()["token_endpoint"],
        now,
        "replay-safe-jti",
    )
    request = {
        "client_id": client["client_id"],
        "client_assertion_type": module.CLIENT_ASSERTION_TYPE,
        "client_assertion": assertion,
    }

    assert flow._authenticate_client(request)[1] == "client_secret_jwt"
    with pytest.raises(module.OIDCFlowError, match="이미 사용된"):
        flow._authenticate_client(request)


def test_pkce_enforces_rfc_length_and_s256():
    module = load("src/portal/oidcidp/model/struct/flow.py", "modern_oidc_pkce")
    flow = module.Flow(SimpleNamespace())
    verifier = "A" * 43
    challenge = flow.generate_code_challenge(verifier, "S256")
    assert len(challenge) == 43
    flow._verify_pkce({"code_challenge": challenge, "code_challenge_method": "S256"}, verifier)
    with pytest.raises(module.OIDCFlowError, match="43~128"):
        flow.generate_code_challenge("short", "S256")


def test_private_key_jwt_uses_registered_public_jwk(monkeypatch):
    module = load("src/portal/oidcidp/model/struct/flow.py", "modern_oidc_private_key")
    provider_module = load("src/portal/oidcidp/model/struct/provider.py", "modern_oidc_jwk")
    now = 2_000_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = key.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "rp-key-1",
        "n": b64u(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": b64u(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
    }
    client = {
        "client_id": "rp-private-key",
        "client_secret": "",
        "token_endpoint_auth_method": "private_key_jwt",
        "jwks": {"keys": [jwk]},
        "extra": {},
        "expired": False,
        "active": True,
    }
    fs = MemoryJsonFs()
    provider_base = provider_module.Provider(SimpleNamespace())
    provider = SimpleNamespace(
        reviewops_profile=lambda value=None: "",
        info=lambda: {
            "issuer": "https://idp.example.test",
            "token_endpoint": "https://idp.example.test/api/oidc/token",
        },
        _fs=lambda: fs,
        public_key_from_jwk=provider_base.public_key_from_jwk,
    )
    flow = module.Flow(SimpleNamespace(
        provider=provider,
        registry=SimpleNamespace(get=lambda client_id: client),
    ))
    payload = {
        "iss": client["client_id"],
        "sub": client["client_id"],
        "aud": provider.info()["token_endpoint"],
        "iat": now,
        "exp": now + 120,
        "jti": "private-jti-1",
    }
    encoded_header = b64u(json.dumps({"alg": "RS256", "kid": "rp-key-1"}).encode())
    encoded_payload = b64u(json.dumps(payload).encode())
    signing_input = f"{encoded_header}.{encoded_payload}"
    signature = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    assertion = f"{signing_input}.{b64u(signature)}"
    request = {
        "client_id": client["client_id"],
        "client_assertion_type": module.CLIENT_ASSERTION_TYPE,
        "client_assertion": assertion,
    }

    assert flow._authenticate_client(request)[1] == "private_key_jwt"


def test_public_client_rejects_submitted_secret():
    module = load("src/portal/oidcidp/model/struct/flow.py", "modern_oidc_public")
    client = {
        "client_id": "public-rp",
        "token_endpoint_auth_method": "none",
        "client_secret": "",
        "extra": {},
        "expired": False,
        "active": True,
    }
    provider = SimpleNamespace(reviewops_profile=lambda value=None: "")
    flow = module.Flow(SimpleNamespace(
        provider=provider,
        registry=SimpleNamespace(get=lambda client_id: client),
    ))
    assert flow._authenticate_client({"client_id": "public-rp"})[1] == "none"
    with pytest.raises(module.OIDCFlowError, match="credential"):
        flow._authenticate_client({"client_id": "public-rp", "client_secret": "must-fail"})


def test_oidc_profiles_keep_nested_claims_and_subject_settings_isolated():
    module = load("src/portal/oidcidp/model/struct/provider.py", "modern_oidc_profiles")
    fs = MemoryJsonFs()
    provider = module.Provider(SimpleNamespace())
    provider._fs = lambda: fs
    configured = provider.configure_profile("profile-a", {
        "subject_source": "response.subject",
        "claim_overrides": {"response": {"subject": "external-user", "groups": ["a", "b"]}},
        "id_token_signing_alg": "ES256",
    })

    assert configured["subject_source"] == "response.subject"
    assert configured["claim_overrides"]["response"]["groups"] == ["a", "b"]
    assert provider.profile_settings("profile-a")["id_token_signing_alg"] == "ES256"
    assert provider.profile_settings("profile-b")["subject_source"] == "sub"


def test_oidc_id_token_signing_algorithms_are_verifiable(monkeypatch):
    module = load("src/portal/oidcidp/model/struct/provider.py", "modern_oidc_signing")
    module.wiz = SimpleNamespace(
        request=SimpleNamespace(query=lambda key, default="": default),
        config=lambda name: SimpleNamespace(OIDC_ISSUER="https://idp.example.test"),
    )
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    provider = module.Provider(SimpleNamespace())
    rs_public, _ = provider._rsa_jwk_pair(rsa_key, "rs-key")
    ps_public = dict(rs_public, kid="ps-key", alg="PS256")
    es_public, _ = provider._ec_jwk_pair(ec_key, "es-key")
    provider.jwks_public = lambda: {"keys": [rs_public, ps_public, es_public]}
    provider._private_key = lambda alg="RS256": ec_key if alg == "ES256" else rsa_key
    monkeypatch.setattr(module.time, "time", lambda: 2_000_000_000)

    for algorithm in ["RS256", "PS256", "ES256"]:
        issued = provider.issue_id_token("rp", "subject", signing_alg=algorithm)
        verified = provider.verify_jwt(
            issued["token"],
            allowed_algs=[algorithm],
            expected_issuer="https://idp.example.test",
        )
        assert verified["header"]["alg"] == algorithm


def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "protocol-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    cert_body = "".join(line for line in cert_pem.splitlines() if not line.startswith("---"))
    return key, key_pem, cert_pem, cert_body


class DebugFs:
    def __init__(self):
        self.values = {}

    def write(self, path, value):
        self.values[path] = value


def test_encrypted_assertion_uses_signed_then_encrypted_aes_gcm():
    module = load("src/portal/samlidp/model/struct/process.py", "modern_saml_process")
    sp_key, _, _, sp_cert_body = keypair()
    _, idp_key_pem, idp_cert_pem, _ = keypair()
    sp_entity = "https://sp.example.test/metadata"
    metadata = SimpleNamespace(
        entity_id=lambda profile: "https://idp.example.test/metadata",
        get_key_pem=lambda: idp_key_pem,
        get_cert_pem=lambda: idp_cert_pem,
        normalize_omit_attributes=lambda value: value or [],
        normalize_attribute_values=lambda value: value or {},
    )
    registry = SimpleNamespace(get=lambda entity_id: {
        "entity_id": sp_entity,
        "certificates": {"encryption": [sp_cert_body], "signing": []},
    })
    user = {"id": "user-1", "username": "tester", "email": "tester@example.test", "saml_attributes": {}}
    core = SimpleNamespace(
        user=SimpleNamespace(get=lambda **kwargs: user),
        attribute_preset=SimpleNamespace(get=lambda **kwargs: None),
        saml_attribute_spec=lambda name: None,
    )
    db = SimpleNamespace(update=lambda *args, **kwargs: None)
    process = module.Process(SimpleNamespace(metadata=metadata, registry=registry, core=core, db=lambda name: db))
    process._debug_fs = lambda: DebugFs()
    result = process.build_response({
        "user_id": user["id"],
        "sp_entity_id": sp_entity,
        "acs_url": "https://sp.example.test/acs",
        "request_id": "_request-1",
        "sign_response": True,
        "sign_assertion": True,
        "encrypt_assertion": True,
        "content_encryption_algorithm": "aes256-gcm",
        "key_transport_algorithm": "rsa-oaep-sha256",
    })
    root = etree.fromstring(result["response_xml"].encode())
    encrypted_key = base64.b64decode(root.find(".//xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue", NS).text)
    content_key = sp_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    payload = base64.b64decode(root.find(".//xenc:EncryptedData/xenc:CipherData/xenc:CipherValue", NS).text)
    assertion_xml = AESGCM(content_key).decrypt(payload[:12], payload[12:], None)
    assertion = etree.fromstring(assertion_xml)

    assert assertion.tag == f"{{{NS['saml']}}}Assertion"
    assert assertion.find("ds:Signature", NS) is not None
    XMLVerifier().verify(assertion, x509_cert=idp_cert_pem, id_attribute="ID")
    assert result["encrypted_assertion"] is True


def test_saml_encryption_algorithm_matrix_builds():
    module = load("src/portal/samlidp/model/struct/process.py", "modern_saml_matrix")
    _, _, _, sp_cert_body = keypair()
    sp_entity = "https://sp.example.test/metadata"
    process = module.Process(SimpleNamespace(registry=SimpleNamespace(get=lambda entity_id: {
        "certificates": {"encryption": [sp_cert_body], "encryption_methods": []},
    })))
    for content_algorithm in module.CONTENT_ENCRYPTION_ALGORITHMS:
        for key_transport in module.KEY_TRANSPORT_ALGORITHMS:
            assertion = etree.Element(f"{{{NS['saml']}}}Assertion")
            encrypted = process._encrypt_assertion(
                assertion,
                sp_entity,
                content_algorithm,
                key_transport,
            )
            assert encrypted.find(".//xenc:EncryptedData", NS) is not None


def test_idp_metadata_is_signed_and_advertises_encryption():
    module = load("src/portal/samlidp/model/struct/metadata.py", "modern_saml_metadata")
    module.wiz = SimpleNamespace(request=SimpleNamespace(query=lambda key, default="": default))
    _, key_pem, cert_pem, cert_body = keypair()
    _, encryption_key_pem, encryption_cert_pem, encryption_cert_body = keypair()
    metadata = module.Metadata(SimpleNamespace())
    metadata._base_url = lambda: "https://idp.example.test"
    metadata._ensure_keypair = lambda: None
    metadata.get_key_pem = lambda: key_pem
    metadata.get_cert_pem = lambda: cert_pem
    metadata.get_cert_body = lambda: cert_body
    metadata.get_encryption_key_pem = lambda: encryption_key_pem
    metadata.get_encryption_cert_pem = lambda: encryption_cert_pem
    metadata.get_encryption_cert_body = lambda: encryption_cert_body
    xml = metadata.generate_xml()
    root = etree.fromstring(xml.encode())

    XMLVerifier().verify(root, x509_cert=cert_pem, id_attribute="ID")
    encryption = root.xpath(".//*[local-name()='KeyDescriptor' and @use='encryption']")
    assert len(encryption) == 1
    signing_cert = root.xpath("string(.//*[local-name()='KeyDescriptor' and @use='signing']//*[local-name()='X509Certificate'])")
    encryption_cert = root.xpath("string(.//*[local-name()='KeyDescriptor' and @use='encryption']//*[local-name()='X509Certificate'])")
    assert signing_cert == cert_body
    assert encryption_cert == encryption_cert_body
    assert signing_cert != encryption_cert
    assert root.xpath("count(.//*[local-name()='Organization'])") == 1.0


def test_saml_logout_request_requires_and_verifies_sp_signature():
    module = load("src/portal/samlidp/model/struct/process.py", "modern_saml_logout")
    _, sp_key_pem, sp_cert_pem, sp_cert_body = keypair()
    sp_entity = "https://sp.example.test/metadata"
    destination = "https://idp.example.test/api/saml/slo/post"
    sp = {
        "entity_id": sp_entity,
        "certificates": {"signing": [sp_cert_body], "encryption": []},
    }
    registry = SimpleNamespace(
        get=lambda entity_id: sp if entity_id == sp_entity else None,
        is_expired=lambda row: False,
    )
    process = module.Process(SimpleNamespace(registry=registry))
    process._debug_fs = lambda: DebugFs()
    process._match_sessions = lambda issuer, indexes, nameid: []
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    request = etree.Element(
        f"{{{module.NS['samlp']}}}LogoutRequest",
        nsmap={"samlp": module.NS["samlp"], "saml": module.NS["saml"]},
        ID="_logout-request-1",
        Version="2.0",
        IssueInstant=now.isoformat().replace("+00:00", "Z"),
        Destination=destination,
    )
    issuer = etree.SubElement(request, f"{{{module.NS['saml']}}}Issuer")
    issuer.text = sp_entity
    name_id = etree.SubElement(request, f"{{{module.NS['saml']}}}NameID")
    name_id.text = "tester@example.test"
    session_index = etree.SubElement(request, f"{{{module.NS['samlp']}}}SessionIndex")
    session_index.text = "_session-1"
    signed = XMLSigner(
        method=methods.enveloped,
        signature_algorithm="rsa-sha256",
        digest_algorithm="sha256",
    ).sign(request, key=sp_key_pem, cert=sp_cert_pem, reference_uri="_logout-request-1")
    signed_b64 = base64.b64encode(etree.tostring(signed)).decode()

    result = process.parse_logout_request(
        signed_b64,
        binding="POST",
        expected_destination=destination,
    )
    assert result["signature_valid"] is True
    assert result["standards_status"] == "standard"

    unsigned_b64 = base64.b64encode(etree.tostring(request)).decode()
    with pytest.raises(Exception, match="signature"):
        process.parse_logout_request(unsigned_b64, binding="POST", expected_destination=destination)
    compatible = process.parse_logout_request(
        unsigned_b64,
        binding="POST",
        expected_destination=destination,
        allow_unsigned=True,
    )
    assert compatible["standards_status"] == "compatibility"
