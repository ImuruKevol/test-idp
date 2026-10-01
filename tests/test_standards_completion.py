import base64
import datetime
import os
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest
import saml2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLVerifier


ROOT = Path(__file__).resolve().parents[1]
NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata"
NS_DS = "http://www.w3.org/2000/09/xmldsig#"


def load(relative, name):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TokenDb:
    def __init__(self, row):
        self.records = [row]

    def get(self, **where):
        for row in self.records:
            if all(row.get(key) == value for key, value in where.items()):
                return row
        return None

    def update(self, data, **where):
        row = self.get(**where)
        if row is not None:
            row.update(data)

    def rows(self, **where):
        return [
            row for row in self.records
            if all(row.get(key) == value for key, value in where.items())
        ]

    def insert(self, data):
        value = dict(data)
        value.setdefault("id", f"token-{len(self.records) + 1}")
        self.records.append(value)
        return value["id"]


class MetadataFs:
    def __init__(self):
        self.values = {}

    def exists(self, path):
        return path in self.values

    def files(self, filepath=""):
        return list(self.values)

    def delete(self, path):
        self.values.pop(path, None)

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


class RawFs:
    def __init__(self, values=None):
        self.values = dict(values or {})

    def exists(self, path):
        return path in self.values

    def read(self, path):
        return self.values[path]

    def write(self, path, value):
        self.values[path] = value


def metadata_keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "federation.test")])
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
    return (
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
        cert.public_bytes(serialization.Encoding.PEM).decode(),
    )


@pytest.fixture(scope="module")
def saml_metadata_schema():
    schema_dir = Path(saml2.__file__).resolve().parent / "data" / "schemas"

    class LocalSchemaResolver(etree.Resolver):
        def resolve(self, url, public_id, context):
            local = {
                "http://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd": "xmldsig-core-schema.xsd",
                "http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/xenc-schema.xsd": "xenc-schema.xsd",
                "http://www.w3.org/2001/xml.xsd": "xml.xsd",
            }.get(url)
            if local:
                return self.resolve_filename(str(schema_dir / local), context)
            return None

    parser = etree.XMLParser(no_network=True)
    parser.resolvers.add(LocalSchemaResolver())
    wrapper = f"""<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
      <xs:import namespace="urn:oasis:names:tc:SAML:2.0:metadata" schemaLocation="{(schema_dir / 'saml-schema-metadata-2.0.xsd').as_uri()}"/>
      <xs:import namespace="http://www.w3.org/2009/xmlenc11#" schemaLocation="{(schema_dir / 'xenc-schema-11.xsd').as_uri()}"/>
    </xs:schema>"""
    document = etree.fromstring(
        wrapper.encode("utf-8"),
        parser,
        base_url=(schema_dir / "combined-metadata-schema.xsd").as_uri(),
    )
    return etree.XMLSchema(etree.ElementTree(document))


def sp_metadata_xml(binding, valid_until="", protocol="urn:oasis:names:tc:SAML:2.0:protocol"):
    validity = f' validUntil="{valid_until}"' if valid_until else ""
    return f"""<md:EntityDescriptor xmlns:md="{NS_MD}" entityID="https://sp.example.test/metadata"{validity}>
      <md:SPSSODescriptor protocolSupportEnumeration="{protocol}">
        <md:AssertionConsumerService Binding="{binding}" Location="https://sp.example.test/acs" index="0"/>
      </md:SPSSODescriptor>
    </md:EntityDescriptor>"""


def test_discovery_advertises_only_implemented_secure_code_flows():
    module = load("src/portal/oidcidp/model/struct/provider.py", "standards_provider_discovery")
    registry = SimpleNamespace(
        scope_options=lambda: ["openid", "offline_access"],
        auth_method_options=lambda: ["client_secret_basic", "none"],
    )
    core = SimpleNamespace(attribute_preset=SimpleNamespace(list=lambda protocol="": []))
    provider = module.Provider(SimpleNamespace(registry=registry, core=core))
    provider.info = lambda reviewops_profile=None: {
        "issuer": "https://idp.example.test",
        "authorization_endpoint": "https://idp.example.test/api/oidc/authorize",
        "token_endpoint": "https://idp.example.test/api/oidc/token",
        "userinfo_endpoint": "https://idp.example.test/api/oidc/userinfo",
        "jwks_uri": "https://idp.example.test/api/oidc/jwks",
        "end_session_endpoint": "https://idp.example.test/api/oidc/logout",
        "response_types_supported": ["code"],
        "response_modes_supported": ["query", "fragment", "form_post"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "none"],
        "scopes_supported": ["openid", "offline_access"],
        "claims_supported": ["sub"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_signing_alg_values_supported": ["RS256"],
        "code_challenge_methods_supported": ["S256"],
        "dynamic_client_registration_supported": False,
    }
    provider._base_issuer = lambda: "https://idp.example.test"

    discovery = provider.discovery()
    assert discovery["response_types_supported"] == ["code"]
    assert discovery["response_modes_supported"] == ["query", "fragment", "form_post"]
    assert discovery["grant_types_supported"] == ["authorization_code", "refresh_token"]
    assert discovery["code_challenge_methods_supported"] == ["S256"]


def test_registry_rejects_unimplemented_front_channel_and_client_credentials_flows():
    module = load("src/portal/oidcidp/model/struct/registry.py", "standards_registry")
    registry = module.Registry(SimpleNamespace())
    base = {
        "client_name": "Standards RP",
        "redirect_uris": ["https://rp.example.test/callback"],
        "token_endpoint_auth_method": "client_secret_basic",
    }
    with pytest.raises(Exception, match="grant_type"):
        registry._build_payload(dict(base, grant_types=["client_credentials"]))
    with pytest.raises(Exception, match="response_type"):
        registry._build_payload(dict(base, response_types=["id_token"]))


def test_refresh_token_is_rotated_and_replay_is_rejected():
    provider_module = load("src/portal/oidcidp/model/struct/provider.py", "standards_refresh_provider")
    flow_module = load("src/portal/oidcidp/model/struct/flow.py", "standards_refresh_flow")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    provider = provider_module.Provider(SimpleNamespace())
    public_jwk, _ = provider._rsa_jwk_pair(key, "refresh-rs256")
    provider._private_key = lambda alg="RS256": key
    provider.jwks_public = lambda: {"keys": [public_jwk]}
    provider.issuer = lambda reviewops_profile=None: "https://idp.example.test"
    provider.reviewops_profile = lambda value=None: ""
    provider.profile_settings = lambda profile: {
        "id_token_signing_alg": "RS256",
        "response_variant": "standard",
        "time_offset_seconds": 0,
        "token_ttl_seconds": 600,
        "refresh_token_ttl_seconds": 3600,
        "acr": "",
        "amr": ["pwd"],
    }

    issued = provider.issue_refresh_token(
        "rp-refresh",
        "subject-1",
        scope="openid offline_access",
        ttl_seconds=3600,
    )
    now = datetime.datetime.now()
    token_db = TokenDb({
        "id": "token-1",
        "client_id": "rp-refresh",
        "user_id": "user-1",
        "refresh_token_jti": issued["payload"]["jti"],
        "refresh_token_expires": now + datetime.timedelta(hours=1),
        "refresh_token_consumed": None,
        "debug_key": "debug-1",
        "raw_response": {
            "userinfo": {"sub": "subject-1", "email": "tester@example.test"},
            "id_token_payload": {"auth_time": int(now.timestamp()), "sid": "sid-1"},
        },
    })
    user = {"id": "user-1", "username": "tester"}
    core = SimpleNamespace(user=SimpleNamespace(
        get=lambda id: user if id == "user-1" else None,
        is_expired=lambda value: False,
    ))
    struct = SimpleNamespace(
        provider=provider,
        core=core,
        db=lambda name: token_db,
    )
    flow = flow_module.Flow(struct)
    client = {
        "client_id": "rp-refresh",
        "client_secret": "secret",
        "token_endpoint_auth_method": "client_secret_basic",
        "grant_types": ["authorization_code", "refresh_token"],
    }
    request = {
        "grant_type": "refresh_token",
        "refresh_token": issued["token"],
        "scope": "openid",
    }

    result = flow._refresh_token_grant(request, client, "client_secret_basic")
    assert result["token_response"]["refresh_token"] != issued["token"]
    assert result["token_response"]["scope"] == "openid"
    assert token_db.records[0]["refresh_token_consumed"] is not None
    assert token_db.records[1]["refresh_token_parent_jti"] == issued["payload"]["jti"]
    with pytest.raises(flow_module.OIDCFlowError, match="이미 사용된"):
        flow._refresh_token_grant(request, client, "client_secret_basic")
    assert token_db.records[1]["refresh_token_consumed"] is not None


def test_federation_feed_has_one_trust_anchor_signature_and_expiry():
    module = load("src/portal/samlidp/model/struct/metadata.py", "standards_federation_metadata")
    module.wiz = SimpleNamespace(
        request=SimpleNamespace(query=lambda key, default="": default),
    )
    key_pem, cert_pem = metadata_keypair()
    fs = MetadataFs()
    metadata = module.Metadata(SimpleNamespace())
    metadata._base_url = lambda: "https://idp.example.test"
    metadata._cert_fs = lambda: fs
    metadata._ensure_keypair = lambda: None
    metadata.get_key_pem = lambda: key_pem
    metadata.get_cert_pem = lambda: cert_pem
    metadata.get_encryption_cert_pem = lambda: cert_pem
    metadata.get_cert_body = lambda: "".join(
        line for line in cert_pem.splitlines() if not line.startswith("-----")
    )
    metadata.get_encryption_cert_body = metadata.get_cert_body
    metadata.configure_response_defaults("alpha", True, True)

    root = etree.fromstring(metadata.generate_federation_xml("").encode())
    verified = XMLVerifier().verify(root, x509_cert=cert_pem, id_attribute="ID")
    assert verified.signed_xml.tag == f"{{{NS_MD}}}EntitiesDescriptor"
    assert root.get("validUntil")
    assert root.get("cacheDuration") == "PT15M"
    entities = root.findall(f"{{{NS_MD}}}EntityDescriptor")
    assert len(entities) == 2
    assert all(entity.find(f"{{{NS_DS}}}Signature") is None for entity in entities)


def test_idp_generates_distinct_purpose_bound_keypairs_without_rotating_signing_key():
    module = load("src/portal/samlidp/model/struct/metadata.py", "standards_key_separation")
    original_key, original_cert = metadata_keypair()
    fs = RawFs({"idp-key.pem": original_key, "idp-cert.pem": original_cert})
    metadata = module.Metadata(SimpleNamespace())
    metadata._cert_fs = lambda: fs

    metadata._ensure_keypair()
    assert metadata.get_key_pem() == original_key
    assert metadata.get_cert_pem() == original_cert
    assert metadata.get_encryption_cert_pem() != original_cert

    signing = x509.load_pem_x509_certificate(metadata.get_cert_pem().encode())
    encryption = x509.load_pem_x509_certificate(
        metadata.get_encryption_cert_pem().encode()
    )
    assert signing.public_key().public_numbers() != encryption.public_key().public_numbers()
    encryption_usage = encryption.extensions.get_extension_for_class(x509.KeyUsage).value
    assert encryption_usage.key_encipherment is True
    assert encryption_usage.digital_signature is False


def test_quick_federation_creates_multiple_idps_and_named_bundle(
    saml_metadata_schema,
):
    module = load("src/portal/samlidp/model/struct/metadata.py", "standards_quick_federation")
    module.wiz = SimpleNamespace(request=SimpleNamespace(query=lambda key, default="": default))
    signing_key, signing_cert = metadata_keypair()
    _, encryption_cert = metadata_keypair()
    fs = MetadataFs()
    metadata = module.Metadata(SimpleNamespace())
    metadata._base_url = lambda: "https://idp.example.test"
    metadata._cert_fs = lambda: fs
    metadata._ensure_keypair = lambda: None
    metadata.get_key_pem = lambda: signing_key
    metadata.get_cert_pem = lambda: signing_cert
    metadata.get_cert_body = lambda: "".join(
        line for line in signing_cert.splitlines() if not line.startswith("-----")
    )
    metadata.get_encryption_cert_pem = lambda: encryption_cert
    metadata.get_encryption_cert_body = lambda: "".join(
        line for line in encryption_cert.splitlines() if not line.startswith("-----")
    )

    result = metadata.create_federation(
        "partner-lab", count=3, include_base=False, preset="mixed"
    )
    assert result["entity_count"] == 3
    assert result["created_profiles"] == [
        "partner-lab-idp-1",
        "partner-lab-idp-2",
        "partner-lab-idp-3",
    ]
    assert metadata.response_defaults("partner-lab-idp-2")["encrypt_assertion"] is True
    assert metadata.list_federations()[0]["metadata_url"].endswith("federation=partner-lab")

    root = etree.fromstring(
        metadata.generate_federation_xml(federation_name="partner-lab").encode()
    )
    assert saml_metadata_schema.validate(root), saml_metadata_schema.error_log
    entities = root.findall(f"{{{NS_MD}}}EntityDescriptor")
    assert [item.get("entityID") for item in entities] == [
        "https://idp.example.test/reviewops/saml/partner-lab-idp-1",
        "https://idp.example.test/reviewops/saml/partner-lab-idp-2",
        "https://idp.example.test/reviewops/saml/partner-lab-idp-3",
    ]
    modern_oaep = entities[0].find(
        ".//md:KeyDescriptor[@use='encryption']/md:EncryptionMethod"
        "[@Algorithm='http://www.w3.org/2009/xmlenc11#rsa-oaep']",
        {"md": NS_MD},
    )
    assert modern_oaep.find(
        f"{{{NS_DS}}}DigestMethod"
    ).get("Algorithm") == "http://www.w3.org/2001/04/xmlenc#sha256"
    assert modern_oaep.find(
        "{http://www.w3.org/2009/xmlenc11#}MGF"
    ).get("Algorithm") == "http://www.w3.org/2009/xmlenc11#mgf1sha256"

    updated = metadata.create_federation(
        "partner-lab", count=3, include_base=False, preset="encrypted"
    )
    assert updated["reconfigured_profiles"] == result["created_profiles"]
    assert metadata.response_defaults("partner-lab-idp-1")["encrypt_assertion"] is True


@pytest.mark.parametrize(
    "transport_algorithm,digest_algorithm,mgf_algorithm,oaep_hash,sibling_key",
    [
        (
            "http://www.w3.org/2009/xmlenc11#rsa-oaep",
            "http://www.w3.org/2001/04/xmlenc#sha256",
            "http://www.w3.org/2009/xmlenc11#mgf1sha256",
            hashes.SHA256,
            False,
        ),
        (
            "http://www.w3.org/2009/xmlenc11#rsa-oaep",
            "",
            "",
            hashes.SHA1,
            False,
        ),
        (
            "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
            "",
            "",
            hashes.SHA1,
            True,
        ),
    ],
)
def test_idp_encryption_key_decrypts_logout_encrypted_id(
    transport_algorithm,
    digest_algorithm,
    mgf_algorithm,
    oaep_hash,
    sibling_key,
):
    module = load("src/portal/samlidp/model/struct/process.py", "standards_encrypted_id")
    encryption_key, encryption_cert = metadata_keypair()
    encryption_public = x509.load_pem_x509_certificate(
        encryption_cert.encode()
    ).public_key()
    sp_entity = "https://sp.example.test/metadata"
    sp = {
        "entity_id": sp_entity,
        "certificates": {"signing": [], "encryption": []},
    }
    metadata = SimpleNamespace(get_encryption_key_pem=lambda: encryption_key)
    registry = SimpleNamespace(
        get=lambda entity_id: sp if entity_id == sp_entity else None,
        is_expired=lambda row: False,
    )
    process = module.Process(SimpleNamespace(metadata=metadata, registry=registry))
    process._debug_fs = lambda: SimpleNamespace(write=lambda path, value: None)
    process._match_sessions = lambda issuer, indexes, nameid: []

    name_id = etree.Element(f"{{{module.NS['saml']}}}NameID")
    name_id.set("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
    name_id.text = "encrypted-user"
    content_key = os.urandom(16)
    iv = os.urandom(12)
    ciphertext = iv + AESGCM(content_key).encrypt(
        iv, etree.tostring(name_id), None
    )
    wrapped_key = encryption_public.encrypt(
        content_key,
        padding.OAEP(
            mgf=padding.MGF1(oaep_hash()),
            algorithm=oaep_hash(),
            label=None,
        ),
    )

    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    request = etree.Element(
        f"{{{module.NS['samlp']}}}LogoutRequest",
        nsmap={"samlp": module.NS["samlp"], "saml": module.NS["saml"]},
        ID="_encrypted-logout-1",
        Version="2.0",
        IssueInstant=now.isoformat().replace("+00:00", "Z"),
    )
    issuer = etree.SubElement(request, f"{{{module.NS['saml']}}}Issuer")
    issuer.text = sp_entity
    encrypted_id = etree.SubElement(request, f"{{{module.NS['saml']}}}EncryptedID")
    encrypted_data = etree.SubElement(encrypted_id, f"{{{module.NS['xenc']}}}EncryptedData")
    content_method = etree.SubElement(encrypted_data, f"{{{module.NS['xenc']}}}EncryptionMethod")
    content_method.set("Algorithm", "http://www.w3.org/2009/xmlenc11#aes128-gcm")
    if sibling_key:
        encrypted_key_parent = encrypted_id
    else:
        encrypted_key_parent = etree.SubElement(
            encrypted_data, f"{{{module.NS['ds']}}}KeyInfo"
        )
    encrypted_key = etree.SubElement(
        encrypted_key_parent, f"{{{module.NS['xenc']}}}EncryptedKey"
    )
    transport_method = etree.SubElement(encrypted_key, f"{{{module.NS['xenc']}}}EncryptionMethod")
    transport_method.set("Algorithm", transport_algorithm)
    if digest_algorithm:
        etree.SubElement(
            transport_method,
            f"{{{module.NS['ds']}}}DigestMethod",
            Algorithm=digest_algorithm,
        )
    if mgf_algorithm:
        etree.SubElement(
            transport_method,
            f"{{{module.NS['xenc11']}}}MGF",
            Algorithm=mgf_algorithm,
        )
    key_cipher_data = etree.SubElement(encrypted_key, f"{{{module.NS['xenc']}}}CipherData")
    etree.SubElement(key_cipher_data, f"{{{module.NS['xenc']}}}CipherValue").text = base64.b64encode(wrapped_key).decode()
    cipher_data = etree.SubElement(encrypted_data, f"{{{module.NS['xenc']}}}CipherData")
    etree.SubElement(cipher_data, f"{{{module.NS['xenc']}}}CipherValue").text = base64.b64encode(ciphertext).decode()

    result = process.parse_logout_request(
        base64.b64encode(etree.tostring(request)).decode(),
        allow_unsigned=True,
    )
    assert result["nameid_value"] == "encrypted-user"
    assert result["encrypted_nameid"] is True


def test_sp_metadata_requires_live_saml2_post_endpoint_and_honors_aggregate_expiry():
    module = load("src/portal/samlidp/model/struct/registry.py", "standards_sp_registry")
    registry = module.Registry(SimpleNamespace())
    post = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    artifact = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"

    parsed = registry.parse_metadata(sp_metadata_xml(post))
    assert parsed["acs_endpoints"][0]["binding"] == post
    with pytest.raises(Exception, match="HTTP-POST"):
        registry.parse_metadata(sp_metadata_xml(artifact))
    with pytest.raises(Exception, match="SAML 2.0"):
        registry.parse_metadata(sp_metadata_xml(post, protocol="urn:oasis:names:tc:SAML:1.1:protocol"))

    expired = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1)
    ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    nested = f"""<md:EntitiesDescriptor xmlns:md="{NS_MD}" validUntil="{expired}">
      <md:EntitiesDescriptor Name="nested">
        {sp_metadata_xml(post)}
      </md:EntitiesDescriptor>
    </md:EntitiesDescriptor>"""
    with pytest.raises(Exception, match="만료된"):
        registry.parse_metadata(nested)


def test_sp_metadata_keeps_signing_and_encryption_credentials_separate():
    module = load("src/portal/samlidp/model/struct/registry.py", "standards_sp_keys")
    registry = module.Registry(SimpleNamespace())
    _, signing_cert = metadata_keypair()
    _, encryption_cert = metadata_keypair()
    signing_body = "".join(
        line for line in signing_cert.splitlines() if not line.startswith("-----")
    )
    encryption_body = "".join(
        line for line in encryption_cert.splitlines() if not line.startswith("-----")
    )
    xml = f"""<md:EntityDescriptor xmlns:md="{NS_MD}" xmlns:ds="{NS_DS}" entityID="https://sp.example.test/metadata">
      <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{signing_body}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
        <md:KeyDescriptor use="encryption">
          <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{encryption_body}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
          <md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/>
          <md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/>
        </md:KeyDescriptor>
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.test/acs" index="0"/>
      </md:SPSSODescriptor>
    </md:EntityDescriptor>"""
    parsed = registry.parse_metadata(xml)
    assert parsed["certificates"]["signing"] == [signing_body]
    assert parsed["certificates"]["encryption"] == [encryption_body]
    assert parsed["certificates"]["encryption_methods"] == [
        "http://www.w3.org/2009/xmlenc11#aes128-gcm",
        "http://www.w3.org/2009/xmlenc11#rsa-oaep",
    ]
    assert {
        item["use"] for item in parsed["certificates"]["details"]
    } == {"signing", "encryption"}
    assert not set(parsed["certificates"]["signing"]).intersection(
        parsed["certificates"]["encryption"]
    )


def test_routes_expose_cacheable_federation_feed_and_consent_interaction():
    saml_route = (ROOT / "src/portal/samlidp/route/saml/controller.py").read_text()
    oidc_route = (ROOT / "src/portal/oidcidp/route/oidc/controller.py").read_text()
    assert 'action == "federation-info"' in saml_route
    assert 'wiz.request.headers("If-None-Match", "")' in saml_route
    assert '"application/samlmetadata+xml"' in saml_route
    assert '["login", "select_account", "consent"]' in oidc_route
