"""ReviewOps SAML federation metadata·속성 누락 계약.

요약:
- profile federation metadata는 해당 IdP EntityDescriptor 하나만 포함한다.
- profile 설정의 omit_attributes는 개수·길이를 제한하고 다른 profile과 격리한다.
- profile attribute_values는 안전한 OID·문자열 값만 허용하고 다른 profile과 격리한다.
- 실제 생성 Assertion에서 OID 값 주입·덮어쓰기·다중 값과 omit 우선순위를 검증한다.
"""

import base64
import datetime
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree


ROOT = Path(__file__).resolve().parents[1]
METADATA_PATH = ROOT / "src/portal/samlidp/model/struct/metadata.py"
PROCESS_PATH = ROOT / "src/portal/samlidp/model/struct/process.py"
ROUTE_PATH = ROOT / "src/portal/samlidp/route/saml/controller.py"
NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata"
NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
MAIL = "urn:oid:0.9.2342.19200300.100.1.3"
UID = "urn:oid:0.9.2342.19200300.100.1.1"
EPPN = "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"


def load(relative, name):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MemoryJsonFs:
    def __init__(self):
        self.values = {}

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

        self.read = Reader(self)
        self.write = Writer(self)

    def exists(self, path):
        return path in self.values

    def delete(self, path):
        self.values.pop(path, None)

    def files(self, filepath=""):
        return list(self.values)


class DebugFs:
    def __init__(self):
        self.values = {}

    def write(self, path, value):
        self.values[path] = value


def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "reviewops-idp")])
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


def metadata_fixture():
    module = load(
        "src/portal/samlidp/model/struct/metadata.py",
        "reviewops_federation_metadata",
    )
    module.wiz = SimpleNamespace(
        request=SimpleNamespace(query=lambda key, default="": default),
    )
    metadata = module.Metadata(SimpleNamespace())
    key_pem, cert_pem = keypair()
    cert_body = "".join(
        line for line in cert_pem.splitlines() if not line.startswith("-----")
    )
    metadata._base_url = lambda: "https://debug-idp.nanoha.kr"
    metadata._ensure_keypair = lambda: None
    metadata.get_key_pem = lambda: key_pem
    metadata.get_cert_pem = lambda: cert_pem
    metadata.get_cert_body = lambda: cert_body
    metadata.get_encryption_cert_pem = lambda: cert_pem
    metadata.get_encryption_cert_body = lambda: cert_body
    metadata._cert_fs = lambda: MemoryJsonFs()
    return module, metadata


def test_profile_federation_metadata_has_exactly_one_matching_idp_entity():
    _, metadata = metadata_fixture()
    profile = "federation-a1"
    root = etree.fromstring(metadata.generate_federation_xml(profile).encode())

    assert root.tag == f"{{{NS_MD}}}EntitiesDescriptor"
    entities = root.findall(f"{{{NS_MD}}}EntityDescriptor")
    assert len(entities) == 1
    assert entities[0].get("entityID") == (
        f"https://debug-idp.nanoha.kr/reviewops/saml/{profile}"
    )
    assert len(entities[0].findall(f"{{{NS_MD}}}IDPSSODescriptor")) == 1


def test_federation_metadata_without_profile_publishes_base_entity_and_single_metadata_is_unchanged():
    _, metadata = metadata_fixture()
    aggregate = etree.fromstring(metadata.generate_federation_xml("").encode())
    entities = aggregate.findall(f"{{{NS_MD}}}EntityDescriptor")
    assert len(entities) == 1
    assert entities[0].get("entityID") == "https://debug-idp.nanoha.kr/api/saml/metadata"
    assert aggregate.get("validUntil")
    assert aggregate.get("cacheDuration") == "PT15M"
    single = etree.fromstring(metadata.generate_xml().encode())
    assert single.tag == f"{{{NS_MD}}}EntityDescriptor"
    assert single.get("entityID") == "https://debug-idp.nanoha.kr/api/saml/metadata"


def test_federation_feed_aggregates_base_and_saved_profile_entities():
    _, metadata = metadata_fixture()
    fs = MemoryJsonFs()
    metadata._cert_fs = lambda: fs
    metadata.configure_response_defaults("alpha", True, True)
    metadata.configure_response_defaults("beta", True, True)

    root = etree.fromstring(metadata.generate_federation_xml("").encode())
    entity_ids = [
        item.get("entityID")
        for item in root.findall(f"{{{NS_MD}}}EntityDescriptor")
    ]
    assert entity_ids == [
        "https://debug-idp.nanoha.kr/api/saml/metadata",
        "https://debug-idp.nanoha.kr/reviewops/saml/alpha",
        "https://debug-idp.nanoha.kr/reviewops/saml/beta",
    ]
    assert root.get("validUntil")
    assert root.get("cacheDuration") == "PT15M"


def test_omit_attributes_is_profile_isolated_bounded_and_clearable():
    module, metadata = metadata_fixture()
    fs = MemoryJsonFs()
    metadata._cert_fs = lambda: fs
    configured = metadata.configure_response_defaults(
        "omit-a",
        sign_response=True,
        sign_assertion=True,
        omit_attributes=[MAIL, MAIL, UID],
    )

    assert configured["omit_attributes"] == [MAIL, UID]
    assert metadata.response_defaults("omit-b")["omit_attributes"] == []
    assert metadata.clear_response_defaults("omit-a")["omit_attributes"] == []
    assert metadata.response_defaults("omit-a")["configured"] is False
    with pytest.raises(ValueError, match="최대 32개"):
        metadata.normalize_omit_attributes([f"urn:test:{index}" for index in range(33)])
    with pytest.raises(ValueError, match="최대 512자"):
        metadata.normalize_omit_attributes(["x" * 513])
    with pytest.raises(ValueError, match="문자열"):
        metadata.normalize_omit_attributes([123])
    assert module.MAX_OMIT_ATTRIBUTES == 32


def test_attribute_values_is_profile_isolated_bounded_and_clearable():
    module, metadata = metadata_fixture()
    fs = MemoryJsonFs()
    metadata._cert_fs = lambda: fs
    configured = metadata.configure_response_defaults(
        "values-a",
        sign_response=True,
        sign_assertion=True,
        attribute_values={
            UID: "reviewops-user",
            EPPN: ["first@example.test", "second@example.test"],
        },
    )

    assert configured["attribute_values"] == {
        UID: "reviewops-user",
        EPPN: ["first@example.test", "second@example.test"],
    }
    assert metadata.response_defaults("values-a")["attribute_values"] == configured["attribute_values"]
    assert metadata.response_defaults("values-b")["attribute_values"] == {}
    assert metadata.clear_response_defaults("values-a")["attribute_values"] == {}
    assert metadata.response_defaults("values-a")["configured"] is False

    with pytest.raises(ValueError, match="최대 32개"):
        metadata.normalize_attribute_values({
            f"urn:oid:1.3.6.1.4.1.55555.{index}": "value"
            for index in range(33)
        })
    with pytest.raises(ValueError, match="urn:oid"):
        metadata.normalize_attribute_values({"mail": "value"})
    with pytest.raises(ValueError, match="최대 512자"):
        metadata.normalize_attribute_values({f"urn:oid:{'1.' * 260}1": "value"})
    with pytest.raises(ValueError, match="문자열 또는 문자열 배열"):
        metadata.normalize_attribute_values({UID: 123})
    with pytest.raises(ValueError, match="비어 있을 수 없습니다"):
        metadata.normalize_attribute_values({UID: []})
    with pytest.raises(ValueError, match="제어 문자"):
        metadata.normalize_attribute_values({UID: "unsafe\nvalue"})
    with pytest.raises(ValueError, match="최대 16개"):
        metadata.normalize_attribute_values({UID: [str(index) for index in range(17)]})
    assert module.MAX_ATTRIBUTE_VALUES == 32
    assert module.MAX_ATTRIBUTE_VALUE_COUNT == 16


def test_actual_assertion_omits_and_injects_profile_attribute_values():
    metadata_module = load(
        "src/portal/samlidp/model/struct/metadata.py",
        "reviewops_assertion_metadata",
    )
    process_module = load(
        "src/portal/samlidp/model/struct/process.py",
        "reviewops_assertion_process",
    )
    key_pem, cert_pem = keypair()
    metadata = metadata_module.Metadata(SimpleNamespace())
    metadata._base_url = lambda: "https://debug-idp.nanoha.kr"
    metadata.get_key_pem = lambda: key_pem
    metadata.get_cert_pem = lambda: cert_pem

    specs = {
        "mail": {"urn": MAIL, "friendly_name": "mail"},
        MAIL: {"urn": MAIL, "friendly_name": "mail"},
        "uid": {"urn": UID, "friendly_name": "uid"},
        UID: {"urn": UID, "friendly_name": "uid"},
        "eppn": {"urn": EPPN, "friendly_name": "eduPersonPrincipalName"},
        EPPN: {"urn": EPPN, "friendly_name": "eduPersonPrincipalName"},
    }
    user = {
        "id": "user-1",
        "username": "tester",
        "email": "tester@example.test",
        "saml_attributes": {
            "mail": "tester@example.test",
            "uid": "tester",
        },
    }
    core = SimpleNamespace(
        user=SimpleNamespace(get=lambda **kwargs: user),
        attribute_preset=SimpleNamespace(get=lambda **kwargs: None),
        saml_attribute_spec=lambda name: specs.get(name),
    )
    struct = SimpleNamespace(
        core=core,
        metadata=metadata,
        registry=SimpleNamespace(),
        db=lambda name: SimpleNamespace(update=lambda *args, **kwargs: None),
    )
    process = process_module.Process(struct)
    process._debug_fs = lambda: DebugFs()
    result = process.build_response({
        "user_id": "user-1",
        "sp_entity_id": "https://sp.example.test/reviewops",
        "acs_url": "https://sp.example.test/acs",
        "request_id": "_request-1",
        "reviewops_profile": "omit-actual",
        "sign_response": False,
        "sign_assertion": False,
        "omit_attributes": ["mail"],
        "attribute_values": {
            MAIL: "must-be-omitted@example.test",
            UID: ["mapped-user", "mapped-user-appended"],
            EPPN: "mapped-user@example.test",
        },
    })
    root = etree.fromstring(base64.b64decode(result["response_b64"]))
    names = [
        node.get("Name")
        for node in root.findall(f".//{{{NS_SAML}}}Attribute")
    ]

    assert names == [UID, EPPN]
    values_by_name = {
        node.get("Name"): [
            child.text
            for child in node.findall(f"{{{NS_SAML}}}AttributeValue")
        ]
        for node in root.findall(f".//{{{NS_SAML}}}Attribute")
    }
    assert values_by_name == {
        UID: ["mapped-user", "mapped-user-appended"],
        EPPN: ["mapped-user@example.test"],
    }
    assert result["omitted_attributes"] == [MAIL]
    assert result["attributes"] == {
        UID: ["mapped-user", "mapped-user-appended"],
        EPPN: "mapped-user@example.test",
    }


def test_route_propagates_profile_omit_and_exposes_federation_endpoint():
    route = ROUTE_PATH.read_text(encoding="utf-8")
    process = PROCESS_PATH.read_text(encoding="utf-8")

    assert 'action == "federation-metadata"' in route
    assert "generate_federation_xml" in route
    assert 'omit_attributes=_strict_query_string_list("omit_attributes")' in route
    assert 'attribute_values=_strict_query_attribute_values("attribute_values")' in route
    assert '"omit_attributes": response_defaults["omit_attributes"]' in route
    assert '"attribute_values": response_defaults["attribute_values"]' in route
    assert '"omit_attributes": state.get("omit_attributes", [])' in route
    assert '"attribute_values": state.get("attribute_values", {})' in route
    assert "metadata.normalize_omit_attributes(omit_attributes)" in process
    assert "metadata.normalize_attribute_values(attribute_values)" in process
