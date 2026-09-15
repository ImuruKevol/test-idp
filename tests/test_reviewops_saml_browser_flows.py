"""ReviewOps SAML 브라우저 SLO·Passive 계약.

요약:
- IsPassive 비로그인 응답은 서명된 NoPassive SAMLResponse다.
- IdP 시작 SLO의 반환 LogoutResponse는 서명·issuer·InResponseTo·Destination·RelayState를 검증한다.
- 실제 SLO route는 JSON 생성에서 멈추지 않고 HTTP-POST 브라우저 왕복을 제공한다.
"""

import ast
import base64
import datetime
import importlib.util
import zlib
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLSigner, XMLVerifier, methods


ROOT = Path(__file__).resolve().parents[1]
NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


class MemoryFs:
    def __init__(self):
        self.data = {}

    def write(self, path, value):
        self.data[path] = value


def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "reviewops-sp")])
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
    return key_pem, cert_pem, cert_body


def process_fixture():
    path = ROOT / "src/portal/samlidp/model/struct/process.py"
    spec = importlib.util.spec_from_file_location("reviewops_saml_process", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    key_pem, cert_pem, cert_body = keypair()
    issuer = "https://sp.example.test/reviewops"
    metadata = SimpleNamespace(
        entity_id=lambda profile: f"https://debug-idp.nanoha.kr/reviewops/saml/{profile}",
        get_key_pem=lambda: key_pem,
        get_cert_pem=lambda: cert_pem,
    )
    registry = SimpleNamespace(get=lambda entity_id: {
        "entity_id": issuer,
        "certificates": {"signing": [cert_body]},
    })
    fs = MemoryFs()
    struct = SimpleNamespace(
        metadata=metadata,
        registry=registry,
        core=SimpleNamespace(),
        db=lambda name: SimpleNamespace(),
    )
    instance = module.Process(struct)
    instance._debug_fs = lambda: fs
    return instance, key_pem, cert_pem, issuer


def redirect_builder():
    path = ROOT / "src/portal/samlidp/route/saml/controller.py"
    tree = ast.parse(path.read_text())
    node = next(
        item for item in tree.body
        if isinstance(item, ast.FunctionDef)
        and item.name == "_build_saml_redirect_url"
    )
    namespace = {
        "base64": base64,
        "hashes": hashes,
        "etree": etree,
        "padding": padding,
        "parse_qsl": __import__("urllib.parse", fromlist=["parse_qsl"]).parse_qsl,
        "serialization": serialization,
        "urlencode": urlencode,
        "urlparse": urlparse,
        "urlunparse": __import__("urllib.parse", fromlist=["urlunparse"]).urlunparse,
        "zlib": zlib,
    }
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec"), namespace)
    return namespace["_build_saml_redirect_url"]


def signed_logout_response(key_pem, cert_pem, issuer, request_id, destination):
    root = etree.Element(f"{{{NS['samlp']}}}LogoutResponse", nsmap=NS)
    root.set("ID", "_response-1")
    root.set("Version", "2.0")
    root.set(
        "IssueInstant",
        datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    )
    root.set("InResponseTo", request_id)
    root.set("Destination", destination)
    issuer_node = etree.SubElement(root, f"{{{NS['saml']}}}Issuer")
    issuer_node.text = issuer
    status = etree.SubElement(root, f"{{{NS['samlp']}}}Status")
    code = etree.SubElement(status, f"{{{NS['samlp']}}}StatusCode")
    code.set("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")
    signed = XMLSigner(
        method=methods.enveloped,
        signature_algorithm="rsa-sha256",
        digest_algorithm="sha256",
    ).sign(root, key=key_pem, cert=cert_pem)
    return base64.b64encode(etree.tostring(signed)).decode()


def test_no_passive_response_is_signed_and_profile_bound():
    process, _, cert_pem, _ = process_fixture()
    result = process.build_authn_error_response({
        "request_id": "_authn-1",
        "acs_url": "https://sp.example.test/acs",
        "relay_state": "/passive",
        "reviewops_profile": "reviewops-a1",
    })
    root = etree.fromstring(base64.b64decode(result["response_b64"]))

    assert root.get("InResponseTo") == "_authn-1"
    assert root.get("Destination") == "https://sp.example.test/acs"
    assert root.find("saml:Issuer", NS).text.endswith("/reviewops-a1")
    assert root.find("ds:Signature", NS) is not None
    assert root[1].tag == f"{{{NS['ds']}}}Signature"
    XMLVerifier().verify(root, x509_cert=cert_pem, id_attribute="ID")
    status_codes = [node.get("Value") for node in root.findall(".//samlp:StatusCode", NS)]
    assert "urn:oasis:names:tc:SAML:2.0:status:NoPassive" in status_codes


def test_idp_initiated_logout_response_is_fully_validated():
    process, key_pem, cert_pem, issuer = process_fixture()
    destination = "https://debug-idp.nanoha.kr/api/saml/slo?reviewops_profile=reviewops-a1"
    encoded = signed_logout_response(key_pem, cert_pem, issuer, "_logout-1", destination)
    result = process.parse_logout_response(
        encoded,
        relay_state="/done",
        binding="POST",
        expected={
            "request_id": "_logout-1",
            "sp_entity_id": issuer,
            "relay_state": "/done",
            "response_destination": destination,
        },
    )

    assert result["valid"] is True
    assert result["signature_valid"] is True
    assert result["in_response_to_match"] is True
    assert result["destination_match"] is True


def test_idp_initiated_logout_response_rejects_wrong_relay_state():
    process, key_pem, cert_pem, issuer = process_fixture()
    destination = "https://debug-idp.nanoha.kr/api/saml/slo?reviewops_profile=reviewops-a1"
    encoded = signed_logout_response(key_pem, cert_pem, issuer, "_logout-1", destination)
    result = process.parse_logout_response(
        encoded,
        relay_state="/wrong",
        binding="POST",
        expected={
            "request_id": "_logout-1",
            "sp_entity_id": issuer,
            "relay_state": "/done",
            "response_destination": destination,
        },
    )

    assert result["valid"] is False
    assert result["relay_state_match"] is False


def test_redirect_logout_response_is_inflated_and_validated():
    process, key_pem, cert_pem, issuer = process_fixture()
    destination = "https://debug-idp.nanoha.kr/api/saml/slo?reviewops_profile=reviewops-a1"
    post_encoded = signed_logout_response(key_pem, cert_pem, issuer, "_logout-r", destination)
    xml = base64.b64decode(post_encoded)
    compressor = zlib.compressobj(wbits=-15)
    redirect_encoded = base64.b64encode(compressor.compress(xml) + compressor.flush()).decode()
    result = process.parse_logout_response(
        redirect_encoded,
        relay_state="/done",
        binding="Redirect",
        expected={
            "request_id": "_logout-r",
            "sp_entity_id": issuer,
            "relay_state": "/done",
            "response_destination": destination,
        },
    )

    assert result["valid"] is True
    assert result["binding"] == "Redirect"


def test_redirect_logout_message_has_oasis_query_signature():
    key_pem, _, _ = keypair()
    xml = "<LogoutRequest ID=\"_logout-redirect\"/>"
    url = redirect_builder()(
        "https://sp.example.test/sls?reviewops_profile=profile-a",
        "SAMLRequest",
        xml,
        "/done",
        key_pem,
    )
    params = parse_qs(urlparse(url).query)
    assert params["SigAlg"] == [
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    ]
    signing_input = urlencode([
        ("SAMLRequest", params["SAMLRequest"][0]),
        ("RelayState", params["RelayState"][0]),
        ("SigAlg", params["SigAlg"][0]),
    ]).encode("ascii")
    public_key = serialization.load_pem_private_key(
        key_pem.encode("utf-8"),
        password=None,
    ).public_key()
    public_key.verify(
        base64.b64decode(params["Signature"][0]),
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    decoded = zlib.decompress(
        base64.b64decode(params["SAMLRequest"][0]),
        wbits=-15,
    ).decode("utf-8")
    assert etree.tostring(etree.fromstring(decoded.encode())) == etree.tostring(etree.fromstring(xml.encode()))


def test_redirect_logout_removes_xml_signature_before_deflate():
    key_pem, cert_pem, _ = keypair()
    root = etree.Element(
        f"{{{NS['samlp']}}}LogoutRequest",
        nsmap=NS,
        ID="_logout-signed-redirect",
        Version="2.0",
        IssueInstant=datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    )
    issuer = etree.SubElement(root, f"{{{NS['saml']}}}Issuer")
    issuer.text = "https://idp.example.test/metadata"
    signed = XMLSigner(
        method=methods.enveloped,
        signature_algorithm="rsa-sha256",
        digest_algorithm="sha256",
    ).sign(root, key=key_pem, cert=cert_pem)
    url = redirect_builder()(
        "https://sp.example.test/slo",
        "SAMLRequest",
        etree.tostring(signed).decode(),
        "/done",
        key_pem,
    )
    params = parse_qs(urlparse(url).query)
    decoded = zlib.decompress(base64.b64decode(params["SAMLRequest"][0]), wbits=-15)
    decoded_root = etree.fromstring(decoded)

    assert decoded_root.find("ds:Signature", NS) is None
    assert "Signature" in params and "SigAlg" in params


def test_route_contains_browser_delivery_and_result_contract():
    route = (ROOT / "src/portal/samlidp/route/saml/controller.py").read_text()
    assert 'wiz.request.query("deliver", "false")' in route
    assert '"SAMLRequest"' in route
    assert '"SAMLResponse"' in route
    assert "parse_logout_response" in route
    assert 'action == "slo-result"' in route
    assert "_build_slo_result_html" in route
    assert "_build_saml_redirect_url" in route
    assert "signing_key_pem" in route
    assert 'protocol_query.append(("SigAlg", signature_algorithm))' in route
    assert 'binding not in ("POST", "REDIRECT")' in route
