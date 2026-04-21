import os
import datetime
from lxml import etree
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata"
NS_DS = "http://www.w3.org/2000/09/xmldsig#"
BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
BINDING_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"


class Metadata:
    def __init__(self, struct):
        self.struct = struct

    def _cert_fs(self):
        return wiz.project.fs("metadata", "saml", "idp")

    def _ensure_keypair(self):
        fs = self._cert_fs()
        if fs.exists("idp-cert.pem") and fs.exists("idp-key.pem"):
            return

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Test SAML IdP"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test IdP"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256())
        )

        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        fs.write("idp-key.pem", key_pem)
        fs.write("idp-cert.pem", cert_pem)

    def get_cert_pem(self):
        self._ensure_keypair()
        fs = self._cert_fs()
        return fs.read("idp-cert.pem")

    def get_key_pem(self):
        self._ensure_keypair()
        fs = self._cert_fs()
        return fs.read("idp-key.pem")

    def get_cert_body(self):
        pem = self.get_cert_pem()
        lines = pem.strip().split("\n")
        body_lines = [l for l in lines if not l.startswith("-----")]
        return "".join(body_lines)

    def _base_url(self):
        config = wiz.config("season")
        base_url = None
        try:
            base_url = config.get("saml_base_url", None)
        except Exception:
            pass
        if not base_url:
            host = wiz.request.headers("Host", "localhost:3034")
            scheme = wiz.request.headers("X-Forwarded-Proto", "http")
            base_url = f"{scheme}://{host}"
        return base_url.rstrip("/")

    def entity_id(self):
        base = self._base_url()
        return f"{base}/api/saml/metadata"

    def info(self):
        self._ensure_keypair()
        base = self._base_url()
        entity = self.entity_id()
        cert_body = self.get_cert_body()

        return {
            "entity_id": entity,
            "sso_post": f"{base}/api/saml/sso",
            "sso_redirect": f"{base}/api/saml/sso",
            "slo_post": f"{base}/api/saml/slo",
            "slo_redirect": f"{base}/api/saml/slo",
            "certificate": cert_body,
            "sign_algorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "nameid_formats": [
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
                "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            ],
        }

    def generate_xml(self):
        info = self.info()

        nsmap = {
            None: NS_MD,
            "ds": NS_DS,
        }

        ed = etree.Element(f"{{{NS_MD}}}EntityDescriptor", nsmap=nsmap)
        ed.set("entityID", info["entity_id"])

        idp_sso = etree.SubElement(ed, f"{{{NS_MD}}}IDPSSODescriptor")
        idp_sso.set("protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol")
        idp_sso.set("WantAuthnRequestsSigned", "false")

        kd = etree.SubElement(idp_sso, f"{{{NS_MD}}}KeyDescriptor")
        kd.set("use", "signing")
        ki = etree.SubElement(kd, f"{{{NS_DS}}}KeyInfo")
        x509d = etree.SubElement(ki, f"{{{NS_DS}}}X509Data")
        x509c = etree.SubElement(x509d, f"{{{NS_DS}}}X509Certificate")
        x509c.text = info["certificate"]

        for fmt in info["nameid_formats"]:
            nf = etree.SubElement(idp_sso, f"{{{NS_MD}}}NameIDFormat")
            nf.text = fmt

        for binding, url_key in [(BINDING_POST, "sso_post"), (BINDING_REDIRECT, "sso_redirect")]:
            sso = etree.SubElement(idp_sso, f"{{{NS_MD}}}SingleSignOnService")
            sso.set("Binding", binding)
            sso.set("Location", info[url_key])

        for binding, url_key in [(BINDING_POST, "slo_post"), (BINDING_REDIRECT, "slo_redirect")]:
            slo = etree.SubElement(idp_sso, f"{{{NS_MD}}}SingleLogoutService")
            slo.set("Binding", binding)
            slo.set("Location", info[url_key])

        xml_str = etree.tostring(ed, pretty_print=True, xml_declaration=True, encoding="UTF-8").decode("utf-8")
        return xml_str


Model = Metadata
