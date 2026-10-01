import base64
import datetime
import hashlib
import json
import os
import re
import uuid
import zlib
from urllib.parse import unquote
from lxml import etree
from signxml import XMLSigner, XMLVerifier, methods
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.decrepit.ciphers import algorithms as decrepit_algorithms

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "xenc": "http://www.w3.org/2001/04/xmlenc#",
    "xenc11": "http://www.w3.org/2009/xmlenc11#",
}

MAX_XML_SIZE = 256 * 1024  # 256KB
DEFAULT_AUTHN_CONTEXT_CLASS_REF = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
SAML_SESSION_TTL_HOURS = 8
MAX_ACTIVE_SESSION_LIST = 50

def _secure_xml_parser():
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        dtd_validation=False,
        load_dtd=False,
        huge_tree=False,
    )

BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
BINDING_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

CONTENT_ENCRYPTION_ALGORITHMS = {
    "aes128-gcm": ("http://www.w3.org/2009/xmlenc11#aes128-gcm", 16, "gcm"),
    "aes192-gcm": ("http://www.w3.org/2009/xmlenc11#aes192-gcm", 24, "gcm"),
    "aes256-gcm": ("http://www.w3.org/2009/xmlenc11#aes256-gcm", 32, "gcm"),
    "aes128-cbc": ("http://www.w3.org/2001/04/xmlenc#aes128-cbc", 16, "cbc"),
    "aes192-cbc": ("http://www.w3.org/2001/04/xmlenc#aes192-cbc", 24, "cbc"),
    "aes256-cbc": ("http://www.w3.org/2001/04/xmlenc#aes256-cbc", 32, "cbc"),
    "tripledes-cbc": ("http://www.w3.org/2001/04/xmlenc#tripledes-cbc", 24, "3des"),
}
KEY_TRANSPORT_ALGORITHMS = {
    "rsa-oaep-sha256": "http://www.w3.org/2009/xmlenc11#rsa-oaep",
    "rsa-oaep-sha1": "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
    "rsa-1_5": "http://www.w3.org/2001/04/xmlenc#rsa-1_5",
}


class Process:
    def __init__(self, struct):
        self.struct = struct

    def _debug_fs(self):
        return wiz.project.fs("metadata", "debug")

    def _place_signature_after_issuer(self, element):
        signature = element.find("ds:Signature", NS)
        if signature is None:
            return element
        issuer = element.find("saml:Issuer", NS)
        element.remove(signature)
        issuer_index = element.index(issuer) if issuer is not None else -1
        element.insert(issuer_index + 1, signature)
        return element

    def _sp_signing_certificates(self, issuer):
        sp = self.struct.registry.get(entity_id=issuer)
        certificates = sp.get("certificates", {})
        if isinstance(certificates, str):
            certificates = json.loads(certificates)
        if not isinstance(certificates, dict):
            return []
        return list(certificates.get("signing", []) or [])

    def _sp_encryption_certificate(
        self,
        issuer,
        content_algorithm="",
        key_transport_algorithm="",
    ):
        sp = self.struct.registry.get(entity_id=issuer)
        if not sp:
            raise Exception("등록된 SP를 찾을 수 없습니다.")
        certificates = sp.get("certificates", {})
        if isinstance(certificates, str):
            certificates = json.loads(certificates)
        candidates = list((certificates or {}).get("encryption", []) or [])
        if not candidates:
            raise Exception("SP 메타데이터에 encryption 인증서가 없습니다.")
        advertised = list((certificates or {}).get("encryption_methods", []) or [])
        content_methods = {
            value for value in advertised
            if value in {item[0] for item in CONTENT_ENCRYPTION_ALGORITHMS.values()}
        }
        transport_methods = {
            value for value in advertised
            if value in set(KEY_TRANSPORT_ALGORITHMS.values())
        }
        if content_methods and content_algorithm not in content_methods:
            raise Exception("선택한 content encryption algorithm이 SP 메타데이터 허용 목록에 없습니다.")
        if transport_methods and key_transport_algorithm not in transport_methods:
            raise Exception("선택한 key transport algorithm이 SP 메타데이터 허용 목록에 없습니다.")
        for candidate in candidates:
            body = "".join(str(candidate).split())
            try:
                certificate = x509.load_der_x509_certificate(base64.b64decode(body))
                if isinstance(certificate.public_key(), rsa.RSAPublicKey):
                    return certificate, body
            except Exception:
                continue
        raise Exception("RSA SP encryption 인증서를 읽을 수 없습니다.")

    def _encrypt_assertion(self, assertion, sp_entity_id, content_algorithm, key_transport):
        if content_algorithm not in CONTENT_ENCRYPTION_ALGORITHMS:
            raise Exception("지원하지 않는 Assertion content encryption algorithm입니다.")
        if key_transport not in KEY_TRANSPORT_ALGORITHMS:
            raise Exception("지원하지 않는 Assertion key transport algorithm입니다.")
        algorithm_uri, key_size, mode_name = CONTENT_ENCRYPTION_ALGORITHMS[content_algorithm]
        certificate, certificate_body = self._sp_encryption_certificate(
            sp_entity_id,
            algorithm_uri,
            KEY_TRANSPORT_ALGORITHMS[key_transport],
        )
        public_key = certificate.public_key()
        key = os.urandom(key_size)
        plaintext = etree.tostring(assertion, pretty_print=False, encoding="UTF-8")
        if mode_name == "gcm":
            iv = os.urandom(12)
            encrypted_payload = iv + AESGCM(key).encrypt(iv, plaintext, None)
        else:
            block_size = 64 if mode_name == "3des" else 128
            padder = symmetric_padding.PKCS7(block_size).padder()
            padded = padder.update(plaintext) + padder.finalize()
            iv = os.urandom(8 if mode_name == "3des" else 16)
            cipher_algorithm = decrepit_algorithms.TripleDES(key) if mode_name == "3des" else algorithms.AES(key)
            encryptor = Cipher(cipher_algorithm, modes.CBC(iv)).encryptor()
            encrypted_payload = iv + encryptor.update(padded) + encryptor.finalize()

        if key_transport == "rsa-oaep-sha256":
            encrypted_key = public_key.encrypt(
                key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        elif key_transport == "rsa-oaep-sha1":
            encrypted_key = public_key.encrypt(
                key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None,
                ),
            )
        else:
            encrypted_key = public_key.encrypt(key, padding.PKCS1v15())

        encrypted_assertion = etree.Element(
            f"{{{NS['saml']}}}EncryptedAssertion",
            nsmap={"saml": NS["saml"], "xenc": NS["xenc"], "xenc11": NS["xenc11"], "ds": NS["ds"]},
        )
        encrypted_data = etree.SubElement(encrypted_assertion, f"{{{NS['xenc']}}}EncryptedData")
        encrypted_data.set("Type", "http://www.w3.org/2001/04/xmlenc#Element")
        content_method = etree.SubElement(encrypted_data, f"{{{NS['xenc']}}}EncryptionMethod")
        content_method.set("Algorithm", algorithm_uri)
        key_info = etree.SubElement(encrypted_data, f"{{{NS['ds']}}}KeyInfo")
        encrypted_key_node = etree.SubElement(key_info, f"{{{NS['xenc']}}}EncryptedKey")
        transport_method = etree.SubElement(encrypted_key_node, f"{{{NS['xenc']}}}EncryptionMethod")
        transport_method.set("Algorithm", KEY_TRANSPORT_ALGORITHMS[key_transport])
        if key_transport == "rsa-oaep-sha256":
            digest = etree.SubElement(transport_method, f"{{{NS['ds']}}}DigestMethod")
            digest.set("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
            mgf = etree.SubElement(transport_method, f"{{{NS['xenc11']}}}MGF")
            mgf.set("Algorithm", "http://www.w3.org/2009/xmlenc11#mgf1sha256")
        certificate_info = etree.SubElement(encrypted_key_node, f"{{{NS['ds']}}}KeyInfo")
        x509_data = etree.SubElement(certificate_info, f"{{{NS['ds']}}}X509Data")
        certificate_node = etree.SubElement(x509_data, f"{{{NS['ds']}}}X509Certificate")
        certificate_node.text = certificate_body
        key_cipher_data = etree.SubElement(encrypted_key_node, f"{{{NS['xenc']}}}CipherData")
        key_cipher_value = etree.SubElement(key_cipher_data, f"{{{NS['xenc']}}}CipherValue")
        key_cipher_value.text = base64.b64encode(encrypted_key).decode("ascii")
        cipher_data = etree.SubElement(encrypted_data, f"{{{NS['xenc']}}}CipherData")
        cipher_value = etree.SubElement(cipher_data, f"{{{NS['xenc']}}}CipherValue")
        cipher_value.text = base64.b64encode(encrypted_payload).decode("ascii")
        return encrypted_assertion

    def _decrypt_encrypted_id(self, encrypted_id):
        """Decrypt an inbound SAML EncryptedID using the IdP encryption key."""
        try:
            encrypted_data = encrypted_id.find("xenc:EncryptedData", NS)
            if encrypted_data is None:
                raise ValueError("EncryptedData missing")
            content_method = encrypted_data.find("xenc:EncryptionMethod", NS)
            content_algorithm = str(
                content_method.get("Algorithm", "")
                if content_method is not None else ""
            )
            content_options = {
                "http://www.w3.org/2009/xmlenc11#aes128-gcm": 16,
                "http://www.w3.org/2009/xmlenc11#aes192-gcm": 24,
                "http://www.w3.org/2009/xmlenc11#aes256-gcm": 32,
            }
            if content_algorithm not in content_options:
                raise ValueError("content algorithm not allowed")

            encrypted_key = encrypted_data.find("ds:KeyInfo/xenc:EncryptedKey", NS)
            if encrypted_key is None:
                # SAML EncryptedElementType also permits EncryptedKey as a
                # sibling of EncryptedData rather than embedded in ds:KeyInfo.
                encrypted_key = encrypted_id.find("xenc:EncryptedKey", NS)
            if encrypted_key is None:
                raise ValueError("EncryptedKey missing")
            transport_method = encrypted_key.find("xenc:EncryptionMethod", NS)
            transport_algorithm = str(
                transport_method.get("Algorithm", "")
                if transport_method is not None else ""
            )
            encrypted_key_value = encrypted_key.findtext(
                "xenc:CipherData/xenc:CipherValue", namespaces=NS
            )
            encrypted_value = encrypted_data.findtext(
                "xenc:CipherData/xenc:CipherValue", namespaces=NS
            )
            wrapped_key = base64.b64decode(str(encrypted_key_value or ""), validate=True)
            ciphertext = base64.b64decode(str(encrypted_value or ""), validate=True)
            if len(wrapped_key) > 1024 or len(ciphertext) > MAX_XML_SIZE:
                raise ValueError("encrypted payload too large")

            private_key = serialization.load_pem_private_key(
                self.struct.metadata.get_encryption_key_pem().encode("utf-8"),
                password=None,
            )
            if transport_algorithm not in {
                "http://www.w3.org/2009/xmlenc11#rsa-oaep",
                "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
            }:
                raise ValueError("key transport algorithm not allowed")

            digest_node = (
                transport_method.find("ds:DigestMethod", NS)
                if transport_method is not None else None
            )
            digest_uri = str(
                digest_node.get("Algorithm", "")
                if digest_node is not None else
                "http://www.w3.org/2000/09/xmldsig#sha1"
            )
            digest_options = {
                "http://www.w3.org/2000/09/xmldsig#sha1": hashes.SHA1,
                "http://www.w3.org/2001/04/xmlenc#sha256": hashes.SHA256,
            }
            if digest_uri not in digest_options:
                raise ValueError("OAEP digest not allowed")

            mgf_node = (
                transport_method.find("xenc11:MGF", NS)
                if transport_method is not None else None
            )
            if transport_algorithm.endswith("rsa-oaep-mgf1p"):
                if mgf_node is not None:
                    raise ValueError("legacy OAEP cannot override MGF")
                mgf_hash = hashes.SHA1()
            else:
                mgf_uri = str(
                    mgf_node.get("Algorithm", "")
                    if mgf_node is not None else
                    "http://www.w3.org/2009/xmlenc11#mgf1sha1"
                )
                mgf_options = {
                    "http://www.w3.org/2009/xmlenc11#mgf1sha1": hashes.SHA1,
                    "http://www.w3.org/2009/xmlenc11#mgf1sha256": hashes.SHA256,
                }
                if mgf_uri not in mgf_options:
                    raise ValueError("OAEP MGF not allowed")
                mgf_hash = mgf_options[mgf_uri]()

            oaep_params = (
                transport_method.findtext("xenc:OAEPparams", namespaces=NS)
                if transport_method is not None else None
            )
            label = None
            if oaep_params is not None:
                label = base64.b64decode(
                    "".join(str(oaep_params).split()),
                    validate=True,
                )
                if len(label) > 1024:
                    raise ValueError("OAEP parameters too large")
            transport_padding = padding.OAEP(
                mgf=padding.MGF1(mgf_hash),
                algorithm=digest_options[digest_uri](),
                label=label,
            )
            content_key = private_key.decrypt(wrapped_key, transport_padding)
            if len(content_key) != content_options[content_algorithm] or len(ciphertext) < 29:
                raise ValueError("content key or ciphertext invalid")
            plaintext = AESGCM(content_key).decrypt(
                ciphertext[:12], ciphertext[12:], None
            )
            name_id = etree.fromstring(plaintext, parser=_secure_xml_parser())
            if name_id.tag != f"{{{NS['saml']}}}NameID":
                raise ValueError("decrypted element is not NameID")
            return name_id
        except Exception:
            # Keep all failure modes indistinguishable to avoid a decryption oracle.
            raise Exception("LogoutRequest EncryptedID 복호화에 실패했습니다.")

    def verify_redirect_query_signature(self, raw_query, parameter_name, issuer):
        values = {}
        for pair in str(raw_query or "").split("&"):
            key, separator, value = pair.partition("=")
            if not separator:
                continue
            if key in values and key in ["SAMLRequest", "SAMLResponse", "RelayState", "SigAlg", "Signature"]:
                return False, "redirect_signature_parameter_duplicated"
            values[key] = value
        required = [parameter_name, "SigAlg", "Signature"]
        if any(key not in values for key in required):
            return False, "redirect_signature_parameters_missing"
        signed_parts = [f"{parameter_name}={values[parameter_name]}"]
        if "RelayState" in values:
            signed_parts.append(f"RelayState={values['RelayState']}")
        signed_parts.append(f"SigAlg={values['SigAlg']}")
        signed_input = "&".join(signed_parts).encode("ascii")
        algorithm = unquote(values["SigAlg"])
        hash_algorithm = {
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": hashes.SHA256(),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": hashes.SHA384(),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": hashes.SHA512(),
        }.get(algorithm)
        if hash_algorithm is None:
            return False, "redirect_signature_algorithm_not_allowed"
        try:
            signature = base64.b64decode(unquote(values["Signature"]))
        except Exception:
            return False, "redirect_signature_encoding_invalid"
        for certificate_body in self._sp_signing_certificates(issuer):
            try:
                certificate = x509.load_der_x509_certificate(
                    base64.b64decode("".join(str(certificate_body).split()))
                )
                certificate.public_key().verify(
                    signature,
                    signed_input,
                    padding.PKCS1v15(),
                    hash_algorithm,
                )
                return True, ""
            except Exception:
                continue
        return False, "redirect_signature_verification_failed"

    def _normalize_entity_id(self, value):
        if value is None:
            return ""
        value = str(value).strip()
        if value.lower() in ["none", "null"]:
            return ""
        return value

    def _resolve_sp_entity_id(self, sp_entity_id="", acs_url=""):
        entity_id = self._normalize_entity_id(sp_entity_id)
        if entity_id:
            return entity_id

        acs_url = str(acs_url or "").strip()
        if acs_url == "":
            return ""

        try:
            rows = self.struct.registry.list()
        except Exception:
            rows = []

        for row in rows:
            endpoints = row.get("acs_url", [])
            if isinstance(endpoints, str):
                try:
                    endpoints = json.loads(endpoints)
                except Exception:
                    endpoints = []
            for endpoint in endpoints:
                if not isinstance(endpoint, dict):
                    continue
                location = str(endpoint.get("location", "")).strip()
                if location == acs_url:
                    return str(row.get("entity_id", "")).strip()

        return ""

    def _resolve_acs_url(self, acs_url="", sp_entity_id=""):
        acs_url = str(acs_url or "").strip()
        if acs_url:
            return acs_url

        entity_id = self._normalize_entity_id(sp_entity_id)
        if entity_id == "":
            return ""

        try:
            sp = self.struct.registry.get(entity_id=entity_id)
        except Exception:
            sp = None
        if not sp:
            return ""

        endpoints = sp.get("acs_url", [])
        if isinstance(endpoints, str):
            try:
                endpoints = json.loads(endpoints)
            except Exception:
                endpoints = []

        for endpoint in endpoints:
            if not isinstance(endpoint, dict):
                continue
            location = str(endpoint.get("location", "")).strip()
            if location:
                return location

        return ""

    def _first_authn_context_class_ref(self, value):
        if value is None:
            return ""
        if isinstance(value, str):
            source = value.strip()
            if source == "":
                return ""
            if source.startswith("["):
                try:
                    parsed = json.loads(source)
                    return self._first_authn_context_class_ref(parsed)
                except Exception:
                    pass
            candidates = re.split(r"[\r\n,]+", source)
        elif isinstance(value, (list, tuple)):
            candidates = value
        else:
            candidates = [value]

        for candidate in candidates:
            item = str(candidate or "").strip()
            if item:
                return item
        return ""

    def _normalize_authn_context_class_ref(self, value="", requested=None):
        selected = self._first_authn_context_class_ref(value)
        if selected == "":
            selected = self._first_authn_context_class_ref(requested)
        if selected == "":
            selected = DEFAULT_AUTHN_CONTEXT_CLASS_REF

        if len(selected) > 512:
            raise Exception("AuthnContextClassRef 값이 너무 깁니다.")
        if re.search(r"\s", selected):
            raise Exception("AuthnContextClassRef 값에는 공백을 포함할 수 없습니다.")
        return selected

    def _resolve_template(self, value, user):
        if isinstance(value, list):
            return [self._resolve_template(v, user) for v in value]
        if isinstance(value, dict):
            return {k: self._resolve_template(v, user) for k, v in value.items()}
        if not isinstance(value, str):
            return value
        def stringify_template_value(item):
            if isinstance(item, (dict, list)):
                return json.dumps(item)
            if item is None:
                return ""
            return str(item)
        def replacer(match):
            key = match.group(1)
            if "." in key:
                parts = key.split(".", 1)
                obj = user.get(parts[0])
                if isinstance(obj, dict):
                    return stringify_template_value(obj.get(parts[1], ""))
                if isinstance(obj, str):
                    try:
                        obj = json.loads(obj)
                        if isinstance(obj, dict):
                            return stringify_template_value(obj.get(parts[1], ""))
                    except Exception:
                        pass
                return ""
            return stringify_template_value(user.get(key, ""))
        return re.sub(r"\{\{(\w+(?:\.\w+)?)\}\}", replacer, value)

    def parse_authn_request(self, saml_request, relay_state="", binding="POST", raw_query="", expected_destination=""):
        xml_bytes = None
        try:
            decoded = base64.b64decode(saml_request)
            if binding == "Redirect":
                xml_bytes = zlib.decompress(decoded, -15)
            else:
                xml_bytes = decoded
        except Exception:
            try:
                xml_bytes = base64.b64decode(saml_request)
            except Exception:
                xml_bytes = saml_request.encode("utf-8") if isinstance(saml_request, str) else saml_request

        if len(xml_bytes) > MAX_XML_SIZE:
            raise Exception(f"XML 페이로드가 너무 큽니다 (최대 {MAX_XML_SIZE // 1024}KB)")

        try:
            root = etree.fromstring(xml_bytes, parser=_secure_xml_parser())
        except etree.XMLSyntaxError as e:
            raise Exception(f"AuthnRequest XML 파싱 실패: {str(e)}")

        if root.tag != f"{{{NS['samlp']}}}AuthnRequest":
            raise Exception("AuthnRequest 요소가 아닙니다.")

        request_id = root.get("ID", "")
        acs_url = root.get("AssertionConsumerServiceURL", "")
        acs_index = root.get("AssertionConsumerServiceIndex", "")
        protocol_binding = root.get("ProtocolBinding", "")
        destination = root.get("Destination", "")
        issue_instant = root.get("IssueInstant", "")
        force_authn = root.get("ForceAuthn", "false")
        is_passive = root.get("IsPassive", "false")

        if re.fullmatch(r"_[A-Za-z0-9._-]{1,255}", request_id) is None:
            raise Exception("AuthnRequest ID가 없거나 형식이 올바르지 않습니다.")
        if root.get("Version") != "2.0":
            raise Exception("AuthnRequest Version은 2.0이어야 합니다.")
        if force_authn.lower() not in ["true", "false", "1", "0"] or is_passive.lower() not in ["true", "false", "1", "0"]:
            raise Exception("ForceAuthn과 IsPassive는 boolean 값이어야 합니다.")
        if force_authn.lower() in ["true", "1"] and is_passive.lower() in ["true", "1"]:
            raise Exception("ForceAuthn과 IsPassive를 동시에 활성화할 수 없습니다.")
        if binding == "Redirect" and len(str(relay_state).encode("utf-8")) > 80:
            raise Exception("HTTP-Redirect RelayState는 80 bytes를 넘을 수 없습니다.")
        ids = [item.get("ID") for item in root.iter() if item.get("ID")]
        if len(ids) != len(set(ids)):
            raise Exception("AuthnRequest XML에 중복 ID가 있습니다.")
        try:
            parsed_instant = datetime.datetime.fromisoformat(issue_instant.replace("Z", "+00:00"))
            if parsed_instant.tzinfo is None:
                parsed_instant = parsed_instant.replace(tzinfo=datetime.timezone.utc)
            skew = abs((datetime.datetime.now(datetime.timezone.utc) - parsed_instant).total_seconds())
            if skew > 300:
                raise ValueError()
        except Exception:
            raise Exception("AuthnRequest IssueInstant가 허용된 5분 범위를 벗어났습니다.")

        issuer_el = root.find("saml:Issuer", NS)
        issuer = self._normalize_entity_id(issuer_el.text.strip() if issuer_el is not None and issuer_el.text else "")
        if not issuer:
            raise Exception("AuthnRequest Issuer가 필요합니다.")
        try:
            sp = self.struct.registry.get(entity_id=issuer)
        except Exception:
            sp = None
        if not sp or getattr(self.struct.registry, "is_expired", lambda row: False)(sp):
            raise Exception("등록된 활성 SP의 AuthnRequest가 아닙니다.")

        registered_acs = sp.get("acs_url", [])
        if isinstance(registered_acs, str):
            registered_acs = json.loads(registered_acs)
        post_acs = [
            item for item in registered_acs
            if isinstance(item, dict) and item.get("binding") == BINDING_POST
        ]
        allowed_acs = [str(item.get("location", "")) for item in post_acs]
        if not acs_url and acs_index:
            match = next(
                (item for item in post_acs if str(item.get("index", "")) == str(acs_index)),
                None,
            )
            acs_url = str((match or {}).get("location", ""))
        if not acs_url or acs_url not in allowed_acs:
            raise Exception("AssertionConsumerServiceURL이 등록된 ACS URL과 일치하지 않습니다.")
        if protocol_binding and protocol_binding != BINDING_POST:
            raise Exception("현재 SAMLResponse 전송은 HTTP-POST ProtocolBinding만 지원합니다.")
        if expected_destination and destination != expected_destination:
            raise Exception("AuthnRequest Destination이 현재 SSO endpoint와 일치하지 않습니다.")

        nameid_policy_el = root.find("samlp:NameIDPolicy", NS)
        nameid_format = ""
        nameid_allow_create = ""
        if nameid_policy_el is not None:
            nameid_format = nameid_policy_el.get("Format", "")
            nameid_allow_create = nameid_policy_el.get("AllowCreate", "")
            if nameid_allow_create.lower() not in ["", "true", "false", "1", "0"]:
                raise Exception("NameIDPolicy AllowCreate는 boolean 값이어야 합니다.")
        registered_nameids = sp.get("nameid_formats", [])
        if isinstance(registered_nameids, str):
            registered_nameids = json.loads(registered_nameids)
        if nameid_format and registered_nameids and nameid_format not in registered_nameids:
            raise Exception("요청한 NameID Format이 SP 메타데이터와 일치하지 않습니다.")

        authn_context = []
        rac_el = root.find("samlp:RequestedAuthnContext", NS)
        if rac_el is not None:
            comparison = str(rac_el.get("Comparison", "exact") or "exact")
            if comparison not in ["exact", "minimum", "maximum", "better"]:
                raise Exception("RequestedAuthnContext Comparison 값이 올바르지 않습니다.")
            for acr in rac_el.findall("saml:AuthnContextClassRef", NS):
                if acr.text:
                    authn_context.append(acr.text.strip())

        scoping = root.find("samlp:Scoping", NS)
        proxy_count = None
        idp_list = []
        requester_ids = []
        get_complete = ""
        if scoping is not None:
            if scoping.get("ProxyCount") not in [None, ""]:
                try:
                    proxy_count = int(scoping.get("ProxyCount"))
                    if proxy_count < 0:
                        raise ValueError()
                except ValueError:
                    raise Exception("Scoping ProxyCount는 0 이상의 정수여야 합니다.")
            for entry in scoping.findall("samlp:IDPList/samlp:IDPEntry", NS):
                provider_id = str(entry.get("ProviderID", "")).strip()
                if provider_id:
                    idp_list.append(provider_id)
            get_complete_node = scoping.find("samlp:IDPList/samlp:GetComplete", NS)
            if get_complete_node is not None and get_complete_node.text:
                get_complete = get_complete_node.text.strip()
            requester_ids = [
                item.text.strip()
                for item in scoping.findall("samlp:RequesterID", NS)
                if item.text and item.text.strip()
            ]

        flags = sp.get("flags", {})
        if isinstance(flags, str):
            flags = json.loads(flags)
        signature_required = str((flags or {}).get("authn_requests_signed", "false")).lower() == "true"
        signature_present = root.find("ds:Signature", NS) is not None
        signature_valid = False
        if binding == "Redirect" and (signature_required or "Signature=" in str(raw_query)):
            signature_valid, signature_error = self.verify_redirect_query_signature(raw_query, "SAMLRequest", issuer)
            if not signature_valid:
                raise Exception(f"AuthnRequest Redirect signature 검증 실패: {signature_error}")
        elif binding != "Redirect" and (signature_required or signature_present):
            if not signature_present:
                raise Exception("서명된 AuthnRequest가 필요합니다.")
            for certificate in self._sp_signing_certificates(issuer):
                cert_pem = "-----BEGIN CERTIFICATE-----\n" + "".join(str(certificate).split()) + "\n-----END CERTIFICATE-----\n"
                try:
                    XMLVerifier().verify(root, x509_cert=cert_pem, id_attribute="ID")
                    signature_valid = True
                    break
                except Exception:
                    continue
            if not signature_valid:
                raise Exception("AuthnRequest XML signature 검증에 실패했습니다.")

        raw_xml = etree.tostring(root, pretty_print=True, xml_declaration=True, encoding="UTF-8").decode("utf-8")

        key = f"req_{hashlib.md5(request_id.encode()).hexdigest()[:12]}_{datetime.datetime.now().strftime('%H%M%S')}"
        fs = self._debug_fs()
        fs.write(f"{key}.xml", raw_xml)

        now = datetime.datetime.now()
        tx_data = {
            "request_id": request_id,
            "sp_entity_id": issuer,
            "relay_state": relay_state,
            "binding": binding,
            "nameid_format_requested": nameid_format,
            "authn_context_requested": json.dumps(authn_context),
            "raw_request_path": f"{key}.xml",
            "status": "pending",
            "created": now,
        }
        db = self.struct.db("saml_transaction")
        try:
            if db.get(request_id=request_id) is not None:
                raise Exception("이미 처리된 AuthnRequest ID입니다.")
        except Exception as error:
            if "이미 처리된" in str(error):
                raise
        tx_id = db.insert(tx_data)

        return {
            "transaction_id": tx_id if isinstance(tx_id, str) else tx_data.get("id", ""),
            "request_id": request_id,
            "issuer": issuer,
            "acs_url": acs_url,
            "destination": destination,
            "issue_instant": issue_instant,
            "force_authn": force_authn,
            "is_passive": is_passive,
            "nameid_format": nameid_format,
            "nameid_allow_create": nameid_allow_create,
            "authn_context": authn_context,
            "relay_state": relay_state,
            "binding": binding,
            "raw_request_key": key,
            "signature_required": signature_required,
            "signature_present": signature_present or "Signature=" in str(raw_query),
            "signature_valid": signature_valid,
            "requested_authn_context_comparison": rac_el.get("Comparison", "exact") if rac_el is not None else "",
            "acs_index": acs_index,
            "protocol_binding": protocol_binding,
            "scoping": {
                "proxy_count": proxy_count,
                "idp_list": idp_list,
                "requester_ids": requester_ids,
                "get_complete": get_complete,
            },
        }

    def build_response(self, params):
        tx_id = params.get("transaction_id", "")
        user_id = params.get("user_id", "")
        sp_entity_id = params.get("sp_entity_id", "")
        acs_url = params.get("acs_url", "")
        request_id = params.get("request_id", "")
        relay_state = params.get("relay_state", "")
        nameid_format = params.get("nameid_format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
        nameid_value = params.get("nameid_value", "")
        preset_id = params.get("preset_id", "")
        attribute_overrides = params.get("attribute_overrides", {})
        sign_response = params.get("sign_response", True)
        sign_assertion = params.get("sign_assertion", True)
        encrypt_assertion = params.get("encrypt_assertion", False)
        content_encryption_algorithm = str(params.get("content_encryption_algorithm", "aes256-gcm") or "aes256-gcm")
        key_transport_algorithm = str(params.get("key_transport_algorithm", "rsa-oaep-sha256") or "rsa-oaep-sha256")
        response_variant = str(params.get("response_variant", "standard") or "standard")
        if response_variant not in [
            "standard", "wrong_issuer", "wrong_audience", "expired", "future_not_before",
            "unsigned", "bad_ciphertext", "authn_failed", "no_authn_context",
            "request_denied", "responder",
        ]:
            raise Exception("지원하지 않는 SAML response variant입니다.")
        if response_variant == "unsigned":
            sign_response = False
            sign_assertion = False
        if response_variant == "bad_ciphertext" and not encrypt_assertion:
            raise Exception("bad_ciphertext 변형에는 EncryptedAssertion이 필요합니다.")
        if response_variant in ["authn_failed", "no_authn_context", "request_denied", "responder"]:
            sign_assertion = False
            encrypt_assertion = False
        time_offset_seconds = int(params.get("time_offset_seconds", 0) or 0)
        if abs(time_offset_seconds) > 86400:
            raise Exception("time_offset_seconds는 -86400~86400 범위여야 합니다.")
        assertion_ttl_seconds = int(params.get("assertion_ttl_seconds", 300) or 300)
        if assertion_ttl_seconds < 1 or assertion_ttl_seconds > 86400:
            raise Exception("assertion_ttl_seconds는 1~86400 범위여야 합니다.")
        omit_attributes = params.get("omit_attributes", [])
        attribute_values = params.get("attribute_values", {})
        session_index_custom = params.get("session_index", "")
        authn_context_requested = params.get("authn_context_requested", [])
        authn_context_comparison = str(params.get("authn_context_comparison", "exact") or "exact")
        reviewops_profile = params.get("reviewops_profile", "")
        if not params.get("authn_context_class_ref") and tx_id:
            try:
                tx = self.get_transaction(tx_id)
                if tx:
                    authn_context_requested = tx.get("authn_context_requested", authn_context_requested)
            except Exception:
                pass
        authn_context_class_ref = self._normalize_authn_context_class_ref(
            params.get("authn_context_class_ref", ""),
            authn_context_requested,
        )
        authenticating_authorities = params.get("authenticating_authorities", []) or []
        if isinstance(authenticating_authorities, str):
            try:
                authenticating_authorities = json.loads(authenticating_authorities)
            except Exception:
                authenticating_authorities = [item.strip() for item in authenticating_authorities.splitlines() if item.strip()]
        if not isinstance(authenticating_authorities, list) or len(authenticating_authorities) > 16:
            raise Exception("AuthenticatingAuthority는 최대 16개의 문자열 목록이어야 합니다.")
        requested_contexts = authn_context_requested
        if isinstance(requested_contexts, str):
            try:
                requested_contexts = json.loads(requested_contexts)
            except Exception:
                requested_contexts = [requested_contexts]
        if requested_contexts:
            if authn_context_comparison == "better":
                raise Exception(
                    "RequestedAuthnContext better 비교는 인증 강도 순서를 안전하게 판단할 수 없어 지원하지 않습니다."
                )
            if (
                authn_context_comparison in ["exact", "minimum", "maximum"]
                and authn_context_class_ref not in requested_contexts
            ):
                raise Exception(
                    f"RequestedAuthnContext {authn_context_comparison} 조건을 충족하지 않습니다."
                )

        sp_entity_id = self._resolve_sp_entity_id(sp_entity_id, acs_url)
        acs_url = self._resolve_acs_url(acs_url, sp_entity_id)

        if sp_entity_id == "":
            raise Exception("SP entity_id를 확인할 수 없습니다. AuthnRequest Issuer를 설정하거나 등록된 ACS URL과 일치하는 SP를 먼저 등록하세요.")
        if acs_url == "":
            raise Exception("ACS URL을 확인할 수 없습니다. AuthnRequest에 AssertionConsumerServiceURL을 포함하거나 SP 메타데이터를 등록하세요.")

        core = self.struct.core
        metadata = self.struct.metadata
        omit_attributes = metadata.normalize_omit_attributes(omit_attributes)
        attribute_values = metadata.normalize_attribute_values(attribute_values)
        user = core.user.get(id=user_id)
        if user is None:
            raise Exception("사용자를 찾을 수 없습니다.")

        attributes = {}
        if preset_id:
            preset = core.attribute_preset.get(id=preset_id)
            if preset and preset.get("payload"):
                payload = preset["payload"]
                if isinstance(payload, str):
                    payload = json.loads(payload)
                raw_attrs = payload.get("attributes", {})
                attributes = self._resolve_template(raw_attrs, user)

        user_saml = user.get("saml_attributes", {})
        if isinstance(user_saml, str):
            try:
                user_saml = json.loads(user_saml)
            except Exception:
                user_saml = {}
        if user_saml:
            attributes.update(self._resolve_template(user_saml, user))

        if attribute_overrides:
            if isinstance(attribute_overrides, str):
                try:
                    attribute_overrides = json.loads(attribute_overrides)
                except Exception:
                    attribute_overrides = {}
            attributes.update(attribute_overrides)

        # ReviewOps 프로필 값은 실제 인증 callback에서 마지막으로 적용되어
        # 계정·preset 값과 격리된 결정적 SAML Assertion을 만든다.
        if attribute_values:
            attributes.update(attribute_values)

        resolved_attribute_specs = {}
        normalized_attributes = {}
        for raw_name, raw_value in attributes.items():
            attr_spec = core.saml_attribute_spec(raw_name)
            if attr_spec is None:
                continue
            resolved_attribute_specs[attr_spec["urn"]] = attr_spec
            normalized_attributes[attr_spec["urn"]] = raw_value
        attributes = normalized_attributes

        resolved_omit_attributes = []
        resolved_omit_set = set()
        for raw_name in omit_attributes:
            attr_spec = core.saml_attribute_spec(raw_name)
            attr_name = attr_spec["urn"] if attr_spec else raw_name
            if attr_name not in resolved_omit_set:
                resolved_omit_attributes.append(attr_name)
                resolved_omit_set.add(attr_name)
        if resolved_omit_set:
            attributes = {
                name: value
                for name, value in attributes.items()
                if name not in resolved_omit_set
            }

        if not nameid_value:
            if "emailAddress" in nameid_format:
                nameid_value = user.get("email", user.get("username", ""))
            elif "persistent" in nameid_format:
                nameid_value = user.get("id", "")
            elif "transient" in nameid_format:
                nameid_value = f"_transient_{uuid.uuid4().hex[:16]}"
            else:
                nameid_value = user.get("username", "")

        idp_entity_id = metadata.entity_id(reviewops_profile)
        if response_variant == "wrong_issuer":
            idp_entity_id = f"{idp_entity_id}/invalid"
        now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=time_offset_seconds)
        response_id = str(params.get("response_id", "") or f"_resp_{uuid.uuid4().hex}")
        assertion_id = str(params.get("assertion_id", "") or f"_assert_{uuid.uuid4().hex}")
        if re.fullmatch(r"_[A-Za-z0-9._-]{1,255}", response_id) is None or re.fullmatch(r"_[A-Za-z0-9._-]{1,255}", assertion_id) is None:
            raise Exception("Response ID 또는 Assertion ID 형식이 올바르지 않습니다.")
        session_index = session_index_custom or f"_sidx_{uuid.uuid4().hex[:16]}"
        not_on_or_after = now + datetime.timedelta(seconds=assertion_ttl_seconds)
        not_before = now
        if response_variant == "expired":
            not_before = now - datetime.timedelta(hours=2)
            not_on_or_after = now - datetime.timedelta(hours=1)
        elif response_variant == "future_not_before":
            not_before = now + datetime.timedelta(hours=1)
            not_on_or_after = now + datetime.timedelta(hours=2)
        session_not_on_or_after = now + datetime.timedelta(hours=SAML_SESSION_TTL_HOURS)
        instant = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        not_after_str = not_on_or_after.strftime("%Y-%m-%dT%H:%M:%SZ")
        not_before_str = not_before.strftime("%Y-%m-%dT%H:%M:%SZ")
        session_not_after_str = session_not_on_or_after.strftime("%Y-%m-%dT%H:%M:%SZ")
        authn_instant = instant
        if params.get("authn_instant"):
            try:
                authn_time = datetime.datetime.fromisoformat(str(params["authn_instant"]).replace("Z", "+00:00"))
                if authn_time.tzinfo is None:
                    authn_time = authn_time.replace(tzinfo=datetime.timezone.utc)
                authn_instant = authn_time.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                session_not_after_str = (
                    authn_time.astimezone(datetime.timezone.utc) + datetime.timedelta(hours=SAML_SESSION_TTL_HOURS)
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                raise Exception("authn_instant 형식이 올바르지 않습니다.")

        nsmap = {
            "samlp": NS["samlp"],
            "saml": NS["saml"],
        }

        response = etree.Element(f"{{{NS['samlp']}}}Response", nsmap=nsmap)
        response.set("ID", response_id)
        response.set("Version", "2.0")
        response.set("IssueInstant", instant)
        response.set("Destination", acs_url)
        if request_id:
            response.set("InResponseTo", request_id)

        resp_issuer = etree.SubElement(response, f"{{{NS['saml']}}}Issuer")
        resp_issuer.text = idp_entity_id

        status_el = etree.SubElement(response, f"{{{NS['samlp']}}}Status")
        status_code = etree.SubElement(status_el, f"{{{NS['samlp']}}}StatusCode")
        status_variants = {
            "authn_failed": "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
            "no_authn_context": "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext",
            "request_denied": "urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
        }
        if response_variant in status_variants:
            status_code.set("Value", "urn:oasis:names:tc:SAML:2.0:status:Responder")
            child_status = etree.SubElement(status_code, f"{{{NS['samlp']}}}StatusCode")
            child_status.set("Value", status_variants[response_variant])
        elif response_variant == "responder":
            status_code.set("Value", "urn:oasis:names:tc:SAML:2.0:status:Responder")
        else:
            status_code.set("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")

        assertion = etree.SubElement(response, f"{{{NS['saml']}}}Assertion")
        assertion.set("ID", assertion_id)
        assertion.set("Version", "2.0")
        assertion.set("IssueInstant", instant)

        assert_issuer = etree.SubElement(assertion, f"{{{NS['saml']}}}Issuer")
        assert_issuer.text = idp_entity_id

        subject = etree.SubElement(assertion, f"{{{NS['saml']}}}Subject")
        name_id = etree.SubElement(subject, f"{{{NS['saml']}}}NameID")
        name_id.set("Format", nameid_format)
        name_id.set("SPNameQualifier", sp_entity_id)
        name_id.text = nameid_value

        subj_confirm = etree.SubElement(subject, f"{{{NS['saml']}}}SubjectConfirmation")
        subj_confirm.set("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
        subj_data = etree.SubElement(subj_confirm, f"{{{NS['saml']}}}SubjectConfirmationData")
        subj_data.set("NotOnOrAfter", not_after_str)
        subj_data.set("Recipient", acs_url)
        if request_id:
            subj_data.set("InResponseTo", request_id)

        conditions = etree.SubElement(assertion, f"{{{NS['saml']}}}Conditions")
        conditions.set("NotBefore", not_before_str)
        conditions.set("NotOnOrAfter", not_after_str)
        aud_restriction = etree.SubElement(conditions, f"{{{NS['saml']}}}AudienceRestriction")
        audience = etree.SubElement(aud_restriction, f"{{{NS['saml']}}}Audience")
        audience.text = f"{sp_entity_id}/invalid" if response_variant == "wrong_audience" else sp_entity_id

        authn_stmt = etree.SubElement(assertion, f"{{{NS['saml']}}}AuthnStatement")
        authn_stmt.set("AuthnInstant", authn_instant)
        authn_stmt.set("SessionIndex", session_index)
        authn_stmt.set("SessionNotOnOrAfter", session_not_after_str)
        authn_ctx = etree.SubElement(authn_stmt, f"{{{NS['saml']}}}AuthnContext")
        authn_ctx_ref = etree.SubElement(authn_ctx, f"{{{NS['saml']}}}AuthnContextClassRef")
        authn_ctx_ref.text = authn_context_class_ref
        for authority in authenticating_authorities:
            authority = str(authority or "").strip()
            if not authority or authority == idp_entity_id:
                continue
            authority_node = etree.SubElement(authn_ctx, f"{{{NS['saml']}}}AuthenticatingAuthority")
            authority_node.text = authority

        if attributes:
            attr_stmt = etree.SubElement(assertion, f"{{{NS['saml']}}}AttributeStatement")
            for attr_name, attr_val in attributes.items():
                attr_spec = resolved_attribute_specs.get(attr_name) or core.saml_attribute_spec(attr_name)
                attr_el = etree.SubElement(attr_stmt, f"{{{NS['saml']}}}Attribute")
                attr_el.set("Name", attr_spec["urn"] if attr_spec else attr_name)
                name_format = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                if attr_spec:
                    name_format = attr_spec.get("name_format", name_format)
                attr_el.set("NameFormat", name_format)
                if attr_spec and attr_spec.get("friendly_name"):
                    attr_el.set("FriendlyName", attr_spec["friendly_name"])

                vals = attr_val if isinstance(attr_val, list) else [attr_val]
                for v in vals:
                    val_el = etree.SubElement(attr_el, f"{{{NS['saml']}}}AttributeValue")
                    if isinstance(v, (dict, list)):
                        val_el.text = json.dumps(v)
                    else:
                        val_el.text = str(v)

        cert_pem = metadata.get_cert_pem()
        key_pem = metadata.get_key_pem()

        if sign_assertion:
            signer = XMLSigner(
                method=methods.enveloped,
                signature_algorithm="rsa-sha256",
                digest_algorithm="sha256",
                c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
            )
            assertion_signed = signer.sign(assertion, key=key_pem, cert=cert_pem)
            assertion_signed = self._place_signature_after_issuer(assertion_signed)
            response.remove(assertion)
            response.append(assertion_signed)
            assertion = assertion_signed

        if encrypt_assertion:
            encrypted_assertion = self._encrypt_assertion(
                assertion,
                sp_entity_id,
                content_encryption_algorithm,
                key_transport_algorithm,
            )
            response.remove(assertion)
            response.append(encrypted_assertion)

        if response_variant == "bad_ciphertext" and encrypt_assertion:
            cipher_value = response.find(".//xenc:EncryptedData/xenc:CipherData/xenc:CipherValue", NS)
            if cipher_value is not None and cipher_value.text:
                raw_cipher = bytearray(base64.b64decode(cipher_value.text))
                raw_cipher[-1] ^= 1
                cipher_value.text = base64.b64encode(bytes(raw_cipher)).decode("ascii")

        if response_variant in ["authn_failed", "no_authn_context", "request_denied", "responder"]:
            for child in list(response):
                if child.tag in [f"{{{NS['saml']}}}Assertion", f"{{{NS['saml']}}}EncryptedAssertion"]:
                    response.remove(child)

        if sign_response:
            signer = XMLSigner(
                method=methods.enveloped,
                signature_algorithm="rsa-sha256",
                digest_algorithm="sha256",
                c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
            )
            response = signer.sign(response, key=key_pem, cert=cert_pem)
            response = self._place_signature_after_issuer(response)

        # 서명 후 pretty-print가 삽입하는 공백은 XMLDSig digest를 변경한다.
        response_xml = etree.tostring(response, pretty_print=False, xml_declaration=True, encoding="UTF-8").decode("utf-8")
        response_b64 = base64.b64encode(response_xml.encode("utf-8")).decode("utf-8")

        resp_key = f"resp_{hashlib.md5(response_id.encode()).hexdigest()[:12]}_{datetime.datetime.now().strftime('%H%M%S')}"
        fs = self._debug_fs()
        fs.write(f"{resp_key}.xml", response_xml)

        db = self.struct.db("saml_transaction")
        if tx_id:
            try:
                db.update({
                    "sp_entity_id": sp_entity_id,
                    "relay_state": relay_state,
                    "raw_response_path": f"{resp_key}.xml",
                    "session_index": session_index,
                    "status": "success",
                    "user_id": user_id,
                }, id=tx_id)
            except Exception:
                pass

        return {
            "response_xml": response_xml,
            "response_b64": response_b64,
            "response_id": response_id,
            "assertion_id": assertion_id,
            "session_index": session_index,
            "acs_url": acs_url,
            "relay_state": relay_state,
            "nameid_value": nameid_value,
            "nameid_format": nameid_format,
            "authn_context_class_ref": authn_context_class_ref,
            "authenticating_authorities": [
                str(value) for value in authenticating_authorities
                if str(value).strip() and str(value).strip() != idp_entity_id
            ],
            "attributes": attributes,
            "omitted_attributes": resolved_omit_attributes,
            "raw_response_key": resp_key,
            "signed_response": sign_response,
            "signed_assertion": sign_assertion,
            "encrypted_assertion": bool(encrypt_assertion),
            "content_encryption_algorithm": content_encryption_algorithm if encrypt_assertion else "",
            "key_transport_algorithm": key_transport_algorithm if encrypt_assertion else "",
            "response_variant": response_variant,
            "standards_status": "standard" if (
                response_variant == "standard"
                and sign_assertion
                and (
                    not encrypt_assertion
                    or (
                        content_encryption_algorithm in ["aes128-gcm", "aes192-gcm", "aes256-gcm"]
                        and key_transport_algorithm == "rsa-oaep-sha256"
                    )
                )
            ) else "compatibility",
        }

    def get_debug_raw(self, key):
        if not re.match(r'^[a-zA-Z0-9_\-]+$', key):
            raise Exception("Invalid debug key")
        fs = self._debug_fs()
        fname = f"{key}.xml"
        if not fs.exists(fname):
            raise Exception(f"Debug file not found: {key}")
        return fs.read(fname)

    def build_authn_error_response(self, params):
        request_id = params.get("request_id", "")
        acs_url = params.get("acs_url", "")
        relay_state = params.get("relay_state", "")
        reviewops_profile = params.get("reviewops_profile", "")
        top_status = params.get(
            "status_code",
            "urn:oasis:names:tc:SAML:2.0:status:Responder",
        )
        child_status = params.get(
            "sub_status_code",
            "urn:oasis:names:tc:SAML:2.0:status:NoPassive",
        )

        if not acs_url:
            raise Exception("오류 SAMLResponse를 전송할 ACS URL이 없습니다.")

        metadata = self.struct.metadata
        now = datetime.datetime.now(datetime.timezone.utc)
        response_id = f"_error_{uuid.uuid4().hex}"
        instant = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        response = etree.Element(
            f"{{{NS['samlp']}}}Response",
            nsmap={"samlp": NS["samlp"], "saml": NS["saml"]},
        )
        response.set("ID", response_id)
        response.set("Version", "2.0")
        response.set("IssueInstant", instant)
        response.set("Destination", acs_url)
        if request_id:
            response.set("InResponseTo", request_id)

        issuer = etree.SubElement(response, f"{{{NS['saml']}}}Issuer")
        issuer.text = metadata.entity_id(reviewops_profile)
        status = etree.SubElement(response, f"{{{NS['samlp']}}}Status")
        status_code = etree.SubElement(status, f"{{{NS['samlp']}}}StatusCode")
        status_code.set("Value", top_status)
        sub_status = etree.SubElement(status_code, f"{{{NS['samlp']}}}StatusCode")
        sub_status.set("Value", child_status)

        response = XMLSigner(
            method=methods.enveloped,
            signature_algorithm="rsa-sha256",
            digest_algorithm="sha256",
            c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
        ).sign(response, key=metadata.get_key_pem(), cert=metadata.get_cert_pem())
        response = self._place_signature_after_issuer(response)
        response_xml = etree.tostring(
            response,
            pretty_print=False,
            xml_declaration=True,
            encoding="UTF-8",
        ).decode("utf-8")
        response_b64 = base64.b64encode(response_xml.encode("utf-8")).decode("utf-8")
        raw_key = f"resp_error_{hashlib.md5(response_id.encode()).hexdigest()[:12]}_{datetime.datetime.now().strftime('%H%M%S')}"
        self._debug_fs().write(f"{raw_key}.xml", response_xml)
        return {
            "response_b64": response_b64,
            "response_id": response_id,
            "acs_url": acs_url,
            "relay_state": relay_state,
            "status_code": top_status,
            "sub_status_code": child_status,
            "raw_response_key": raw_key,
        }

    def list_transactions(self, sp_entity_id="", status="", limit=50):
        db = self.struct.db("saml_transaction")
        kwargs = dict(orderby="created", order="DESC", page=1, dump=limit)
        if sp_entity_id:
            kwargs["sp_entity_id"] = sp_entity_id
        if status:
            kwargs["status"] = status
        rows = db.rows(**kwargs)
        for row in rows:
            acr = row.get("authn_context_requested")
            if isinstance(acr, str):
                try:
                    row["authn_context_requested"] = json.loads(acr)
                except Exception:
                    pass
        return rows

    def get_transaction(self, id):
        db = self.struct.db("saml_transaction")
        item = db.get(id=id)
        if item:
            acr = item.get("authn_context_requested")
            if isinstance(acr, str):
                try:
                    item["authn_context_requested"] = json.loads(acr)
                except Exception:
                    pass
        return item

    # ─── SLO (Single Logout) ───

    def _normalize_slo_binding(self, binding):
        value = str(binding or "POST").strip().upper()
        if value in ["POST", BINDING_POST.upper()]:
            return "POST", BINDING_POST
        if value in ["REDIRECT", BINDING_REDIRECT.upper()]:
            return "Redirect", BINDING_REDIRECT
        raise Exception("SLO Binding은 HTTP-POST 또는 HTTP-Redirect여야 합니다.")

    def resolve_slo_endpoint(self, sp_entity_id, binding="POST", for_response=False):
        binding_name, binding_uri = self._normalize_slo_binding(binding)
        sp = self.struct.registry.get(entity_id=sp_entity_id)
        if not sp or getattr(self.struct.registry, "is_expired", lambda row: False)(sp):
            raise Exception("등록된 활성 SP를 찾을 수 없습니다.")
        endpoints = sp.get("slo_url", [])
        if isinstance(endpoints, str):
            try:
                endpoints = json.loads(endpoints)
            except Exception:
                endpoints = []
        endpoints = [item for item in endpoints if isinstance(item, dict)]

        def endpoint_url(item):
            if for_response and str(item.get("response_location", "") or "").strip():
                return str(item.get("response_location", "") or "").strip()
            return str(item.get("location", "") or "").strip()

        for item in endpoints:
            value = endpoint_url(item)
            if item.get("binding") == binding_uri and value.startswith(("https://", "http://")):
                return {
                    "url": value,
                    "binding": binding_name,
                    "binding_uri": binding_uri,
                    "standards_status": "standard",
                    "warnings": [],
                }

        for item in endpoints:
            value = endpoint_url(item)
            if value.startswith(("https://", "http://")):
                return {
                    "url": value,
                    "binding": binding_name,
                    "binding_uri": str(item.get("binding", "") or ""),
                    "standards_status": "compatibility",
                    "warnings": ["요청한 Binding의 SLO endpoint가 없어 등록된 다른 endpoint를 사용합니다."],
                }

        return {
            "url": "",
            "binding": binding_name,
            "binding_uri": binding_uri,
            "standards_status": "compatibility",
            "warnings": ["사용할 수 있는 SP SingleLogoutService URL이 없습니다."],
        }

    def parse_logout_request(
        self,
        saml_request,
        relay_state="",
        binding="POST",
        raw_query="",
        expected_destination="",
        allow_unsigned=False,
    ):
        binding, _ = self._normalize_slo_binding(binding)
        xml_bytes = None
        try:
            decoded = base64.b64decode(saml_request)
            if binding == "Redirect":
                xml_bytes = zlib.decompress(decoded, -15)
            else:
                xml_bytes = decoded
        except Exception:
            try:
                xml_bytes = base64.b64decode(saml_request)
            except Exception:
                xml_bytes = saml_request.encode("utf-8") if isinstance(saml_request, str) else saml_request

        if len(xml_bytes) > MAX_XML_SIZE:
            raise Exception(f"XML 페이로드가 너무 큽니다 (최대 {MAX_XML_SIZE // 1024}KB)")

        try:
            root = etree.fromstring(xml_bytes, parser=_secure_xml_parser())
        except etree.XMLSyntaxError as e:
            raise Exception(f"LogoutRequest XML 파싱 실패: {str(e)}")

        if root.tag != f"{{{NS['samlp']}}}LogoutRequest":
            raise Exception("LogoutRequest 요소가 아닙니다.")

        request_id = root.get("ID", "")
        version = root.get("Version", "")
        destination = root.get("Destination", "")
        issue_instant = root.get("IssueInstant", "")
        not_on_or_after = root.get("NotOnOrAfter", "")
        if re.fullmatch(r"_[A-Za-z0-9._-]{1,255}", request_id) is None or version != "2.0":
            raise Exception("LogoutRequest ID 또는 Version이 올바르지 않습니다.")
        if len(str(relay_state).encode("utf-8")) > 80:
            raise Exception("SLO RelayState는 80 bytes를 넘을 수 없습니다.")
        try:
            issued = datetime.datetime.fromisoformat(issue_instant.replace("Z", "+00:00"))
            if issued.tzinfo is None:
                issued = issued.replace(tzinfo=datetime.timezone.utc)
            if abs((datetime.datetime.now(datetime.timezone.utc) - issued).total_seconds()) > 300:
                raise ValueError()
            if not_on_or_after:
                deadline = datetime.datetime.fromisoformat(not_on_or_after.replace("Z", "+00:00"))
                if deadline.tzinfo is None:
                    deadline = deadline.replace(tzinfo=datetime.timezone.utc)
                if deadline <= datetime.datetime.now(datetime.timezone.utc):
                    raise ValueError()
        except Exception:
            raise Exception("LogoutRequest 유효 시간이 허용 범위를 벗어났습니다.")

        issuer_el = root.find("saml:Issuer", NS)
        issuer = issuer_el.text.strip() if issuer_el is not None and issuer_el.text else ""
        issuer_format = issuer_el.get("Format", "") if issuer_el is not None else ""
        if not issuer:
            raise Exception("LogoutRequest Issuer가 필요합니다.")
        try:
            sp = self.struct.registry.get(entity_id=issuer)
        except Exception:
            sp = None
        if not sp or getattr(self.struct.registry, "is_expired", lambda row: False)(sp):
            raise Exception("등록된 활성 SP의 LogoutRequest가 아닙니다.")
        if expected_destination and destination != expected_destination:
            raise Exception("LogoutRequest Destination이 현재 SLO endpoint와 일치하지 않습니다.")

        xml_signature_present = root.find("ds:Signature", NS) is not None
        signature_present = xml_signature_present or "Signature=" in str(raw_query)
        signature_valid = False
        signature_error = ""
        if binding == "Redirect" and signature_present:
            signature_valid, signature_error = self.verify_redirect_query_signature(raw_query, "SAMLRequest", issuer)
        elif xml_signature_present:
            for certificate in self._sp_signing_certificates(issuer):
                cert_pem = "-----BEGIN CERTIFICATE-----\n" + "".join(str(certificate).split()) + "\n-----END CERTIFICATE-----\n"
                try:
                    XMLVerifier().verify(root, x509_cert=cert_pem, id_attribute="ID")
                    signature_valid = True
                    break
                except Exception as error:
                    signature_error = str(error)
        if not signature_valid and not allow_unsigned:
            raise Exception(f"LogoutRequest signature 검증에 실패했습니다: {signature_error or 'signature_missing'}")

        name_id_el = root.find("saml:NameID", NS)
        encrypted_name_id = False
        if name_id_el is None:
            encrypted_id_el = root.find("saml:EncryptedID", NS)
            if encrypted_id_el is not None:
                name_id_el = self._decrypt_encrypted_id(encrypted_id_el)
                encrypted_name_id = True
        nameid_value = ""
        nameid_format = ""
        nameid_sp_qualifier = ""
        if name_id_el is not None:
            nameid_value = name_id_el.text.strip() if name_id_el.text else ""
            nameid_format = name_id_el.get("Format", "")
            nameid_sp_qualifier = name_id_el.get("SPNameQualifier", "")
        if not nameid_value:
            raise Exception("LogoutRequest NameID가 필요합니다.")
        if nameid_sp_qualifier and nameid_sp_qualifier != issuer:
            raise Exception("LogoutRequest NameID의 SPNameQualifier가 Issuer와 일치하지 않습니다.")

        session_indexes = []
        for si_el in root.findall("samlp:SessionIndex", NS):
            if si_el.text:
                session_indexes.append(si_el.text.strip())

        compatibility_warnings = []
        if not signature_valid:
            compatibility_warnings.append("서명 없는 LogoutRequest를 호환 시험으로 처리했습니다.")
        if issuer_format not in ["", "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"]:
            compatibility_warnings.append("Issuer Format이 SAML SLO 프로필 값과 다릅니다.")
        if not session_indexes:
            compatibility_warnings.append("SP 시작 LogoutRequest에 SessionIndex가 없어 NameID로 세션을 찾습니다.")

        raw_xml = etree.tostring(root, pretty_print=True, xml_declaration=True, encoding="UTF-8").decode("utf-8")

        key = f"slo_req_{hashlib.md5(request_id.encode()).hexdigest()[:12]}_{datetime.datetime.now().strftime('%H%M%S')}"
        fs = self._debug_fs()
        fs.write(f"{key}.xml", raw_xml)

        matched = self._match_sessions(issuer, session_indexes, nameid_value)

        return {
            "request_id": request_id,
            "issuer": issuer,
            "destination": destination,
            "issue_instant": issue_instant,
            "not_on_or_after": not_on_or_after,
            "nameid_value": nameid_value,
            "nameid_format": nameid_format,
            "nameid_sp_qualifier": nameid_sp_qualifier,
            "encrypted_nameid": encrypted_name_id,
            "session_indexes": session_indexes,
            "relay_state": relay_state,
            "binding": binding,
            "raw_request_key": key,
            "matched_sessions": matched,
            "signature_present": signature_present,
            "signature_valid": signature_valid,
            "compatibility_warnings": compatibility_warnings,
            "standards_status": "standard" if not compatibility_warnings else "compatibility",
        }

    def parse_logout_response(self, saml_response, relay_state="", binding="POST", expected=None, redirect_signature_valid=None, redirect_signature_error=""):
        expected = expected if isinstance(expected, dict) else {}
        binding, _ = self._normalize_slo_binding(binding)
        if len(str(relay_state).encode("utf-8")) > 80:
            raise Exception("SLO RelayState는 80 bytes를 넘을 수 없습니다.")
        try:
            decoded = base64.b64decode(saml_response)
            if binding == "Redirect":
                xml_bytes = zlib.decompress(decoded, -15)
            else:
                xml_bytes = decoded
        except Exception as error:
            raise Exception(f"LogoutResponse 디코딩 실패: {str(error)}")

        if len(xml_bytes) > MAX_XML_SIZE:
            raise Exception(f"XML 페이로드가 너무 큽니다 (최대 {MAX_XML_SIZE // 1024}KB)")
        try:
            root = etree.fromstring(xml_bytes, parser=_secure_xml_parser())
        except etree.XMLSyntaxError as error:
            raise Exception(f"LogoutResponse XML 파싱 실패: {str(error)}")
        if root.tag != f"{{{NS['samlp']}}}LogoutResponse":
            raise Exception("LogoutResponse 요소가 아닙니다.")

        response_id = root.get("ID", "")
        version = root.get("Version", "")
        issue_instant = root.get("IssueInstant", "")
        in_response_to = root.get("InResponseTo", "")
        destination = root.get("Destination", "")
        issuer_el = root.find("saml:Issuer", NS)
        issuer = issuer_el.text.strip() if issuer_el is not None and issuer_el.text else ""
        issuer_format = issuer_el.get("Format", "") if issuer_el is not None else ""
        response_id_valid = re.fullmatch(r"_[A-Za-z0-9._-]{1,255}", response_id or "") is not None
        version_valid = version == "2.0"
        issue_instant_valid = False
        try:
            issued = datetime.datetime.fromisoformat(issue_instant.replace("Z", "+00:00"))
            if issued.tzinfo is None:
                issued = issued.replace(tzinfo=datetime.timezone.utc)
            issue_instant_valid = abs(
                (datetime.datetime.now(datetime.timezone.utc) - issued).total_seconds()
            ) <= 300
        except Exception:
            issue_instant_valid = False
        issuer_format_valid = issuer_format in ["", "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"]
        status_codes = [
            item.get("Value", "")
            for item in root.findall(".//samlp:StatusCode", NS)
        ]
        success = bool(status_codes) and status_codes[0] == "urn:oasis:names:tc:SAML:2.0:status:Success"
        xml_signature_present = root.find("ds:Signature", NS) is not None
        signature_present = xml_signature_present or redirect_signature_valid is not None
        signature_valid = redirect_signature_valid is True
        signature_error = redirect_signature_error
        if xml_signature_present and issuer and not signature_valid:
            try:
                for certificate in self._sp_signing_certificates(issuer):
                    cert_pem = "-----BEGIN CERTIFICATE-----\n" + str(certificate).strip() + "\n-----END CERTIFICATE-----\n"
                    try:
                        XMLVerifier().verify(root, x509_cert=cert_pem, id_attribute="ID")
                        signature_valid = True
                        break
                    except Exception as error:
                        signature_error = str(error)
            except Exception as error:
                signature_error = str(error)

        request_id_match = bool(expected.get("request_id")) and in_response_to == expected.get("request_id")
        issuer_match = bool(expected.get("sp_entity_id")) and issuer == expected.get("sp_entity_id")
        relay_state_match = relay_state == expected.get("relay_state", "")
        expected_destination = str(expected.get("response_destination", "") or "")
        destination_match = bool(expected_destination) and destination == expected_destination
        valid = all([
            response_id_valid,
            version_valid,
            issue_instant_valid,
            issuer_format_valid,
            request_id_match,
            issuer_match,
            relay_state_match,
            destination_match,
            success,
            signature_present,
            signature_valid,
        ])

        raw_xml = etree.tostring(root, pretty_print=True, xml_declaration=True, encoding="UTF-8").decode("utf-8")
        raw_key = f"slo_callback_{hashlib.md5(response_id.encode()).hexdigest()[:12]}_{datetime.datetime.now().strftime('%H%M%S')}"
        self._debug_fs().write(f"{raw_key}.xml", raw_xml)
        return {
            "response_id_present": bool(response_id),
            "response_id_valid": response_id_valid,
            "version_valid": version_valid,
            "issue_instant_valid": issue_instant_valid,
            "issuer_format_valid": issuer_format_valid,
            "in_response_to_match": request_id_match,
            "issuer_match": issuer_match,
            "relay_state_match": relay_state_match,
            "destination_match": destination_match,
            "status_success": success,
            "signature_present": signature_present,
            "signature_valid": signature_valid,
            "signature_error": signature_error[:240],
            "binding": binding,
            "raw_response_key": raw_key,
            "status_codes": status_codes,
            "standards_status": "standard" if valid else "rejected",
            "valid": valid,
        }

    def _match_sessions(self, sp_entity_id, session_indexes, nameid_value=""):
        db = self.struct.db("saml_transaction")
        matched = []
        cutoff = datetime.datetime.now() - datetime.timedelta(hours=SAML_SESSION_TTL_HOURS)
        active_only = self._active_session_query(cutoff)

        if session_indexes:
            for si in session_indexes:
                try:
                    rows = db.rows(
                        session_index=si,
                        sp_entity_id=sp_entity_id,
                        status="success",
                        query=active_only,
                        orderby="created",
                        order="DESC",
                        page=1,
                        dump=MAX_ACTIVE_SESSION_LIST,
                    )
                    matched.extend(rows)
                except Exception:
                    pass

        if not matched and nameid_value:
            all_rows = db.rows(
                sp_entity_id=sp_entity_id,
                status="success",
                query=active_only,
                orderby="created",
                order="DESC",
                page=1,
                dump=MAX_ACTIVE_SESSION_LIST,
            )
            for row in all_rows:
                if row.get("user_id"):
                    try:
                        user = self.struct.core.user.get(id=row["user_id"])
                        if user:
                            if (user.get("email") == nameid_value or
                                user.get("username") == nameid_value or
                                user.get("id") == nameid_value):
                                matched.append(row)
                    except Exception:
                        pass

        return list({row.get("id"): row for row in matched if row.get("id")}.values())

    def invalidate_sessions(self, session_ids):
        db = self.struct.db("saml_transaction")
        invalidated = []
        for sid in session_ids:
            try:
                db.update({"status": "logged_out"}, id=sid)
                invalidated.append(sid)
            except Exception:
                pass
        return invalidated

    def build_logout_response(self, params):
        request_id = params.get("request_id", "")
        sp_entity_id = params.get("sp_entity_id", "")
        destination = params.get("destination", "")
        relay_state = params.get("relay_state", "")
        status_code = params.get("status_code", "urn:oasis:names:tc:SAML:2.0:status:Success")
        sign = params.get("sign", True)
        reviewops_profile = params.get("reviewops_profile", "")

        metadata = self.struct.metadata
        idp_entity_id = metadata.entity_id(reviewops_profile)
        now = datetime.datetime.utcnow()
        response_id = f"_sloresp_{uuid.uuid4().hex}"
        instant = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        nsmap = {
            "samlp": NS["samlp"],
            "saml": NS["saml"],
        }

        resp = etree.Element(f"{{{NS['samlp']}}}LogoutResponse", nsmap=nsmap)
        resp.set("ID", response_id)
        resp.set("Version", "2.0")
        resp.set("IssueInstant", instant)
        if destination:
            resp.set("Destination", destination)
        if request_id:
            resp.set("InResponseTo", request_id)

        issuer_el = etree.SubElement(resp, f"{{{NS['saml']}}}Issuer")
        issuer_el.text = idp_entity_id

        status_el = etree.SubElement(resp, f"{{{NS['samlp']}}}Status")
        code_el = etree.SubElement(status_el, f"{{{NS['samlp']}}}StatusCode")
        code_el.set("Value", status_code)

        if sign:
            cert_pem = metadata.get_cert_pem()
            key_pem = metadata.get_key_pem()
            signer = XMLSigner(
                method=methods.enveloped,
                signature_algorithm="rsa-sha256",
                digest_algorithm="sha256",
                c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
            )
            resp = signer.sign(resp, key=key_pem, cert=cert_pem)
            resp = self._place_signature_after_issuer(resp)

        response_xml = etree.tostring(resp, pretty_print=False, xml_declaration=True, encoding="UTF-8").decode("utf-8")
        response_b64 = base64.b64encode(response_xml.encode("utf-8")).decode("utf-8")

        resp_key = f"slo_resp_{hashlib.md5(response_id.encode()).hexdigest()[:12]}_{datetime.datetime.now().strftime('%H%M%S')}"
        fs = self._debug_fs()
        fs.write(f"{resp_key}.xml", response_xml)

        return {
            "response_xml": response_xml,
            "response_b64": response_b64,
            "response_id": response_id,
            "destination": destination,
            "relay_state": relay_state,
            "status_code": status_code,
            "raw_response_key": resp_key,
            "signed": sign,
        }

    def build_logout_request(self, params):
        sp_entity_id = params.get("sp_entity_id", "")
        nameid_value = params.get("nameid_value", "")
        nameid_format = params.get("nameid_format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
        session_indexes = params.get("session_indexes", [])
        destination = params.get("destination", "")
        sign = params.get("sign", True)
        reviewops_profile = params.get("reviewops_profile", "")
        binding, _ = self._normalize_slo_binding(params.get("binding", "POST"))
        endpoint_result = {
            "standards_status": "standard",
            "warnings": [],
        }

        if not destination and sp_entity_id:
            try:
                endpoint_result = self.resolve_slo_endpoint(
                    sp_entity_id,
                    binding=binding,
                    for_response=False,
                )
                destination = endpoint_result.get("url", "")
            except Exception as error:
                endpoint_result = {
                    "standards_status": "compatibility",
                    "warnings": [str(error) or "SP SingleLogoutService를 확인하지 못했습니다."],
                }

        metadata = self.struct.metadata
        idp_entity_id = metadata.entity_id(reviewops_profile)
        now = datetime.datetime.utcnow()
        request_id = f"_sloreq_{uuid.uuid4().hex}"
        instant = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        not_on_or_after = (now + datetime.timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")

        nsmap = {
            "samlp": NS["samlp"],
            "saml": NS["saml"],
        }

        req = etree.Element(f"{{{NS['samlp']}}}LogoutRequest", nsmap=nsmap)
        req.set("ID", request_id)
        req.set("Version", "2.0")
        req.set("IssueInstant", instant)
        req.set("NotOnOrAfter", not_on_or_after)
        if destination:
            req.set("Destination", destination)

        issuer_el = etree.SubElement(req, f"{{{NS['saml']}}}Issuer")
        issuer_el.text = idp_entity_id

        name_id = etree.SubElement(req, f"{{{NS['saml']}}}NameID")
        name_id.set("Format", nameid_format)
        if sp_entity_id:
            name_id.set("SPNameQualifier", sp_entity_id)
        name_id.text = nameid_value

        for si in session_indexes:
            si_el = etree.SubElement(req, f"{{{NS['samlp']}}}SessionIndex")
            si_el.text = si

        if sign:
            cert_pem = metadata.get_cert_pem()
            key_pem = metadata.get_key_pem()
            signer = XMLSigner(
                method=methods.enveloped,
                signature_algorithm="rsa-sha256",
                digest_algorithm="sha256",
                c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
            )
            req = signer.sign(req, key=key_pem, cert=cert_pem)
            req = self._place_signature_after_issuer(req)

        request_xml = etree.tostring(req, pretty_print=False, xml_declaration=True, encoding="UTF-8").decode("utf-8")
        request_b64 = base64.b64encode(request_xml.encode("utf-8")).decode("utf-8")

        req_key = f"slo_idpreq_{hashlib.md5(request_id.encode()).hexdigest()[:12]}_{datetime.datetime.now().strftime('%H%M%S')}"
        fs = self._debug_fs()
        fs.write(f"{req_key}.xml", request_xml)

        return {
            "request_xml": request_xml,
            "request_b64": request_b64,
            "request_id": request_id,
            "destination": destination,
            "nameid_value": nameid_value,
            "nameid_format": nameid_format,
            "session_indexes": session_indexes,
            "binding": binding,
            "standards_status": endpoint_result.get("standards_status", "standard") if sign else "compatibility",
            "compatibility_warnings": list(endpoint_result.get("warnings", [])) + ([] if sign else ["서명 없는 LogoutRequest를 호환 시험용으로 생성했습니다."]),
            "raw_request_key": req_key,
            "signed": sign,
        }

    def _active_session_query(self, cutoff):
        def active_only(model, query):
            return query.where(model.created >= cutoff)
        return active_only

    def list_active_sessions(self, sp_entity_id="", limit=MAX_ACTIVE_SESSION_LIST, cutoff=None):
        db = self.struct.db("saml_transaction")
        cutoff = cutoff or (
            datetime.datetime.now() - datetime.timedelta(hours=SAML_SESSION_TTL_HOURS)
        )
        limit = max(1, min(int(limit or MAX_ACTIVE_SESSION_LIST), MAX_ACTIVE_SESSION_LIST))
        kwargs = dict(
            orderby="created",
            order="DESC",
            page=1,
            dump=limit,
            status="success",
            query=self._active_session_query(cutoff),
        )
        if sp_entity_id:
            kwargs["sp_entity_id"] = sp_entity_id
        rows = db.rows(**kwargs)
        for row in rows:
            if row.get("user_id"):
                try:
                    user = self.struct.core.user.get(id=row["user_id"])
                    if user:
                        row["user_display"] = user.get("name", user.get("username", ""))
                        row["user_email"] = user.get("email", "")
                except Exception:
                    pass
        return rows

    def active_session_summary(self, sp_entity_id="", limit=MAX_ACTIVE_SESSION_LIST):
        db = self.struct.db("saml_transaction")
        cutoff = datetime.datetime.now() - datetime.timedelta(hours=SAML_SESSION_TTL_HOURS)
        normalized_limit = max(
            1,
            min(int(limit or MAX_ACTIVE_SESSION_LIST), MAX_ACTIVE_SESSION_LIST),
        )
        kwargs = {
            "status": "success",
            "query": self._active_session_query(cutoff),
        }
        if sp_entity_id:
            kwargs["sp_entity_id"] = sp_entity_id
        total = db.count(**kwargs)
        items = self.list_active_sessions(
            sp_entity_id=sp_entity_id,
            limit=normalized_limit,
            cutoff=cutoff,
        )
        return {
            "items": items,
            "total": int(total if total is not None else len(items)),
            "window_hours": SAML_SESSION_TTL_HOURS,
            "limit": normalized_limit,
        }


Model = Process
