import json
import datetime
import base64
from lxml import etree
from signxml import XMLVerifier
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

NS = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}

SP_TTL_HOURS = 24
MAX_XML_SIZE = 256 * 1024  # 256KB
MAX_SP_COUNT = 50  # maximum SP registrations

def _secure_xml_parser():
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        dtd_validation=False,
        load_dtd=False,
        huge_tree=False,
    )


class Registry:
    def __init__(self, struct):
        self.struct = struct

    def db(self):
        return self.struct.db("saml_sp_registry")

    def _get_ttl_hours(self):
        try:
            config = wiz.config("idp")
            return int(getattr(config, "SAML_SP_TTL_HOURS", getattr(config, "TEMPORARY_ACCOUNT_TTL_HOURS", SP_TTL_HOURS)) or SP_TTL_HOURS)
        except Exception:
            return SP_TTL_HOURS

    def _get_protected_entity_ids(self):
        try:
            config = wiz.config("idp")
            return getattr(config, "PROTECTED_SAML_SP_ENTITY_IDS", [])
        except Exception:
            return []

    def cleanup_expired(self):
        db = self.db()
        now = datetime.datetime.now()
        protected = self._get_protected_entity_ids()
        rows = db.rows()
        deleted_count = 0
        for row in rows:
            expires = row.get("expires")
            if expires is None:
                continue
            if isinstance(expires, str):
                try:
                    expires = datetime.datetime.fromisoformat(expires)
                except Exception:
                    continue
            if expires > now:
                continue
            entity_id = row.get("entity_id", "")
            if entity_id in protected:
                continue
            try:
                self.delete(row["id"])
                deleted_count += 1
            except Exception:
                pass
        return deleted_count

    def _parse_expires(self, expires):
        if expires in [None, ""]:
            return None
        if isinstance(expires, str):
            try:
                return datetime.datetime.fromisoformat(expires)
            except Exception:
                return None
        return expires

    def is_expired(self, row):
        expires = self._parse_expires(row.get("expires"))
        if expires is None:
            return False
        return expires < datetime.datetime.now()

    def list(self):
        db = self.db()
        rows = db.rows(orderby="-created")
        return rows

    def get(self, id=None, entity_id=None):
        db = self.db()
        if id:
            return db.get(id=id)
        if entity_id:
            return db.get(entity_id=entity_id)
        raise Exception("id or entity_id required")

    def delete(self, id):
        db = self.db()
        item = db.get(id=id)
        if item.get("raw_metadata_path"):
            fs = wiz.project.fs("metadata", "saml", "sp")
            fname = item["raw_metadata_path"]
            if fs.exists(fname):
                fs.delete(fname)
        db.delete(id=id)
        return True

    def extend_validity(self, id, ttl_hours=None):
        item = self.get(id=id)
        if item.get("expires") is None:
            raise Exception("이미 영구 보관 중인 SP입니다.")

        if ttl_hours is None:
            ttl_hours = self._get_ttl_hours()
        ttl_hours = int(ttl_hours)
        if ttl_hours <= 0:
            raise Exception("ttl_hours는 1 이상이어야 합니다.")

        now = datetime.datetime.now()
        current_expires = self._parse_expires(item.get("expires"))
        baseline = current_expires if current_expires and current_expires > now else now
        expires = baseline + datetime.timedelta(hours=ttl_hours)
        self.db().update({
            "expires": expires,
            "updated": now,
        }, id=id)
        return self.get(id=id)

    def set_unlimited(self, id):
        item = self.get(id=id)
        if item.get("expires") is None:
            return item

        now = datetime.datetime.now()
        self.db().update({
            "expires": None,
            "updated": now,
        }, id=id)
        return self.get(id=id)

    def can_delete(self, sp, client_ip="", is_admin=False):
        """Check whether the given client is allowed to delete this SP."""
        if is_admin:
            return True
        created_ip = sp.get("created_by_ip", "")
        if created_ip and client_ip and created_ip == client_ip:
            return True
        return False

    def register(self, xml_string, created_by_ip=""):
        parsed = self.parse_metadata(xml_string)
        entity_id = parsed["entity_id"]

        db = self.db()
        now = datetime.datetime.now()
        ttl_hours = self._get_ttl_hours()
        expires = now + datetime.timedelta(hours=ttl_hours)

        # Check SP count limit (exclude updates to existing entity)
        existing = None
        try:
            existing = db.get(entity_id=entity_id)
        except Exception:
            pass

        if existing is None:
            total = db.count()
            if total >= MAX_SP_COUNT:
                raise Exception(f"SP 등록 한도에 도달했습니다 (최대 {MAX_SP_COUNT}개). 기존 SP를 삭제한 후 다시 시도해주세요.")

        fs = wiz.project.fs("metadata", "saml", "sp")
        safe_name = entity_id.replace("://", "_").replace("/", "_").replace(".", "_")
        fname = f"{safe_name}.xml"
        fs.write(fname, xml_string)

        protected = self._get_protected_entity_ids()
        is_protected = entity_id in protected

        data = {
            "entity_id": entity_id,
            "acs_url": json.dumps(parsed["acs_endpoints"]),
            "slo_url": json.dumps(parsed["slo_endpoints"]),
            "nameid_formats": json.dumps(parsed["nameid_formats"]),
            "certificates": json.dumps(parsed["certificates"]),
            "requested_attributes": json.dumps(parsed["requested_attributes"]),
            "raw_metadata_path": fname,
            "flags": json.dumps(parsed["flags"]),
            "expires": None if is_protected else expires,
            "updated": now,
        }

        if existing:
            db.update(data, id=existing["id"])
            result = db.get(id=existing["id"])
        else:
            data["created"] = now
            data["created_by_ip"] = str(created_by_ip)
            db.insert(data)
            result = db.get(entity_id=entity_id)

        result["warnings"] = parsed.get("warnings", [])
        return result

    def parse_metadata(self, xml_string):
        xml_bytes = xml_string.encode("utf-8") if isinstance(xml_string, str) else xml_string
        if len(xml_bytes) > MAX_XML_SIZE:
            raise Exception(f"XML 페이로드가 너무 큽니다 (최대 {MAX_XML_SIZE // 1024}KB)")
        try:
            root = etree.fromstring(xml_bytes, parser=_secure_xml_parser())
        except etree.XMLSyntaxError as e:
            raise Exception(f"XML 문법 오류: {str(e)}")

        ids = [str(item.get("ID")) for item in root.iter() if item.get("ID")]
        if len(ids) != len(set(ids)):
            raise Exception("SP metadata XML에 중복 ID가 있습니다.")

        if root.tag == f"{{{NS['md']}}}EntityDescriptor":
            candidates = [root]
        elif root.tag == f"{{{NS['md']}}}EntitiesDescriptor":
            candidates = root.findall(".//md:EntityDescriptor", NS)
        else:
            raise Exception("SAML metadata의 루트는 EntityDescriptor 또는 EntitiesDescriptor여야 합니다.")
        sp_candidates = [
            item for item in candidates
            if item.find("md:SPSSODescriptor", NS) is not None
        ]
        if len(sp_candidates) != 1:
            raise Exception("SP 등록 metadata에는 SPSSODescriptor를 가진 EntityDescriptor가 정확히 하나 필요합니다.")
        ed = sp_candidates[0]

        entity_id = ed.get("entityID")
        if not entity_id:
            raise Exception("entityID 속성이 없습니다.")

        sp_sso = ed.find(".//md:SPSSODescriptor", NS)
        if sp_sso is None:
            raise Exception("SPSSODescriptor 요소를 찾을 수 없습니다.")
        supported_protocols = str(
            sp_sso.get("protocolSupportEnumeration", "")
        ).split()
        if "urn:oasis:names:tc:SAML:2.0:protocol" not in supported_protocols:
            raise Exception("SPSSODescriptor가 SAML 2.0 protocol을 지원하지 않습니다.")

        validity_sources = [ed]
        validity_sources.extend(
            ancestor
            for ancestor in ed.iterancestors()
            if ancestor.tag == f"{{{NS['md']}}}EntitiesDescriptor"
        )
        validity_values = [
            item.get("validUntil") for item in validity_sources
            if item.get("validUntil")
        ]
        validity_deadlines = []
        for value in validity_values:
            try:
                deadline = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                if deadline.tzinfo is None:
                    deadline = deadline.replace(tzinfo=datetime.timezone.utc)
                validity_deadlines.append(deadline.astimezone(datetime.timezone.utc))
            except Exception:
                raise Exception("SP metadata validUntil 형식이 올바르지 않습니다.")
        metadata_valid_until = min(validity_deadlines) if validity_deadlines else None
        if metadata_valid_until is not None and metadata_valid_until <= datetime.datetime.now(datetime.timezone.utc):
            raise Exception("만료된 SP metadata는 등록할 수 없습니다.")

        acs_endpoints = []
        acs_indexes = set()
        acs_warnings = []
        for acs in sp_sso.findall("md:AssertionConsumerService", NS):
            location = str(acs.get("Location", ""))
            if not location.startswith(("https://", "http://")):
                raise Exception("AssertionConsumerService Location은 http 또는 https 절대 URL이어야 합니다.")
            binding = str(acs.get("Binding", ""))
            index = str(acs.get("index", ""))
            try:
                index_number = int(index)
                if index_number < 0 or index_number > 65535:
                    raise ValueError()
            except ValueError:
                raise Exception("AssertionConsumerService index는 0~65535 정수여야 합니다.")
            if index_number in acs_indexes:
                raise Exception("AssertionConsumerService index는 중복될 수 없습니다.")
            acs_indexes.add(index_number)
            is_default = str(acs.get("isDefault", "false"))
            if is_default.lower() not in ["true", "false", "1", "0"]:
                raise Exception("AssertionConsumerService isDefault는 boolean 값이어야 합니다.")
            if binding != "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST":
                acs_warnings.append(
                    "HTTP-POST가 아닌 AssertionConsumerService는 호환 정보로만 보관됩니다."
                )
            acs_endpoints.append({
                "binding": binding,
                "location": location,
                "index": str(index_number),
                "is_default": is_default,
            })
        if not acs_endpoints:
            raise Exception("AssertionConsumerService가 하나도 없습니다.")
        if not any(
            item["binding"] == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            for item in acs_endpoints
        ):
            raise Exception("HTTP-POST AssertionConsumerService가 하나 이상 필요합니다.")

        slo_endpoints = []
        slo_warnings = []
        for slo in sp_sso.findall("md:SingleLogoutService", NS):
            binding = str(slo.get("Binding", ""))
            location = str(slo.get("Location", ""))
            response_location = str(slo.get("ResponseLocation", ""))
            if binding not in [
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            ]:
                slo_warnings.append("지원 범위 밖 SLO Binding은 호환 정보로만 보관됩니다.")
            for label, value in [("Location", location), ("ResponseLocation", response_location)]:
                if value and not value.startswith(("https://", "http://")):
                    slo_warnings.append(f"SingleLogoutService {label}이 http 또는 https 절대 URL이 아닙니다.")
            slo_endpoints.append({
                "binding": binding,
                "location": location,
                "response_location": response_location,
            })

        nameid_formats = []
        for nf in sp_sso.findall("md:NameIDFormat", NS):
            if nf.text:
                nameid_formats.append(nf.text.strip())

        certificates = {
            "signing": [],
            "encryption": [],
            "encryption_methods": [],
            "details": [],
        }
        certificate_warnings = []
        for kd in sp_sso.findall("md:KeyDescriptor", NS):
            use = kd.get("use", "")
            if use not in ["", "signing", "encryption"]:
                raise Exception("KeyDescriptor use는 signing 또는 encryption이어야 합니다.")
            roles = [use] if use else ["signing", "encryption"]
            if not use:
                certificate_warnings.append(
                    "use가 없는 KeyDescriptor는 signing과 encryption 양쪽 키로 해석됩니다. 키 분리를 권장합니다."
                )
            cert_elements = kd.findall(".//ds:X509Certificate", NS)
            for cert_el in cert_elements:
                if not cert_el.text:
                    continue
                cert_text = "".join(cert_el.text.split())
                try:
                    certificate = x509.load_der_x509_certificate(
                        base64.b64decode(cert_text, validate=True)
                    )
                except Exception:
                    certificate_warnings.append("읽을 수 없는 X.509 인증서는 사용하지 않습니다.")
                    continue
                public_key = certificate.public_key()
                fingerprint = certificate.fingerprint(hashes.SHA256()).hex().upper()
                accepted_roles = []
                for role in roles:
                    if role == "encryption" and not isinstance(public_key, rsa.RSAPublicKey):
                        certificate_warnings.append(
                            "RSA가 아닌 encryption 인증서는 현재 RSA-OAEP Assertion 암호화에 사용할 수 없습니다."
                        )
                        continue
                    if cert_text not in certificates[role]:
                        certificates[role].append(cert_text)
                    accepted_roles.append(role)
                key_size = int(getattr(public_key, "key_size", 0) or 0)
                if key_size and key_size < 2048:
                    certificate_warnings.append(
                        f"{key_size}-bit 인증서 키는 호환 시험용이며 2048-bit 이상을 권장합니다."
                    )
                certificates["details"].append({
                    "use": use or "both",
                    "accepted_roles": accepted_roles,
                    "sha256": fingerprint,
                    "subject": certificate.subject.rfc4514_string(),
                    "serial_number": format(certificate.serial_number, "X"),
                    "public_key_type": public_key.__class__.__name__,
                    "key_size": key_size,
                })
            if use in ["", "encryption"]:
                for method in kd.findall("md:EncryptionMethod", NS):
                    algorithm = str(method.get("Algorithm", "")).strip()
                    if algorithm and algorithm not in certificates["encryption_methods"]:
                        certificates["encryption_methods"].append(algorithm)

        requested_attributes = []
        acs_el = sp_sso.find(".//md:AttributeConsumingService", NS)
        if acs_el is not None:
            for ra in acs_el.findall("md:RequestedAttribute", NS):
                requested_attributes.append({
                    "name": ra.get("Name", ""),
                    "name_format": ra.get("NameFormat", ""),
                    "is_required": ra.get("isRequired", "false"),
                    "friendly_name": ra.get("FriendlyName", ""),
                })

        signature_parent = None
        signature_scope = ""
        for candidate in [ed] + list(ed.iterancestors()):
            if candidate.find("ds:Signature", NS) is not None:
                signature_parent = candidate
                signature_scope = "entity" if candidate is ed else "aggregate"
                break
        flags = {
            "authn_requests_signed": sp_sso.get("AuthnRequestsSigned", "false"),
            "want_assertions_signed": sp_sso.get("WantAssertionsSigned", "false"),
            "has_signing_cert": len(certificates["signing"]) > 0,
            "has_encryption_cert": len(certificates["encryption"]) > 0,
            "has_slo": len(slo_endpoints) > 0,
            "metadata_signature_present": signature_parent is not None,
            "metadata_signature_scope": signature_scope,
            "metadata_valid_until": metadata_valid_until.isoformat() if metadata_valid_until is not None else "",
        }

        flags["metadata_signature_valid"] = False
        if flags["metadata_signature_present"]:
            signature_cert = signature_parent.find("ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate", NS)
            if signature_cert is not None and signature_cert.text:
                cert_pem = "-----BEGIN CERTIFICATE-----\n" + "".join(signature_cert.text.split()) + "\n-----END CERTIFICATE-----\n"
                try:
                    XMLVerifier().verify(signature_parent, x509_cert=cert_pem, id_attribute="ID")
                    flags["metadata_signature_valid"] = True
                except Exception:
                    pass

        warnings = []
        if not flags["has_signing_cert"]:
            warnings.append("SP 메타데이터에 서명 인증서가 없습니다.")
        if not flags["has_slo"]:
            warnings.append("SP 메타데이터에 SingleLogoutService가 없습니다.")
        warnings.extend(slo_warnings)
        warnings.extend(acs_warnings)
        warnings.extend(certificate_warnings)
        if set(certificates["signing"]).intersection(certificates["encryption"]):
            warnings.append("동일 공개키를 signing과 encryption에 함께 사용하고 있습니다. 키 분리를 권장합니다.")
        if not flags["has_encryption_cert"]:
            warnings.append("SP 메타데이터에 암호화 인증서가 없습니다.")
        if not flags["metadata_signature_present"]:
            warnings.append("서명되지 않은 SP 메타데이터는 호환 시험으로 등록됩니다.")
        elif not flags["metadata_signature_valid"]:
            warnings.append("SP 메타데이터 signature 검증에 실패했습니다.")
        flags["standards_warnings"] = list(warnings)
        flags["standards_status"] = "compatibility" if warnings else "standard"

        return {
            "entity_id": entity_id,
            "acs_endpoints": acs_endpoints,
            "slo_endpoints": slo_endpoints,
            "nameid_formats": nameid_formats,
            "certificates": certificates,
            "requested_attributes": requested_attributes,
            "flags": flags,
            "warnings": warnings,
        }


Model = Registry
