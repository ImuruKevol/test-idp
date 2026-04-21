import json
import datetime
from lxml import etree

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

        ed = root if root.tag == f"{{{NS['md']}}}EntityDescriptor" else root.find(".//md:EntityDescriptor", NS)
        if ed is None:
            raise Exception("EntityDescriptor 요소를 찾을 수 없습니다.")

        entity_id = ed.get("entityID")
        if not entity_id:
            raise Exception("entityID 속성이 없습니다.")

        sp_sso = ed.find(".//md:SPSSODescriptor", NS)
        if sp_sso is None:
            raise Exception("SPSSODescriptor 요소를 찾을 수 없습니다.")

        acs_endpoints = []
        for acs in sp_sso.findall("md:AssertionConsumerService", NS):
            acs_endpoints.append({
                "binding": acs.get("Binding", ""),
                "location": acs.get("Location", ""),
                "index": acs.get("index", "0"),
                "is_default": acs.get("isDefault", "false"),
            })
        if not acs_endpoints:
            raise Exception("AssertionConsumerService가 하나도 없습니다.")

        slo_endpoints = []
        for slo in sp_sso.findall("md:SingleLogoutService", NS):
            slo_endpoints.append({
                "binding": slo.get("Binding", ""),
                "location": slo.get("Location", ""),
            })

        nameid_formats = []
        for nf in sp_sso.findall("md:NameIDFormat", NS):
            if nf.text:
                nameid_formats.append(nf.text.strip())

        certificates = {"signing": [], "encryption": []}
        for kd in sp_sso.findall("md:KeyDescriptor", NS):
            use = kd.get("use", "signing")
            cert_el = kd.find(".//ds:X509Certificate", NS)
            if cert_el is not None and cert_el.text:
                cert_text = cert_el.text.strip()
                if use in certificates:
                    certificates[use].append(cert_text)
                else:
                    certificates["signing"].append(cert_text)

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

        flags = {
            "authn_requests_signed": sp_sso.get("AuthnRequestsSigned", "false"),
            "want_assertions_signed": sp_sso.get("WantAssertionsSigned", "false"),
            "has_signing_cert": len(certificates["signing"]) > 0,
            "has_encryption_cert": len(certificates["encryption"]) > 0,
            "has_slo": len(slo_endpoints) > 0,
        }

        warnings = []
        if not flags["has_signing_cert"]:
            warnings.append("SP 메타데이터에 서명 인증서가 없습니다.")
        if not flags["has_slo"]:
            warnings.append("SP 메타데이터에 SingleLogoutService가 없습니다.")
        if not flags["has_encryption_cert"]:
            warnings.append("SP 메타데이터에 암호화 인증서가 없습니다.")

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
