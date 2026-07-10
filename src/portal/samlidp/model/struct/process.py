import base64
import datetime
import hashlib
import json
import re
import uuid
import zlib
from lxml import etree
from signxml import XMLSigner, methods

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}

MAX_XML_SIZE = 256 * 1024  # 256KB
DEFAULT_AUTHN_CONTEXT_CLASS_REF = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

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


class Process:
    def __init__(self, struct):
        self.struct = struct

    def _debug_fs(self):
        return wiz.project.fs("metadata", "debug")

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

    def parse_authn_request(self, saml_request, relay_state="", binding="POST"):
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
        destination = root.get("Destination", "")
        issue_instant = root.get("IssueInstant", "")
        force_authn = root.get("ForceAuthn", "false")
        is_passive = root.get("IsPassive", "false")

        issuer_el = root.find("saml:Issuer", NS)
        issuer = self._normalize_entity_id(issuer_el.text.strip() if issuer_el is not None and issuer_el.text else "")

        nameid_policy_el = root.find("samlp:NameIDPolicy", NS)
        nameid_format = ""
        if nameid_policy_el is not None:
            nameid_format = nameid_policy_el.get("Format", "")

        authn_context = []
        rac_el = root.find("samlp:RequestedAuthnContext", NS)
        if rac_el is not None:
            for acr in rac_el.findall("saml:AuthnContextClassRef", NS):
                if acr.text:
                    authn_context.append(acr.text.strip())

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
            "authn_context": authn_context,
            "relay_state": relay_state,
            "binding": binding,
            "raw_request_key": key,
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
        session_index_custom = params.get("session_index", "")
        authn_context_requested = params.get("authn_context_requested", [])
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

        sp_entity_id = self._resolve_sp_entity_id(sp_entity_id, acs_url)
        acs_url = self._resolve_acs_url(acs_url, sp_entity_id)

        if sp_entity_id == "":
            raise Exception("SP entity_id를 확인할 수 없습니다. AuthnRequest Issuer를 설정하거나 등록된 ACS URL과 일치하는 SP를 먼저 등록하세요.")
        if acs_url == "":
            raise Exception("ACS URL을 확인할 수 없습니다. AuthnRequest에 AssertionConsumerServiceURL을 포함하거나 SP 메타데이터를 등록하세요.")

        core = self.struct.core
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

        resolved_attribute_specs = {}
        normalized_attributes = {}
        for raw_name, raw_value in attributes.items():
            attr_spec = core.saml_attribute_spec(raw_name)
            if attr_spec is None:
                continue
            resolved_attribute_specs[attr_spec["urn"]] = attr_spec
            normalized_attributes[attr_spec["urn"]] = raw_value
        attributes = normalized_attributes

        if not nameid_value:
            if "emailAddress" in nameid_format:
                nameid_value = user.get("email", user.get("username", ""))
            elif "persistent" in nameid_format:
                nameid_value = user.get("id", "")
            elif "transient" in nameid_format:
                nameid_value = f"_transient_{uuid.uuid4().hex[:16]}"
            else:
                nameid_value = user.get("username", "")

        metadata = self.struct.metadata
        idp_entity_id = metadata.entity_id()
        now = datetime.datetime.utcnow()
        response_id = f"_resp_{uuid.uuid4().hex}"
        assertion_id = f"_assert_{uuid.uuid4().hex}"
        session_index = session_index_custom or f"_sidx_{uuid.uuid4().hex[:16]}"
        not_on_or_after = now + datetime.timedelta(minutes=5)
        session_not_on_or_after = now + datetime.timedelta(hours=8)
        instant = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        not_after_str = not_on_or_after.strftime("%Y-%m-%dT%H:%M:%SZ")
        session_not_after_str = session_not_on_or_after.strftime("%Y-%m-%dT%H:%M:%SZ")

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
        conditions.set("NotBefore", instant)
        conditions.set("NotOnOrAfter", not_after_str)
        aud_restriction = etree.SubElement(conditions, f"{{{NS['saml']}}}AudienceRestriction")
        audience = etree.SubElement(aud_restriction, f"{{{NS['saml']}}}Audience")
        audience.text = sp_entity_id

        authn_stmt = etree.SubElement(assertion, f"{{{NS['saml']}}}AuthnStatement")
        authn_stmt.set("AuthnInstant", instant)
        authn_stmt.set("SessionIndex", session_index)
        authn_stmt.set("SessionNotOnOrAfter", session_not_after_str)
        authn_ctx = etree.SubElement(authn_stmt, f"{{{NS['saml']}}}AuthnContext")
        authn_ctx_ref = etree.SubElement(authn_ctx, f"{{{NS['saml']}}}AuthnContextClassRef")
        authn_ctx_ref.text = authn_context_class_ref

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
            response.remove(assertion)
            response.append(assertion_signed)
            assertion = assertion_signed

        if sign_response:
            signer = XMLSigner(
                method=methods.enveloped,
                signature_algorithm="rsa-sha256",
                digest_algorithm="sha256",
                c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
            )
            response = signer.sign(response, key=key_pem, cert=cert_pem)

        response_xml = etree.tostring(response, pretty_print=True, xml_declaration=True, encoding="UTF-8").decode("utf-8")
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
            "attributes": attributes,
            "raw_response_key": resp_key,
            "signed_response": sign_response,
            "signed_assertion": sign_assertion,
        }

    def get_debug_raw(self, key):
        if not re.match(r'^[a-zA-Z0-9_\-]+$', key):
            raise Exception("Invalid debug key")
        fs = self._debug_fs()
        fname = f"{key}.xml"
        if not fs.exists(fname):
            raise Exception(f"Debug file not found: {key}")
        return fs.read(fname)

    def list_transactions(self, sp_entity_id="", status="", limit=50):
        db = self.struct.db("saml_transaction")
        kwargs = dict(orderby="-created", dump=limit)
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

    def parse_logout_request(self, saml_request, relay_state="", binding="POST"):
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
        destination = root.get("Destination", "")
        issue_instant = root.get("IssueInstant", "")
        not_on_or_after = root.get("NotOnOrAfter", "")

        issuer_el = root.find("saml:Issuer", NS)
        issuer = issuer_el.text.strip() if issuer_el is not None and issuer_el.text else ""

        name_id_el = root.find("saml:NameID", NS)
        nameid_value = ""
        nameid_format = ""
        nameid_sp_qualifier = ""
        if name_id_el is not None:
            nameid_value = name_id_el.text.strip() if name_id_el.text else ""
            nameid_format = name_id_el.get("Format", "")
            nameid_sp_qualifier = name_id_el.get("SPNameQualifier", "")

        session_indexes = []
        for si_el in root.findall("samlp:SessionIndex", NS):
            if si_el.text:
                session_indexes.append(si_el.text.strip())

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
            "session_indexes": session_indexes,
            "relay_state": relay_state,
            "binding": binding,
            "raw_request_key": key,
            "matched_sessions": matched,
        }

    def _match_sessions(self, sp_entity_id, session_indexes, nameid_value=""):
        db = self.struct.db("saml_transaction")
        matched = []

        if session_indexes:
            for si in session_indexes:
                try:
                    rows = db.rows(session_index=si, sp_entity_id=sp_entity_id, status="success")
                    matched.extend(rows)
                except Exception:
                    pass

        if not matched and nameid_value:
            all_rows = db.rows(sp_entity_id=sp_entity_id, status="success")
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

        return matched

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

        metadata = self.struct.metadata
        idp_entity_id = metadata.entity_id()
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

        response_xml = etree.tostring(resp, pretty_print=True, xml_declaration=True, encoding="UTF-8").decode("utf-8")
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

        if not destination and sp_entity_id:
            try:
                sp = self.struct.registry.get(entity_id=sp_entity_id)
                slo_urls = sp.get("slo_url", "[]")
                if isinstance(slo_urls, str):
                    slo_urls = json.loads(slo_urls)
                for ep in slo_urls:
                    if ep.get("location"):
                        destination = ep["location"]
                        break
            except Exception:
                pass

        metadata = self.struct.metadata
        idp_entity_id = metadata.entity_id()
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

        request_xml = etree.tostring(req, pretty_print=True, xml_declaration=True, encoding="UTF-8").decode("utf-8")
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
            "raw_request_key": req_key,
            "signed": sign,
        }

    def list_active_sessions(self, sp_entity_id="", limit=50):
        db = self.struct.db("saml_transaction")
        kwargs = dict(orderby="-created", dump=limit, status="success")
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


Model = Process
