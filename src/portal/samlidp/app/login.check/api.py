import json

struct = wiz.model("portal/samlidp/struct")
core = wiz.model("portal/idpcore/struct")


def sp_list():
    rows = struct.registry.list()
    for row in rows:
        for key in ("acs_url", "slo_url", "nameid_formats", "certificates", "requested_attributes", "flags"):
            val = row.get(key)
            if isinstance(val, str):
                try:
                    row[key] = json.loads(val)
                except Exception:
                    pass
    wiz.response.status(200, data=rows)


def user_list():
    rows = core.user.list_active()
    sanitized = []
    for u in rows:
        item = dict(u)
        item.pop("password_hash", None)
        sanitized.append(item)
    wiz.response.status(200, data=sanitized)


def preset_list():
    rows = core.attribute_preset.list(protocol="saml")
    wiz.response.status(200, data=rows)


def tx_list():
    rows = struct.process.list_transactions()
    wiz.response.status(200, data=rows)


def parse_request():
    saml_request = wiz.request.query("SAMLRequest", True)
    relay_state = wiz.request.query("RelayState", "")
    binding = wiz.request.query("binding", "POST")
    try:
        result = struct.process.parse_authn_request(saml_request, relay_state=relay_state, binding=binding)
    except Exception as e:
        wiz.response.status(400, message=str(e))
    wiz.response.status(200, data=result)


def build_response():
    params = dict()
    params["transaction_id"] = wiz.request.query("transaction_id", "")
    params["user_id"] = wiz.request.query("user_id", True)
    params["sp_entity_id"] = wiz.request.query("sp_entity_id", "")
    params["acs_url"] = wiz.request.query("acs_url", "")
    params["request_id"] = wiz.request.query("request_id", "")
    params["relay_state"] = wiz.request.query("relay_state", "")
    params["nameid_format"] = wiz.request.query("nameid_format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
    params["nameid_value"] = wiz.request.query("nameid_value", "")
    params["preset_id"] = wiz.request.query("preset_id", "")

    attribute_overrides = wiz.request.query("attribute_overrides", "")
    if attribute_overrides:
        if isinstance(attribute_overrides, str):
            try:
                params["attribute_overrides"] = json.loads(attribute_overrides)
            except Exception:
                params["attribute_overrides"] = {}
        else:
            params["attribute_overrides"] = attribute_overrides

    params["sign_response"] = wiz.request.query("sign_response", "true") == "true"
    params["sign_assertion"] = wiz.request.query("sign_assertion", "true") == "true"
    params["session_index"] = wiz.request.query("session_index", "")
    params["authn_context_class_ref"] = wiz.request.query("authn_context_class_ref", "")

    try:
        result = struct.process.build_response(params)
    except Exception as e:
        wiz.response.status(400, message=str(e))
    wiz.response.status(200, data=result)
