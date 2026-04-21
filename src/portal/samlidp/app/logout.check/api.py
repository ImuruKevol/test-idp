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


def active_sessions():
    sp_entity_id = wiz.request.query("sp_entity_id", "")
    rows = struct.process.list_active_sessions(sp_entity_id=sp_entity_id)
    wiz.response.status(200, data=rows)


def parse_logout_request():
    saml_request = wiz.request.query("SAMLRequest", True)
    relay_state = wiz.request.query("RelayState", "")
    binding = wiz.request.query("binding", "POST")
    try:
        result = struct.process.parse_logout_request(saml_request, relay_state=relay_state, binding=binding)
    except Exception as e:
        wiz.response.status(400, message=str(e))
    wiz.response.status(200, data=result)


def build_logout_response():
    params = dict()
    params["request_id"] = wiz.request.query("request_id", "")
    params["sp_entity_id"] = wiz.request.query("sp_entity_id", "")
    params["destination"] = wiz.request.query("destination", "")
    params["relay_state"] = wiz.request.query("relay_state", "")
    params["status_code"] = wiz.request.query("status_code", "urn:oasis:names:tc:SAML:2.0:status:Success")
    params["sign"] = wiz.request.query("sign", "true") == "true"

    invalidate_ids = wiz.request.query("invalidate_ids", "")
    if invalidate_ids:
        if isinstance(invalidate_ids, str):
            try:
                ids = json.loads(invalidate_ids)
            except Exception:
                ids = [x.strip() for x in invalidate_ids.split(",") if x.strip()]
        else:
            ids = invalidate_ids
        struct.process.invalidate_sessions(ids)

    try:
        result = struct.process.build_logout_response(params)
    except Exception as e:
        wiz.response.status(400, message=str(e))
    wiz.response.status(200, data=result)


def build_logout_request():
    params = dict()
    params["sp_entity_id"] = wiz.request.query("sp_entity_id", True)
    params["nameid_value"] = wiz.request.query("nameid_value", True)
    params["nameid_format"] = wiz.request.query("nameid_format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
    params["destination"] = wiz.request.query("destination", "")
    params["sign"] = wiz.request.query("sign", "true") == "true"

    session_indexes_str = wiz.request.query("session_indexes", "")
    if session_indexes_str:
        if isinstance(session_indexes_str, str):
            try:
                params["session_indexes"] = json.loads(session_indexes_str)
            except Exception:
                params["session_indexes"] = [x.strip() for x in session_indexes_str.split(",") if x.strip()]
        else:
            params["session_indexes"] = session_indexes_str
    else:
        params["session_indexes"] = []

    try:
        result = struct.process.build_logout_request(params)
    except Exception as e:
        wiz.response.status(400, message=str(e))
    wiz.response.status(200, data=result)


def invalidate_sessions():
    session_ids_str = wiz.request.query("session_ids", True)
    if isinstance(session_ids_str, str):
        try:
            session_ids = json.loads(session_ids_str)
        except Exception:
            session_ids = [x.strip() for x in session_ids_str.split(",") if x.strip()]
    else:
        session_ids = session_ids_str
    invalidated = struct.process.invalidate_sessions(session_ids)
    wiz.response.status(200, data=invalidated)
