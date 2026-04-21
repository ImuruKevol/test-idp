import json

struct = wiz.model("portal/samlidp/struct")


def _client_ip():
    try:
        return wiz.request.ip()
    except Exception:
        return "unknown"

def _is_admin():
    try:
        session = wiz.model("portal/season/session").use()
        return session.get("role") == "admin"
    except Exception:
        return False


def _require_admin():
    if _is_admin() is False:
        wiz.response.status(403, message="admin 권한이 필요합니다.")

def _serialize_row(row):
    for key in ("acs_url", "slo_url", "nameid_formats", "certificates", "requested_attributes", "flags"):
        val = row.get(key)
        if isinstance(val, str):
            try:
                row[key] = json.loads(val)
            except Exception:
                pass
    if row.get("expires") and hasattr(row["expires"], "isoformat"):
        row["expires"] = row["expires"].isoformat()
    return row


def list():
    ip = _client_ip()
    admin = _is_admin()
    rows = struct.registry.list()
    for row in rows:
        _serialize_row(row)
        row["can_delete"] = struct.registry.can_delete(row, client_ip=ip, is_admin=admin)
    wiz.response.status(200, data=rows)


def register():
    ip = _client_ip()
    xml_string = wiz.request.query("xml", True)
    try:
        result = struct.registry.register(xml_string, created_by_ip=ip)
    except Exception as e:
        wiz.response.status(400, message=str(e))
    _serialize_row(result)
    wiz.response.status(200, data=result)


def get():
    sp_id = wiz.request.query("id", True)
    ip = _client_ip()
    admin = _is_admin()
    try:
        item = struct.registry.get(id=sp_id)
    except Exception as e:
        wiz.response.status(404, message=str(e))
    _serialize_row(item)
    item["can_delete"] = struct.registry.can_delete(item, client_ip=ip, is_admin=admin)
    wiz.response.status(200, data=item)


def delete():
    sp_id = wiz.request.query("id", True)
    ip = _client_ip()
    admin = _is_admin()
    try:
        sp = struct.registry.get(id=sp_id)
    except Exception as e:
        wiz.response.status(404, message=str(e))
    if not struct.registry.can_delete(sp, client_ip=ip, is_admin=admin):
        wiz.response.status(403, message="삭제 권한이 없습니다. admin 로그인 또는 등록한 IP에서만 삭제할 수 있습니다.")
    try:
        struct.registry.delete(sp_id)
    except Exception as e:
        wiz.response.status(400, message=str(e))
    wiz.response.status(200)


def extend_validity():
    _require_admin()
    sp_id = wiz.request.query("id", True)
    ttl_hours = int(wiz.request.query("ttl_hours", 24))
    try:
        result = struct.registry.extend_validity(sp_id, ttl_hours=ttl_hours)
        struct.core.audit.log(
            "saml_sp.extend",
            protocol="saml",
            target_type="saml_sp",
            target_id=result["id"],
            payload={"entity_id": result.get("entity_id", ""), "ttl_hours": ttl_hours},
        )
    except Exception as e:
        wiz.response.status(400, message=str(e))
    _serialize_row(result)
    result["can_delete"] = struct.registry.can_delete(result, client_ip=_client_ip(), is_admin=True)
    wiz.response.status(200, data=result)


def set_unlimited():
    _require_admin()
    sp_id = wiz.request.query("id", True)
    try:
        result = struct.registry.set_unlimited(sp_id)
        struct.core.audit.log(
            "saml_sp.set_unlimited",
            protocol="saml",
            target_type="saml_sp",
            target_id=result["id"],
            payload={"entity_id": result.get("entity_id", "")},
        )
    except Exception as e:
        wiz.response.status(400, message=str(e))
    _serialize_row(result)
    result["can_delete"] = struct.registry.can_delete(result, client_ip=_client_ip(), is_admin=True)
    wiz.response.status(200, data=result)
