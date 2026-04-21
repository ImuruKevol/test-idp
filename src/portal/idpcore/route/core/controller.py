import json

core = wiz.model("portal/idpcore/struct")
rate_limiter = wiz.model("portal/idpcore/struct/rate_limiter")

def _client_ip():
    try:
        return wiz.request.ip()
    except Exception:
        return "unknown"

def _sanitize_user(user):
    """Strip sensitive fields from user data before returning to client."""
    if user is None:
        return None
    if isinstance(user, dict):
        result = dict(user)
        result.pop("password_hash", None)
        return result
    return user

def _sanitize_users(users):
    """Strip sensitive fields from a list of user dicts."""
    return [_sanitize_user(u) for u in users]

def _is_admin():
    try:
        session = wiz.model("portal/season/session").use()
        return session.get("role") == "admin"
    except Exception:
        return False

def _require_admin():
    if _is_admin() is False:
        wiz.response.status(403, message="admin 권한이 필요합니다.")

def _add_can_delete(user, client_ip, is_admin):
    """Add can_delete flag to user data."""
    u = dict(user) if user else {}
    created_ip = u.get("created_by_ip", "")
    if is_admin:
        u["can_delete"] = True
    elif created_ip and client_ip and created_ip == client_ip:
        u["can_delete"] = True
    else:
        u["can_delete"] = False
    return u

def _sanitize_users_with_delete(users, client_ip, is_admin):
    return [_add_can_delete(_sanitize_user(u), client_ip, is_admin) for u in users]

TEMP_USER_ALLOWED_FIELDS = {
    "username", "password", "email", "display_name",
    "profile", "saml_attributes", "oidc_claims",
}

USER_UPDATE_ALLOWED_FIELDS = {
    "username", "password", "email", "display_name", "role",
    "profile", "saml_attributes", "oidc_claims",
}

segment = wiz.request.match("/api/idpcore/<action>")
if segment is None:
    wiz.response.status(404)

action = segment.action

if action == "info":
    try:
        result = core.info()
    except Exception as e:
        wiz.response.status(500, message=str(e))
    wiz.response.status(200, data=result)

if action == "seed":
    _require_admin()
    try:
        result = core.seed(force=False)
    except Exception as e:
        wiz.response.status(500, message=str(e))
    wiz.response.status(200, data=result)

if action == "seed-force":
    _require_admin()
    ip = _client_ip()
    if not rate_limiter.check(f"seed-force:{ip}", max_requests=3, window_seconds=300):
        wiz.response.status(429, message="요청이 너무 많습니다. 잠시 후 다시 시도해주세요.")
    try:
        result = core.seed(force=True)
    except Exception as e:
        wiz.response.status(500, message=str(e))
    wiz.response.status(200, data=result)

if action == "users":
    try:
        result = _sanitize_users(core.user.list_active())
    except Exception as e:
        wiz.response.status(500, message=str(e))
    wiz.response.status(200, data=result)

if action == "users-permanent":
    try:
        result = _sanitize_users(core.user.list_permanent())
    except Exception as e:
        wiz.response.status(500, message=str(e))
    wiz.response.status(200, data=result)

if action == "users-temporary":
    include_expired = wiz.request.query("include_expired", "") == "true"
    ip = _client_ip()
    admin = _is_admin()
    try:
        result = _sanitize_users_with_delete(core.user.list_temporary(include_expired=include_expired), ip, admin)
    except Exception as e:
        wiz.response.status(500, message=str(e))
    wiz.response.status(200, data=result)

if action == "user":
    id = wiz.request.query("id", "")
    username = wiz.request.query("username", "")
    try:
        result = core.user.get(id=id or None, username=username or None)
    except Exception as e:
        wiz.response.status(500, message=str(e))
    if result is None:
        wiz.response.status(404, message="user not found")
    wiz.response.status(200, data=_sanitize_user(result))

if action == "user-create-temporary":
    ip = _client_ip()
    if not rate_limiter.check(f"create-temp:{ip}", max_requests=10, window_seconds=300):
        wiz.response.status(429, message="임시 계정 생성 요청이 너무 많습니다. 잠시 후 다시 시도해주세요.")
    raw_data = wiz.request.query()
    data = {k: v for k, v in raw_data.items() if k in TEMP_USER_ALLOWED_FIELDS}
    if "saml_attributes" in data and isinstance(data["saml_attributes"], str):
        try:
            data["saml_attributes"] = json.loads(data["saml_attributes"])
        except Exception:
            pass
    if "oidc_claims" in data and isinstance(data["oidc_claims"], str):
        try:
            data["oidc_claims"] = json.loads(data["oidc_claims"])
        except Exception:
            pass
    if "profile" in data and isinstance(data["profile"], str):
        try:
            data["profile"] = json.loads(data["profile"])
        except Exception:
            pass
    try:
        user_id = core.user.create_temporary(data, created_by_ip=ip)
        result = core.user.get(id=user_id)
    except Exception as e:
        wiz.response.status(400, message=str(e))
    wiz.response.status(200, data=_sanitize_user(result))

if action == "user-update":
    id = wiz.request.query("id", True)
    raw_data = wiz.request.query()
    raw_data.pop("id", None)
    data = {k: v for k, v in raw_data.items() if k in USER_UPDATE_ALLOWED_FIELDS}
    if "saml_attributes" in data and isinstance(data["saml_attributes"], str):
        try:
            data["saml_attributes"] = json.loads(data["saml_attributes"])
        except Exception:
            pass
    if "oidc_claims" in data and isinstance(data["oidc_claims"], str):
        try:
            data["oidc_claims"] = json.loads(data["oidc_claims"])
        except Exception:
            pass
    if "profile" in data and isinstance(data["profile"], str):
        try:
            data["profile"] = json.loads(data["profile"])
        except Exception:
            pass
    try:
        core.user.update(data, id=id)
        result = core.user.get(id=id)
    except Exception as e:
        wiz.response.status(400, message=str(e))
    wiz.response.status(200, data=_sanitize_user(result))

if action == "user-delete":
    ip = _client_ip()
    if not rate_limiter.check(f"user-delete:{ip}", max_requests=10, window_seconds=300):
        wiz.response.status(429, message="요청이 너무 많습니다. 잠시 후 다시 시도해주세요.")
    id = wiz.request.query("id", True)
    admin = _is_admin()
    try:
        user = core.user.get(id=id)
    except Exception as e:
        wiz.response.status(404, message=str(e))
    if not core.user.can_delete(user, client_ip=ip, is_admin=admin):
        wiz.response.status(403, message="삭제 권한이 없습니다. admin 로그인 또는 등록한 IP에서만 삭제할 수 있습니다.")
    try:
        core.user.delete(id=id)
    except Exception as e:
        wiz.response.status(400, message=str(e))
    wiz.response.status(200, message="deleted")

if action == "cleanup-expired":
    try:
        result = core.user.cleanup_expired()
    except Exception as e:
        wiz.response.status(500, message=str(e))
    wiz.response.status(200, data=result)

if action == "user-extend-validity":
    _require_admin()
    id = wiz.request.query("id", True)
    ttl_hours = int(wiz.request.query("ttl_hours", 24))
    try:
        result = core.user.extend_validity(id=id, ttl_hours=ttl_hours)
        core.audit.log(
            "temporary_account.extend",
            protocol="common",
            target_type="user",
            target_id=result["id"],
            payload={"ttl_hours": ttl_hours, "username": result.get("username", "")},
        )
    except Exception as e:
        wiz.response.status(400, message=str(e))
    wiz.response.status(200, data=_sanitize_user(result))

if action == "user-set-unlimited":
    _require_admin()
    id = wiz.request.query("id", True)
    try:
        result = core.user.set_unlimited(id=id)
        core.audit.log(
            "temporary_account.set_unlimited",
            protocol="common",
            target_type="user",
            target_id=result["id"],
            payload={"username": result.get("username", "")},
        )
    except Exception as e:
        wiz.response.status(400, message=str(e))
    wiz.response.status(200, data=_sanitize_user(result))

if action == "saml-attribute-catalog":
    try:
        result = core.saml_attribute_catalog()
    except Exception as e:
        wiz.response.status(500, message=str(e))
    wiz.response.status(200, data=result)

if action == "presets":
    protocol = wiz.request.query("protocol", "")
    try:
        result = core.attribute_preset.list(protocol=protocol)
    except Exception as e:
        wiz.response.status(500, message=str(e))
    wiz.response.status(200, data=result)

if action == "rate-limit-reset":
    key = wiz.request.query("key", "")
    rate_limiter.reset(key=key if key else None)
    wiz.response.status(200, message="rate limits reset")

wiz.response.status(404)
