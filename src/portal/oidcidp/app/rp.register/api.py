struct = wiz.model("portal/oidcidp/struct")


def _is_admin():
    try:
        session = wiz.model("portal/season/session").use()
        return session.get("role") == "admin"
    except Exception:
        return False


def _require_admin():
    if _is_admin() is False:
        wiz.response.status(403, message="admin 권한이 필요합니다.")


def bootstrap():
    wiz.response.status(200, data={
        "clients": [struct.registry.public_view(item) for item in struct.registry.list()],
        "provider": struct.provider.info(),
        "options": {
            "auth_methods": struct.registry.auth_method_options(),
            "grant_types": struct.registry.grant_type_options(),
            "response_types": struct.registry.response_type_options(),
            "scope_options": struct.registry.scope_options(),
        },
    })


def register():
    params = {
        "client_name": wiz.request.query("client_name", True),
        "redirect_uris": wiz.request.query("redirect_uris", "[]"),
        "post_logout_redirect_uris": wiz.request.query("post_logout_redirect_uris", "[]"),
        "grant_types": wiz.request.query("grant_types", "[]"),
        "response_types": wiz.request.query("response_types", "[]"),
        "scope_policy": wiz.request.query("scope_policy", "[]"),
        "claims_policy": wiz.request.query("claims_policy", "[]"),
        "token_endpoint_auth_method": wiz.request.query("token_endpoint_auth_method", "client_secret_basic"),
        "public_client": wiz.request.query("public_client", "false"),
        "jwks": wiz.request.query("jwks", ""),
        "jwks_uri": wiz.request.query("jwks_uri", ""),
        "extra": wiz.request.query("extra", "{}"),
        "active": wiz.request.query("active", "true"),
        "allow_plain_pkce": wiz.request.query("allow_plain_pkce", "false"),
    }
    try:
        result = struct.registry.register(params)
    except Exception as e:
        wiz.response.status(400, message=str(e))

    response = struct.registry.public_view(result, include_secret=True)
    response["client_secret_one_time"] = bool(result.get("client_secret"))
    response["provider"] = struct.provider.info()
    wiz.response.status(200, data=response)


def get():
    item_id = wiz.request.query("id", True)
    try:
        result = struct.registry.get(id=item_id)
    except Exception as e:
        wiz.response.status(404, message=str(e))
    wiz.response.status(200, data=struct.registry.public_view(result))


def update():
    item_id = wiz.request.query("id", True)
    params = {
        "client_name": wiz.request.query("client_name", True),
        "redirect_uris": wiz.request.query("redirect_uris", "[]"),
        "post_logout_redirect_uris": wiz.request.query("post_logout_redirect_uris", "[]"),
        "grant_types": wiz.request.query("grant_types", "[]"),
        "response_types": wiz.request.query("response_types", "[]"),
        "scope_policy": wiz.request.query("scope_policy", "[]"),
        "claims_policy": wiz.request.query("claims_policy", "[]"),
        "token_endpoint_auth_method": wiz.request.query("token_endpoint_auth_method", "client_secret_basic"),
        "public_client": wiz.request.query("public_client", "false"),
        "jwks": wiz.request.query("jwks", ""),
        "jwks_uri": wiz.request.query("jwks_uri", ""),
        "extra": wiz.request.query("extra", "{}"),
        "active": wiz.request.query("active", "true"),
        "allow_plain_pkce": wiz.request.query("allow_plain_pkce", "false"),
    }
    try:
        result = struct.registry.update(item_id, params)
        struct.core.audit.log(
            "oidc_rp.update",
            protocol="oidc",
            target_type="oidc_rp",
            target_id=result["id"],
            payload={"client_id": result.get("client_id", "")},
        )
    except Exception as e:
        wiz.response.status(400, message=str(e))
    wiz.response.status(200, data=struct.registry.public_view(result))


def delete():
    item_id = wiz.request.query("id", True)
    try:
        struct.registry.delete(item_id)
    except Exception as e:
        wiz.response.status(400, message=str(e))
    wiz.response.status(200, message="deleted")


def extend_validity():
    _require_admin()
    item_id = wiz.request.query("id", True)
    ttl_hours = int(wiz.request.query("ttl_hours", 24))
    try:
        result = struct.registry.extend_validity(item_id, ttl_hours=ttl_hours)
        struct.core.audit.log(
            "oidc_rp.extend",
            protocol="oidc",
            target_type="oidc_rp",
            target_id=result["id"],
            payload={"client_id": result.get("client_id", ""), "ttl_hours": ttl_hours},
        )
    except Exception as e:
        wiz.response.status(400, message=str(e))
    wiz.response.status(200, data=result)


def set_unlimited():
    _require_admin()
    item_id = wiz.request.query("id", True)
    try:
        result = struct.registry.set_unlimited(item_id)
        struct.core.audit.log(
            "oidc_rp.set_unlimited",
            protocol="oidc",
            target_type="oidc_rp",
            target_id=result["id"],
            payload={"client_id": result.get("client_id", "")},
        )
    except Exception as e:
        wiz.response.status(400, message=str(e))
    wiz.response.status(200, data=result)
