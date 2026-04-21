core = wiz.model("portal/idpcore/struct")
struct = wiz.model("portal/oidcidp/struct")


def _sanitize_user(user):
    if user is None:
        return None
    item = dict(user)
    item.pop("password_hash", None)
    return item


def bootstrap():
    users = [_sanitize_user(user) for user in core.user.list_active()]
    presets = core.attribute_preset.list(protocol="oidc")
    wiz.response.status(200, data={
        "clients": struct.registry.list(),
        "users": users,
        "presets": presets,
        "provider": struct.provider.info(),
        "history": struct.preview.history("authorize"),
        "options": struct.preview.authorize_options(),
    })


def history():
    wiz.response.status(200, data=struct.preview.history("authorize"))


def simulate():
    params = {
        "client_id": wiz.request.query("client_id", True),
        "user_id": wiz.request.query("user_id", True),
        "redirect_uri": wiz.request.query("redirect_uri", ""),
        "response_type": wiz.request.query("response_type", "code"),
        "response_mode": wiz.request.query("response_mode", ""),
        "scope": wiz.request.query("scope", "openid"),
        "state": wiz.request.query("state", ""),
        "nonce": wiz.request.query("nonce", ""),
        "prompt": wiz.request.query("prompt", ""),
        "max_age": wiz.request.query("max_age", ""),
        "acr_values": wiz.request.query("acr_values", ""),
        "code_challenge": wiz.request.query("code_challenge", ""),
        "code_challenge_method": wiz.request.query("code_challenge_method", "S256"),
        "code_verifier": wiz.request.query("code_verifier", ""),
        "error_mode": wiz.request.query("error_mode", ""),
        "claims": wiz.request.query("claims", "{}"),
        "preset_id": wiz.request.query("preset_id", ""),
    }
    try:
        if params["response_type"] == "code" and params["error_mode"] == "":
            result = struct.flow.simulate_authorization_code_flow(params)
        else:
            result = struct.preview.simulate_authorize(params)
    except Exception as e:
        message = getattr(e, "description", str(e))
        wiz.response.status(400, message=message)
    wiz.response.status(200, data=result)