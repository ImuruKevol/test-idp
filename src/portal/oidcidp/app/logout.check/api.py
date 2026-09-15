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
    wiz.response.status(200, data={
        "clients": [struct.registry.public_view(item) for item in struct.registry.list()],
        "users": users,
        "provider": struct.provider.info(),
        "history": struct.preview.history("logout"),
    })


def history():
    wiz.response.status(200, data=struct.preview.history("logout"))


def simulate():
    params = {
        "client_id": wiz.request.query("client_id", True),
        "user_id": wiz.request.query("user_id", ""),
        "post_logout_redirect_uri": wiz.request.query("post_logout_redirect_uri", ""),
        "id_token_hint": wiz.request.query("id_token_hint", ""),
        "logout_hint": wiz.request.query("logout_hint", ""),
        "state": wiz.request.query("state", ""),
        "ui_locales": wiz.request.query("ui_locales", ""),
        "local_session_clear": wiz.request.query("local_session_clear", "true"),
    }
    try:
        result = struct.preview.simulate_logout(params)
    except Exception as e:
        wiz.response.status(400, message=str(e))
    wiz.response.status(200, data=result)
