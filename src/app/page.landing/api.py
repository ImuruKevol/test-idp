session = wiz.model("portal/season/session").use()
core = wiz.model("portal/idpcore/struct")
saml = wiz.model("portal/samlidp/struct")
oidc = wiz.model("portal/oidcidp/struct")


def _require_admin():
    if session.get("role") != "admin":
        wiz.response.status(403, message="admin 권한이 필요합니다.")


def _current_admin():
    user_id = session.get("id", "")
    if user_id:
        user = core.user.get(id=user_id)
        if user is not None:
            return user
    username = session.get("username", "")
    if username:
        return core.user.get(username=username)
    return None


def load():
    try:
        core.seed(force=False)
        info = core.info()
        temporary_all = core.user.list_temporary(include_expired=True)
        saml_rows = saml.registry.list()
        oidc_rows = oidc.registry.list()
        temp_count = len([item for item in temporary_all if not core.user.is_expired(item)])
        info["counts"]["temporary_active"] = temp_count
        info["counts"]["temporary_expired"] = len([item for item in temporary_all if core.user.is_expired(item)])
        info["counts"]["saml_sp"] = len(saml_rows)
        info["counts"]["saml_expired"] = len([item for item in saml_rows if saml.registry.is_expired(item)])
        info["counts"]["oidc_rp"] = len(oidc_rows)
        info["counts"]["oidc_expired"] = len([item for item in oidc_rows if oidc.registry.is_expired(item)])
        info["default_accounts"] = [
            {
                "username": item.get("username", ""),
                "password": item.get("password", ""),
                "display_name": item.get("display_name", ""),
                "role": item.get("role", "tester"),
                "email": item.get("email", ""),
            }
            for item in core.user.sample_accounts()
            if item.get("username") != "admin"
        ]
    except Exception as e:
        wiz.response.status(500, message=str(e))
    wiz.response.status(200, data=info)


def change_password():
    _require_admin()
    current_password = wiz.request.query("current_password", True)
    new_password = wiz.request.query("new_password", True)
    confirm_password = wiz.request.query("confirm_password", True)

    user = _current_admin()
    if user is None:
        wiz.response.status(404, message="admin 계정을 찾을 수 없습니다.")
    if user.get("role") != "admin":
        wiz.response.status(403, message="admin 계정만 비밀번호를 변경할 수 있습니다.")
    if new_password != confirm_password:
        wiz.response.status(400, message="새 비밀번호 확인이 일치하지 않습니다.")
    if len(new_password) < 8:
        wiz.response.status(400, message="새 비밀번호는 8자 이상이어야 합니다.")
    if current_password == new_password:
        wiz.response.status(400, message="현재 비밀번호와 다른 값을 입력해주세요.")

    authenticated = core.user.authenticate(user.get("username", ""), current_password)
    if authenticated is None:
        wiz.response.status(400, message="현재 비밀번호가 올바르지 않습니다.")

    try:
        core.user.update({"password": new_password}, id=user["id"])
        core.audit.log(
            "admin.password.change",
            protocol="common",
            target_type="user",
            target_id=user["id"],
            payload={"username": user.get("username", "")},
        )
    except Exception as e:
        wiz.response.status(400, message=str(e))
    wiz.response.status(200, message="password updated")
