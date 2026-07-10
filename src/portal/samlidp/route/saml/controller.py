import html
import json
import re

struct = wiz.model("portal/samlidp/struct")
rate_limiter = wiz.model("portal/idpcore/struct/rate_limiter")

AUTHN_CONTEXT_OPTIONS = [
    ("REFEDS MFA", "https://refeds.org/profile/mfa"),
    ("REFEDS SFA", "https://refeds.org/profile/sfa"),
    ("PasswordProtectedTransport", "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"),
]

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

def _serialize_sp(row):
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

def _find_active_user(user_id="", username="", email=""):
    try:
        rows = struct.core.user.list_active()
    except Exception:
        rows = []
    for row in rows:
        if user_id and row.get("id") == user_id:
            return row
        if username and row.get("username") == username:
            return row
        if email and row.get("email") == email:
            return row
    return None

def _is_admin_account(user):
    if not user:
        return False
    role = str(user.get("role", "")).strip().lower()
    username = str(user.get("username", "")).strip().lower()
    return role == "admin" or username == "admin"

def _session_sso_user():
    session_user_id = struct.session.get("id", "")
    if session_user_id:
        user = _find_active_user(user_id=session_user_id)
        if user is not None:
            return user

    session_username = str(struct.session.get("username", "")).strip()
    if session_username:
        user = _find_active_user(username=session_username)
        if user is not None:
            return user

    session_email = str(struct.session.get("email", "")).strip()
    if session_email:
        user = _find_active_user(email=session_email)
        if user is not None:
            return user

    return None

def _set_session_user(user):
    struct.session.set(
        id=user["id"],
        username=user.get("username", ""),
        email=user.get("email", ""),
        name=user.get("display_name", user.get("username", "")),
        role=user.get("role", "tester"),
    )

def _request_authn_context_class_ref():
    return (
        str(wiz.request.query("authn_context_class_ref", "") or "").strip()
        or str(wiz.request.query("AuthnContextClassRef", "") or "").strip()
        or str(wiz.request.query("acr_values", "") or "").strip()
    )

def _first_authn_context_class_ref(value):
    if value is None:
        return ""
    if isinstance(value, str):
        source = value.strip()
        if source == "":
            return ""
        try:
            if source.startswith("["):
                return _first_authn_context_class_ref(json.loads(source))
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

def _resolve_sso_request_state():
    default_nameid = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    state = {
        "transaction_id": wiz.request.query("transaction_id", ""),
        "sp_entity_id": wiz.request.query("sp_entity_id", ""),
        "acs_url": wiz.request.query("acs_url", ""),
        "request_id": wiz.request.query("request_id", ""),
        "relay_state": wiz.request.query("relay_state", ""),
        "nameid_format": wiz.request.query("nameid_format", default_nameid) or default_nameid,
        "preset_id": _default_sso_preset_id(),
        "sign_response": wiz.request.query("sign_response", "true") == "true",
        "sign_assertion": wiz.request.query("sign_assertion", "true") == "true",
        "session_index": wiz.request.query("session_index", ""),
        "authn_context_class_ref": _request_authn_context_class_ref(),
    }

    if any([state["transaction_id"], state["sp_entity_id"], state["acs_url"], state["request_id"]]):
        if state["transaction_id"]:
            tx = struct.process.get_transaction(state["transaction_id"])
            if tx:
                if not state["sp_entity_id"]:
                    state["sp_entity_id"] = tx.get("sp_entity_id", "")
                if not state["request_id"]:
                    state["request_id"] = tx.get("request_id", "")
                if not state["relay_state"]:
                    state["relay_state"] = tx.get("relay_state", "")
                if state["nameid_format"] == default_nameid:
                    requested_nameid = tx.get("nameid_format_requested", "")
                    if requested_nameid:
                        state["nameid_format"] = requested_nameid
                if not state["authn_context_class_ref"]:
                    state["authn_context_class_ref"] = _first_authn_context_class_ref(tx.get("authn_context_requested", []))
        return state

    method = wiz.request.method()
    saml_request = wiz.request.query("SAMLRequest", "")
    relay_state = wiz.request.query("RelayState", "")
    if not saml_request:
        raise Exception("SAMLRequest 파라미터가 필요합니다.")

    binding = "Redirect" if method == "GET" else "POST"
    parsed = struct.process.parse_authn_request(saml_request, relay_state=relay_state, binding=binding)
    state["transaction_id"] = parsed.get("transaction_id", "")
    state["sp_entity_id"] = parsed.get("issuer", "")
    state["acs_url"] = parsed.get("acs_url", "")
    state["request_id"] = parsed.get("request_id", "")
    state["relay_state"] = parsed.get("relay_state", "")
    state["nameid_format"] = parsed.get("nameid_format", default_nameid) or default_nameid
    if not state["authn_context_class_ref"]:
        state["authn_context_class_ref"] = _first_authn_context_class_ref(parsed.get("authn_context", []))
    return state

def _resolve_login_user():
    selected_user_id = str(wiz.request.query("selected_user_id", "")).strip()
    if selected_user_id:
        user = _find_active_user(user_id=selected_user_id)
        if user is None:
            raise Exception("선택한 테스트 사용자를 찾을 수 없습니다.")
        if _is_admin_account(user):
            raise Exception("admin 계정은 목록에서 바로 선택할 수 없습니다. 관리자 로그인 폼을 사용해주세요.")
        _set_session_user(user)
        return user

    login_id = str(wiz.request.query("login_id", "")).strip()
    password = wiz.request.query("password", "")
    if login_id or password:
        if not rate_limiter.check(f"sso-login:{_client_ip()}", max_requests=10, window_seconds=300):
            raise Exception("로그인 시도가 너무 많습니다. 잠시 후 다시 시도해주세요.")
        if not login_id or not password:
            raise Exception("사용자명 또는 이메일과 비밀번호를 모두 입력해주세요.")

        user = _find_active_user(username=login_id)
        if user is None:
            user = _find_active_user(email=login_id)
        if user is None:
            raise Exception("사용자명 또는 이메일을 찾을 수 없습니다.")
        if user.get("role") != "admin":
            raise Exception("관리자 계정만 비밀번호 로그인할 수 있습니다.")

        authenticated = struct.core.user.authenticate(user.get("username", ""), password)
        if authenticated is None:
            raise Exception("사용자명 또는 이메일과 비밀번호가 올바르지 않습니다.")

        _set_session_user(authenticated)
        return authenticated

    return _session_sso_user()

def _hidden_sso_inputs(state, extra=None, exclude=None):
    payload = dict(state)
    if extra:
        payload.update(extra)
    exclude = set(exclude or [])
    lines = []
    for key, value in payload.items():
        if key in exclude:
            continue
        if value is None:
            value = ""
        if isinstance(value, bool):
            value = "true" if value else "false"
        lines.append(
            f'<input type="hidden" name="{html.escape(str(key), quote=True)}" value="{html.escape(str(value), quote=True)}"/>'
        )
    return "\n        ".join(lines)

def _authn_context_options_html():
    options = []
    for label, value in AUTHN_CONTEXT_OPTIONS:
        options.append(f'<option value="{html.escape(value, quote=True)}">{html.escape(label)}</option>')
    return '<datalist id="authn-context-options">' + "".join(options) + "</datalist>"

def _authn_context_field_html(state, field_id):
    selected = str(state.get("authn_context_class_ref", "") or "").strip()
    buttons = []
    for label, value in AUTHN_CONTEXT_OPTIONS:
        active_class = " active" if selected == value else ""
        buttons.append(f"""
            <button type=\"button\" class=\"preset-button{active_class}\" data-authn-context=\"{html.escape(value, quote=True)}\" onclick=\"this.closest('form').querySelector('[name=authn_context_class_ref]').value=this.dataset.authnContext\">
                {html.escape(label)}
            </button>
        """)
    return f"""
        <div class=\"authn-context-box\">
            <div class=\"field\">
                <label for=\"{html.escape(field_id, quote=True)}\">AuthnContextClassRef</label>
                <input id=\"{html.escape(field_id, quote=True)}\" name=\"authn_context_class_ref\" type=\"text\" value=\"{html.escape(selected, quote=True)}\" placeholder=\"https://refeds.org/profile/mfa\" list=\"authn-context-options\" autocomplete=\"off\"/>
            </div>
            <div class=\"preset-row\">{''.join(buttons)}</div>
        </div>
    """

def _build_sso_prompt_html(state, error_message=""):
    try:
        users = struct.core.user.list_active()
    except Exception:
        users = []

    account_buttons = []
    for user in users:
        if _is_admin_account(user):
            continue
        display_name = str(user.get("display_name", user.get("username", ""))).strip() or str(user.get("username", "")).strip()
        username = str(user.get("username", "")).strip()
        email_value = str(user.get("email", "")).strip()
        role = str(user.get("role", "tester")).strip() or "tester"
        account_buttons.append(f"""
            <button type=\"submit\" name=\"selected_user_id\" value=\"{html.escape(str(user.get("id", "")), quote=True)}\" class=\"account-button\">
                <span class=\"account-name\">{html.escape(display_name)}</span>
                <span class=\"account-meta\">{html.escape(username)}{(' · ' + html.escape(email_value)) if email_value else ''}</span>
                <span class=\"account-role\">{html.escape(role)}</span>
            </button>
        """)

    error_block = ""
    if error_message:
        error_block = f'<div class="notice error">{html.escape(error_message)}</div>'

    empty_block = ""
    if len(account_buttons) == 0:
        empty_block = '<div class="notice">선택 가능한 활성 테스트 계정이 없습니다. 아래 폼으로 로그인하세요.</div>'

    service_label = str(state.get("sp_entity_id", "")).strip() or "알 수 없는 서비스"
    acs_label = str(state.get("acs_url", "")).strip() or "등록된 ACS에서 확인"
    request_label = str(state.get("request_id", "")).strip() or "미지정"

    return f"""<!DOCTYPE html>
<html lang=\"ko\">
<head>
    <meta charset=\"utf-8\"/>
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>
    <meta name=\"robots\" content=\"noindex,nofollow\"/>
    <title>Test IdP Sign In</title>
    <style>
        :root {{
            color-scheme: light;
            --bg-1: #f7efe6;
            --bg-2: #fffdf9;
            --ink: #1f1b16;
            --muted: #6c6257;
            --line: rgba(84, 63, 36, 0.12);
            --brand: #bb5a27;
            --brand-deep: #8c3f17;
            --panel: rgba(255, 255, 255, 0.88);
            --warn: #a33b22;
            --shadow: 0 24px 60px rgba(75, 42, 19, 0.12);
        }}
        * {{ box-sizing: border-box; }}
        body {{
            margin: 0;
            min-height: 100vh;
            font-family: "Segoe UI", "Noto Sans KR", sans-serif;
            color: var(--ink);
            background:
                radial-gradient(circle at top left, rgba(255, 222, 180, 0.72), transparent 32%),
                radial-gradient(circle at bottom right, rgba(235, 152, 102, 0.22), transparent 28%),
                linear-gradient(180deg, var(--bg-1), var(--bg-2));
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }}
        .shell {{
            width: 100%;
            max-width: 1040px;
            display: grid;
            grid-template-columns: minmax(0, 1.05fr) minmax(320px, 0.95fr);
            gap: 20px;
        }}
        .panel {{
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 28px;
            box-shadow: var(--shadow);
            backdrop-filter: blur(12px);
        }}
        .hero {{ padding: 32px; }}
        .auth {{ padding: 24px; }}
        .eyebrow {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 12px;
            border-radius: 999px;
            background: rgba(187, 90, 39, 0.12);
            color: var(--brand-deep);
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.06em;
            text-transform: uppercase;
        }}
        h1 {{
            margin: 18px 0 10px;
            font-size: clamp(30px, 4vw, 46px);
            line-height: 1.02;
        }}
        p {{ margin: 0; }}
        .lead {{ color: var(--muted); font-size: 15px; line-height: 1.65; max-width: 52ch; }}
        .request-box {{
            margin-top: 24px;
            display: grid;
            gap: 12px;
            padding: 18px;
            border-radius: 22px;
            background: rgba(255,255,255,0.82);
            border: 1px solid rgba(84, 63, 36, 0.08);
        }}
        .request-row {{ display: grid; gap: 4px; }}
        .request-label {{ font-size: 11px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: var(--muted); }}
        .request-value {{ font-size: 14px; line-height: 1.45; word-break: break-all; }}
        .auth-grid {{ display: grid; gap: 16px; }}
        .notice {{
            border-radius: 16px;
            padding: 13px 14px;
            font-size: 13px;
            background: rgba(84, 63, 36, 0.06);
            color: var(--muted);
        }}
        .notice.error {{ background: rgba(163, 59, 34, 0.12); color: var(--warn); }}
        .section-title {{ font-size: 12px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: var(--muted); }}
        .account-list {{ display: grid; gap: 10px; }}
        .account-button {{
            width: 100%;
            border: 1px solid rgba(84, 63, 36, 0.09);
            background: #fff;
            border-radius: 18px;
            padding: 16px;
            text-align: left;
            cursor: pointer;
            transition: transform 120ms ease, border-color 120ms ease, box-shadow 120ms ease;
        }}
        .account-button:hover {{ transform: translateY(-1px); border-color: rgba(187, 90, 39, 0.38); box-shadow: 0 14px 28px rgba(75, 42, 19, 0.08); }}
        .account-name {{ display: block; font-size: 16px; font-weight: 700; color: var(--ink); }}
        .account-meta {{ display: block; margin-top: 4px; font-size: 13px; color: var(--muted); }}
        .account-role {{ display: inline-block; margin-top: 10px; padding: 5px 10px; border-radius: 999px; background: rgba(187, 90, 39, 0.1); color: var(--brand-deep); font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; }}
        .divider {{ display: flex; align-items: center; gap: 10px; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }}
        .divider::before, .divider::after {{ content: \"\"; height: 1px; flex: 1; background: rgba(84, 63, 36, 0.12); }}
        .field {{ display: grid; gap: 6px; }}
        .field label {{ font-size: 13px; font-weight: 600; color: var(--ink); }}
        .field input {{
            width: 100%;
            border-radius: 14px;
            border: 1px solid rgba(84, 63, 36, 0.16);
            padding: 12px 14px;
            font-size: 14px;
            background: #fff;
        }}
        .field input:focus {{ outline: 2px solid rgba(187, 90, 39, 0.18); border-color: rgba(187, 90, 39, 0.42); }}
        .authn-context-box {{
            display: grid;
            gap: 10px;
            padding: 14px;
            border-radius: 18px;
            border: 1px solid rgba(187, 90, 39, 0.18);
            background: rgba(187, 90, 39, 0.06);
        }}
        .preset-row {{ display: flex; flex-wrap: wrap; gap: 8px; }}
        .preset-button {{
            border: 1px solid rgba(187, 90, 39, 0.18);
            border-radius: 999px;
            background: #fff;
            color: var(--brand-deep);
            padding: 7px 10px;
            font-size: 12px;
            font-weight: 700;
            cursor: pointer;
        }}
        .preset-button.active {{ background: rgba(187, 90, 39, 0.14); border-color: rgba(187, 90, 39, 0.42); }}
        .submit {{
            width: 100%;
            border: 0;
            border-radius: 16px;
            padding: 13px 16px;
            font-size: 14px;
            font-weight: 700;
            color: #fff;
            background: linear-gradient(135deg, var(--brand), var(--brand-deep));
            cursor: pointer;
        }}
        .hint {{ font-size: 12px; color: var(--muted); line-height: 1.5; }}
        @media (max-width: 860px) {{
            .shell {{ grid-template-columns: 1fr; }}
            .hero, .auth {{ padding: 22px; }}
        }}
    </style>
</head>
<body>
    <div class=\"shell\">
        <section class=\"panel hero\">
            <div class=\"eyebrow\">SAML Sign In</div>
            <h1>서비스가 인증을 요청했습니다.</h1>
            <p class=\"lead\">테스트 IdP가 로그인 또는 계정 선택을 기다리고 있습니다. 아래에서 계정을 고르면 즉시 SAML 응답을 생성해 서비스의 ACS로 돌려보냅니다.</p>
            <div class=\"request-box\">
                <div class=\"request-row\">
                    <span class=\"request-label\">Service Provider</span>
                    <span class=\"request-value\">{html.escape(service_label)}</span>
                </div>
                <div class=\"request-row\">
                    <span class=\"request-label\">Assertion Consumer Service</span>
                    <span class=\"request-value\">{html.escape(acs_label)}</span>
                </div>
                <div class=\"request-row\">
                    <span class=\"request-label\">Request ID</span>
                    <span class=\"request-value\">{html.escape(request_label)}</span>
                </div>
            </div>
        </section>
        <section class=\"panel auth\">
            <div class=\"auth-grid\">
                {error_block}
                <form method=\"post\" action=\"/api/saml/sso\" class=\"auth-grid\">
                    {_hidden_sso_inputs(state, exclude={"authn_context_class_ref"})}
                    {_authn_context_field_html(state, "authn_context_class_ref")}
                    <div class=\"section-title\">빠른 테스트 계정 선택</div>
                    {empty_block}
                    <div class=\"account-list\">{''.join(account_buttons)}</div>
                    <div class=\"divider\">또는</div>
                    <div class=\"field\">
                        <label for=\"login_id\">사용자명 또는 이메일</label>
                        <input id=\"login_id\" name=\"login_id\" type=\"text\" placeholder=\"admin\" autocomplete=\"username\"/>
                    </div>
                    <div class=\"field\">
                        <label for=\"password\">비밀번호</label>
                        <input id=\"password\" name=\"password\" type=\"password\" placeholder=\"••••••••\" autocomplete=\"current-password\"/>
                    </div>
                    <button type=\"submit\" class=\"submit\">로그인 후 계속</button>
                    <p class=\"hint\">관리자 계정으로 로그인하거나, 계정 선택 버튼을 누르면 별도 비밀번호 입력 없이 해당 테스트 사용자로 즉시 로그인할 수 있습니다.</p>
                </form>
                {_authn_context_options_html()}
            </div>
        </section>
    </div>
</body>
</html>
"""

def _default_sso_preset_id():
    preset_id = wiz.request.query("preset_id", "")
    if preset_id:
        return preset_id
    try:
        preset = struct.core.attribute_preset.get(protocol="saml", name="minimal")
    except Exception:
        preset = None
    if preset and preset.get("id"):
        return preset["id"]
    return ""

def _build_sso_post_html(action_url, saml_response, relay_state=""):
    relay_input = ""
    if relay_state:
        relay_input = f'\n            <input type="hidden" name="RelayState" value="{html.escape(relay_state, quote=True)}"/>'
    return f"""<!DOCTYPE html>
<html lang=\"ko\">
<head>
    <meta charset=\"utf-8\"/>
    <meta name=\"robots\" content=\"noindex,nofollow\"/>
    <title>Redirecting</title>
</head>
<body onload=\"document.forms[0].submit()\">
    <form method=\"post\" action=\"{html.escape(action_url, quote=True)}\">
        <input type=\"hidden\" name=\"SAMLResponse\" value=\"{html.escape(saml_response, quote=True)}\"/>{relay_input}
        <noscript>
            <p>SAML 응답을 서비스로 전송할 준비가 되었습니다.</p>
            <button type=\"submit\">계속</button>
        </noscript>
    </form>
</body>
</html>
"""

def _send_html_response(body):
    flask = wiz.response._flask
    resp = flask.Response(body, mimetype="text/html")
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    wiz.response.response(resp)

segment = wiz.request.match("/api/saml/<action>")
action = segment.action if segment else None

# --- IdP Metadata (XML) ---
if action == "metadata":
    xml = struct.metadata.generate_xml()
    flask = wiz.response._flask
    resp = flask.Response(xml, mimetype="application/xml")
    resp.headers["Content-Disposition"] = 'inline; filename="idp-metadata.xml"'
    wiz.response.response(resp)

# --- IdP Info (JSON) ---
if action == "idp-info":
    info = struct.metadata.info()
    wiz.response.status(200, data=info)

# --- SP List ---
if action == "sp-list":
    ip = _client_ip()
    admin = _is_admin()
    rows = struct.registry.list()
    for row in rows:
        _serialize_sp(row)
        row["can_delete"] = struct.registry.can_delete(row, client_ip=ip, is_admin=admin)
    wiz.response.status(200, data=rows)

# --- SP Register (upload/paste XML) ---
if action == "sp-register":
    ip = _client_ip()
    if not rate_limiter.check(f"sp-register:{ip}", max_requests=5, window_seconds=300):
        wiz.response.status(429, message="SP 등록 요청이 너무 많습니다. 잠시 후 다시 시도해주세요.")
    xml_string = wiz.request.query("xml", True)
    try:
        result = struct.registry.register(xml_string, created_by_ip=ip)
    except Exception as e:
        wiz.response.status(400, message=str(e))
    _serialize_sp(result)
    wiz.response.status(200, data=result)

# --- SP Get ---
if action == "sp-get":
    sp_id = wiz.request.query("id", True)
    ip = _client_ip()
    admin = _is_admin()
    try:
        item = struct.registry.get(id=sp_id)
    except Exception as e:
        wiz.response.status(404, message=str(e))
    _serialize_sp(item)
    item["can_delete"] = struct.registry.can_delete(item, client_ip=ip, is_admin=admin)
    wiz.response.status(200, data=item)

# --- SP Delete ---
if action == "sp-delete":
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

# --- SP Cleanup Expired ---
if action == "sp-cleanup-expired":
    deleted_count = struct.registry.cleanup_expired()
    wiz.response.status(200, data={"deleted": deleted_count})

# --- SP Metadata Raw Download ---
if action == "sp-metadata-raw":
    sp_id = wiz.request.query("id", True)
    try:
        item = struct.registry.get(id=sp_id)
    except Exception as e:
        wiz.response.status(404, message=str(e))
    raw_path = item.get("raw_metadata_path", "")
    if not raw_path:
        wiz.response.status(404, message="Raw metadata not found")
    fs = wiz.project.fs("metadata", "saml", "sp")
    if not fs.exists(raw_path):
        wiz.response.status(404, message="Raw metadata file not found")
    xml = fs.read(raw_path)
    flask = wiz.response._flask
    resp = flask.Response(xml, mimetype="application/xml")
    safe_filename = re.sub(r'[^\w\-.]', '_', raw_path.split('/')[-1])
    resp.headers["Content-Disposition"] = f'attachment; filename="{safe_filename}"'
    wiz.response.response(resp)

# --- SSO: Parse AuthnRequest ---
if action == "sso-parse":
    ip = _client_ip()
    if not rate_limiter.check(f"sso-parse:{ip}", max_requests=30, window_seconds=60):
        wiz.response.status(429, message="요청이 너무 많습니다. 잠시 후 다시 시도해주세요.")
    saml_request = wiz.request.query("SAMLRequest", True)
    relay_state = wiz.request.query("RelayState", "")
    binding = wiz.request.query("binding", "POST")
    try:
        result = struct.process.parse_authn_request(saml_request, relay_state=relay_state, binding=binding)
    except Exception as e:
        wiz.response.status(400, message=str(e))
    wiz.response.status(200, data=result)

# --- SSO: Build Response ---
if action == "sso-respond":
    params = dict()
    params["transaction_id"] = wiz.request.query("transaction_id", "")
    params["user_id"] = wiz.request.query("user_id", True)
    params["sp_entity_id"] = wiz.request.query("sp_entity_id", True)
    params["acs_url"] = wiz.request.query("acs_url", True)
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
    params["authn_context_class_ref"] = _request_authn_context_class_ref()

    try:
        result = struct.process.build_response(params)
    except Exception as e:
        wiz.response.status(400, message=str(e))
    wiz.response.status(200, data=result)

# --- SSO: Actual endpoint for SP-initiated SSO (receives AuthnRequest from SP) ---
if action == "sso":
    ip = _client_ip()
    if not rate_limiter.check(f"sso:{ip}", max_requests=30, window_seconds=60):
        wiz.response.status(429, message="요청이 너무 많습니다. 잠시 후 다시 시도해주세요.")

    try:
        state = _resolve_sso_request_state()
    except Exception as e:
        wiz.response.status(400, message=str(e))

    try:
        user = _resolve_login_user()
    except Exception as e:
        prompt_html = _build_sso_prompt_html(state, error_message=str(e))
        _send_html_response(prompt_html)

    if user is None:
        prompt_html = _build_sso_prompt_html(state)
        _send_html_response(prompt_html)

    try:
        result = struct.process.build_response({
            "transaction_id": state.get("transaction_id", ""),
            "user_id": user["id"],
            "sp_entity_id": state.get("sp_entity_id", ""),
            "acs_url": state.get("acs_url", ""),
            "request_id": state.get("request_id", ""),
            "relay_state": state.get("relay_state", ""),
            "nameid_format": state.get("nameid_format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
            "preset_id": state.get("preset_id", ""),
            "sign_response": state.get("sign_response", True),
            "sign_assertion": state.get("sign_assertion", True),
            "session_index": state.get("session_index", ""),
            "authn_context_class_ref": state.get("authn_context_class_ref", ""),
        })
    except Exception as e:
        wiz.response.status(400, message=str(e))
    html_doc = _build_sso_post_html(result["acs_url"], result["response_b64"], result.get("relay_state", ""))
    _send_html_response(html_doc)

# --- Debug Raw File ---
if action == "debug-raw":
    key = wiz.request.query("key", True)
    try:
        xml = struct.process.get_debug_raw(key)
    except Exception as e:
        wiz.response.status(404, message=str(e))
    flask = wiz.response._flask
    resp = flask.Response(xml, mimetype="application/xml")
    wiz.response.response(resp)

# --- Transaction List ---
if action == "transactions":
    sp_entity_id = wiz.request.query("sp_entity_id", "")
    status = wiz.request.query("status", "")
    rows = struct.process.list_transactions(sp_entity_id=sp_entity_id, status=status)
    wiz.response.status(200, data=rows)

# --- Transaction Get ---
if action == "transaction":
    tx_id = wiz.request.query("id", True)
    item = struct.process.get_transaction(tx_id)
    if not item:
        wiz.response.status(404, message="Transaction not found")
    wiz.response.status(200, data=item)

# --- SLO: Actual endpoint for SP-initiated SLO (receives LogoutRequest from SP) ---
if action == "slo":
    method = wiz.request.method()
    saml_request = wiz.request.query("SAMLRequest", "")
    relay_state = wiz.request.query("RelayState", "")

    if not saml_request:
        wiz.response.status(400, message="SAMLRequest 파라미터가 필요합니다.")

    binding = "Redirect" if method == "GET" else "POST"
    try:
        parsed = struct.process.parse_logout_request(saml_request, relay_state=relay_state, binding=binding)
    except Exception as e:
        wiz.response.status(400, message=str(e))

    matched = parsed.get("matched_sessions", [])
    session_ids = [s["id"] for s in matched if s.get("id")]
    if session_ids:
        struct.process.invalidate_sessions(session_ids)

    sp_entity_id = parsed.get("issuer", "")
    slo_destination = ""
    try:
        sp = struct.registry.get(entity_id=sp_entity_id)
        slo_urls = sp.get("slo_url", "[]")
        if isinstance(slo_urls, str):
            slo_urls = json.loads(slo_urls)
        for ep in slo_urls:
            if ep.get("location"):
                slo_destination = ep["location"]
                break
    except Exception:
        pass

    resp_params = {
        "request_id": parsed.get("request_id", ""),
        "sp_entity_id": sp_entity_id,
        "destination": slo_destination,
        "relay_state": relay_state,
        "status_code": "urn:oasis:names:tc:SAML:2.0:status:Success",
        "sign": True,
    }
    try:
        result = struct.process.build_logout_response(resp_params)
    except Exception as e:
        wiz.response.status(500, message=str(e))

    result["parsed_request"] = parsed
    result["invalidated_sessions"] = session_ids
    wiz.response.status(200, data=result)

# --- SLO: Parse LogoutRequest (debug) ---
if action == "slo-parse":
    ip = _client_ip()
    if not rate_limiter.check(f"slo-parse:{ip}", max_requests=30, window_seconds=60):
        wiz.response.status(429, message="요청이 너무 많습니다. 잠시 후 다시 시도해주세요.")
    saml_request = wiz.request.query("SAMLRequest", True)
    relay_state = wiz.request.query("RelayState", "")
    binding = wiz.request.query("binding", "POST")
    try:
        result = struct.process.parse_logout_request(saml_request, relay_state=relay_state, binding=binding)
    except Exception as e:
        wiz.response.status(400, message=str(e))
    wiz.response.status(200, data=result)

# --- SLO: Build LogoutResponse (debug) ---
if action == "slo-respond":
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
                invalidate_ids = json.loads(invalidate_ids)
            except Exception:
                invalidate_ids = [x.strip() for x in invalidate_ids.split(",") if x.strip()]
        struct.process.invalidate_sessions(invalidate_ids)

    try:
        result = struct.process.build_logout_response(params)
    except Exception as e:
        wiz.response.status(400, message=str(e))
    wiz.response.status(200, data=result)

# --- SLO: Build IdP-initiated LogoutRequest ---
if action == "slo-initiate":
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

# --- SLO: Active Sessions ---
if action == "slo-sessions":
    sp_entity_id = wiz.request.query("sp_entity_id", "")
    rows = struct.process.list_active_sessions(sp_entity_id=sp_entity_id)
    wiz.response.status(200, data=rows)

# --- SLO: Invalidate Sessions ---
if action == "slo-invalidate":
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

wiz.response.status(404, message="Unknown action")
