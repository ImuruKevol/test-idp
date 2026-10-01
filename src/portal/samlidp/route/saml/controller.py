import html
import base64
import datetime
import hashlib
import json
import re
import uuid
import zlib
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from lxml import etree

struct = wiz.model("portal/samlidp/struct")
rate_limiter = wiz.model("portal/idpcore/struct/rate_limiter")

AUTHN_CONTEXT_OPTIONS = [
    ("REFEDS MFA", "https://refeds.org/profile/mfa"),
    ("REFEDS SFA", "https://refeds.org/profile/sfa"),
    ("PasswordProtectedTransport", "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"),
]
SAML_SSO_SESSION_TTL_SECONDS = 8 * 3600

def _client_ip():
    try:
        return wiz.request.ip()
    except Exception:
        return "unknown"

def _raw_query_string():
    try:
        return wiz.request._flask.request.query_string.decode("ascii")
    except Exception:
        return ""

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
        user = struct.core.user.get(
            id=user_id or None,
            username=username or None,
            email=email or None,
        )
    except Exception:
        return None
    if user is None or struct.core.user.is_expired(user):
        return None
    return user

def _is_admin_account(user):
    if not user:
        return False
    role = str(user.get("role", "")).strip().lower()
    username = str(user.get("username", "")).strip().lower()
    return role == "admin" or username == "admin"

def _session_sso_user():
    if struct.session.is_expired("saml_auth_time", SAML_SSO_SESSION_TTL_SECONDS):
        struct.session.clear()
        return None

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
        saml_session_index=f"_sidx_{uuid.uuid4().hex[:20]}",
        saml_auth_time=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )

def _request_authn_context_class_ref():
    return (
        str(wiz.request.query("authn_context_class_ref", "") or "").strip()
        or str(wiz.request.query("AuthnContextClassRef", "") or "").strip()
        or str(wiz.request.query("acr_values", "") or "").strip()
    )

def _strict_query_bool(name, default):
    raw = str(wiz.request.query(name, "true" if default else "false") or "").strip().lower()
    if raw not in ("true", "false"):
        raise ValueError(f"{name}은 true 또는 false여야 합니다.")
    return raw == "true"

def _strict_query_string_list(name):
    raw = wiz.request.query(name, "")
    if raw in (None, ""):
        return []
    if isinstance(raw, (list, tuple)):
        return list(raw)
    try:
        value = json.loads(str(raw))
    except Exception:
        raise ValueError(f"{name}은 JSON 문자열 배열이어야 합니다.")
    if not isinstance(value, list):
        raise ValueError(f"{name}은 JSON 문자열 배열이어야 합니다.")
    return value

def _strict_query_attribute_values(name):
    raw = wiz.request.query(name, "")
    if raw in (None, ""):
        return {}
    if isinstance(raw, dict):
        return raw
    try:
        value = json.loads(str(raw))
    except Exception:
        raise ValueError(f"{name}은 JSON 객체여야 합니다.")
    if not isinstance(value, dict):
        raise ValueError(f"{name}은 JSON 객체여야 합니다.")
    return value

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
    reviewops_profile = struct.metadata.reviewops_profile(wiz.request.query("reviewops_profile", ""))
    response_defaults = struct.metadata.response_defaults(reviewops_profile)
    sign_response_value = str(wiz.request.query("sign_response", "") or "").strip().lower()
    sign_assertion_value = str(wiz.request.query("sign_assertion", "") or "").strip().lower()
    if sign_response_value not in ("", "true", "false"):
        raise ValueError("sign_response은 true 또는 false여야 합니다.")
    if sign_assertion_value not in ("", "true", "false"):
        raise ValueError("sign_assertion은 true 또는 false여야 합니다.")
    state = {
        "transaction_id": wiz.request.query("transaction_id", ""),
        "sp_entity_id": wiz.request.query("sp_entity_id", ""),
        "acs_url": wiz.request.query("acs_url", ""),
        "request_id": wiz.request.query("request_id", ""),
        "relay_state": wiz.request.query("relay_state", ""),
        "nameid_format": wiz.request.query("nameid_format", default_nameid) or default_nameid,
        "preset_id": _default_sso_preset_id(),
        "sign_response": response_defaults["sign_response"] if sign_response_value == "" else sign_response_value == "true",
        "sign_assertion": response_defaults["sign_assertion"] if sign_assertion_value == "" else sign_assertion_value == "true",
        "omit_attributes": response_defaults["omit_attributes"],
        "attribute_values": response_defaults["attribute_values"],
        "encrypt_assertion": response_defaults.get("encrypt_assertion", False),
        "content_encryption_algorithm": response_defaults.get("content_encryption_algorithm", "aes256-gcm"),
        "key_transport_algorithm": response_defaults.get("key_transport_algorithm", "rsa-oaep-sha256"),
        "response_variant": response_defaults.get("response_variant", "standard"),
        "time_offset_seconds": response_defaults.get("time_offset_seconds", 0),
        "assertion_ttl_seconds": response_defaults.get("assertion_ttl_seconds", 300),
        "session_index": wiz.request.query("session_index", ""),
        "authn_context_class_ref": _request_authn_context_class_ref(),
        "authn_context_comparison": "exact",
        "authn_context_requested": [],
        "authn_instant": str(struct.session.get("saml_auth_time", "") or ""),
        "force_authn": str(wiz.request.query("force_authn", "false") or "false"),
        "is_passive": str(wiz.request.query("is_passive", "false") or "false"),
    }
    if not state["session_index"]:
        state["session_index"] = str(struct.session.get("saml_session_index", "") or "")
    if not state["session_index"] and _session_sso_user() is not None:
        state["session_index"] = f"_sidx_{uuid.uuid4().hex[:20]}"
        state["authn_instant"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        struct.session.set(
            saml_session_index=state["session_index"],
            saml_auth_time=state["authn_instant"],
        )
    if reviewops_profile:
        state["reviewops_profile"] = reviewops_profile

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
                state["authn_context_requested"] = tx.get("authn_context_requested", [])
        return state

    method = wiz.request.method()
    saml_request = wiz.request.query("SAMLRequest", "")
    relay_state = wiz.request.query("RelayState", "")
    if not saml_request:
        raise Exception("SAMLRequest 파라미터가 필요합니다.")

    binding = "Redirect" if method == "GET" else "POST"
    idp_info = struct.metadata.info(reviewops_profile)
    expected_destination = idp_info["sso_redirect" if binding == "Redirect" else "sso_post"]
    parsed = struct.process.parse_authn_request(
        saml_request,
        relay_state=relay_state,
        binding=binding,
        raw_query=_raw_query_string(),
        expected_destination=expected_destination,
    )
    state["transaction_id"] = parsed.get("transaction_id", "")
    state["sp_entity_id"] = parsed.get("issuer", "")
    state["acs_url"] = parsed.get("acs_url", "")
    state["request_id"] = parsed.get("request_id", "")
    state["relay_state"] = parsed.get("relay_state", "")
    state["nameid_format"] = parsed.get("nameid_format", default_nameid) or default_nameid
    state["force_authn"] = parsed.get("force_authn", "false")
    state["is_passive"] = parsed.get("is_passive", "false")
    state["authn_context_comparison"] = parsed.get("requested_authn_context_comparison", "exact") or "exact"
    state["authn_context_requested"] = parsed.get("authn_context", [])
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

def _build_saml_post_html(action_url, parameter_name, parameter_value, relay_state="", title="Redirecting"):
    if len(str(relay_state).encode("utf-8")) > 80:
        raise ValueError("SLO RelayState는 80 bytes를 넘을 수 없습니다.")
    relay_input = ""
    if relay_state:
        relay_input = f'\n            <input type="hidden" name="RelayState" value="{html.escape(relay_state, quote=True)}"/>'
    return f"""<!DOCTYPE html>
<html lang=\"ko\">
<head>
    <meta charset=\"utf-8\"/>
    <meta name=\"robots\" content=\"noindex,nofollow\"/>
    <title>{html.escape(title)}</title>
</head>
<body onload=\"document.forms[0].submit()\">
    <form method=\"post\" action=\"{html.escape(action_url, quote=True)}\">
        <input type=\"hidden\" name=\"{html.escape(parameter_name, quote=True)}\" value=\"{html.escape(parameter_value, quote=True)}\"/>{relay_input}
        <noscript>
            <p>SAML 응답을 서비스로 전송할 준비가 되었습니다.</p>
            <button type=\"submit\">계속</button>
        </noscript>
    </form>
</body>
</html>
"""

def _build_sso_post_html(action_url, saml_response, relay_state=""):
    return _build_saml_post_html(action_url, "SAMLResponse", saml_response, relay_state)

def _build_saml_redirect_url(action_url, parameter_name, xml_payload, relay_state="",
                             signing_key_pem=""):
    if len(str(relay_state).encode("utf-8")) > 80:
        raise ValueError("SLO RelayState는 80 bytes를 넘을 수 없습니다.")
    try:
        root = etree.fromstring(xml_payload.encode("utf-8"))
        signature = root.find("{http://www.w3.org/2000/09/xmldsig#}Signature")
        if signature is not None:
            root.remove(signature)
        xml_payload = etree.tostring(
            root,
            pretty_print=False,
            xml_declaration=True,
            encoding="UTF-8",
        ).decode("utf-8")
    except Exception:
        pass
    compressor = zlib.compressobj(wbits=-15)
    encoded = base64.b64encode(
        compressor.compress(xml_payload.encode("utf-8")) + compressor.flush()
    ).decode("utf-8")
    parsed = urlparse(action_url)
    protocol_query = [(parameter_name, encoded)]
    if relay_state:
        protocol_query.append(("RelayState", relay_state))
    if signing_key_pem:
        # OASIS SAML Bindings 3.4.4.1: Redirect 서명은 XML 내부
        # Signature가 아니라 정확히 SAMLRequest/SAMLResponse,
        # RelayState, SigAlg 순서의 URL-encoded octet string을 서명한다.
        signature_algorithm = (
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        )
        protocol_query.append(("SigAlg", signature_algorithm))
        signing_input = urlencode(protocol_query).encode("ascii")
        key_value = (
            signing_key_pem.encode("utf-8")
            if isinstance(signing_key_pem, str)
            else signing_key_pem
        )
        private_key = serialization.load_pem_private_key(
            key_value,
            password=None,
        )
        signature = private_key.sign(
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        protocol_query.append((
            "Signature",
            base64.b64encode(signature).decode("ascii"),
        ))
    query = list(parse_qsl(parsed.query, keep_blank_values=True))
    query.extend(protocol_query)
    return urlunparse(parsed._replace(query=urlencode(query)))

def _build_slo_result_html(result):
    checks = "".join(
        f'<li data-check="{html.escape(str(key), quote=True)}" data-pass="{str(value).lower()}">{html.escape(str(key))}: {html.escape(str(value))}</li>'
        for key, value in result.items()
        if isinstance(value, bool)
    )
    valid = str(result.get("valid") is True).lower()
    return f"""<!DOCTYPE html>
<html lang="ko"><head><meta charset="utf-8"/><meta name="robots" content="noindex,nofollow"/>
<title>SAML 로그아웃 검증 결과</title></head>
<body data-reviewops-slo-result="{valid}"><main><h1>SAML 로그아웃 검증 결과</h1><ul>{checks}</ul></main></body></html>"""

def _send_html_response(body, status=200):
    flask = wiz.response._flask
    resp = flask.Response(body, mimetype="text/html")
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    wiz.response.set_status(status)
    wiz.response.response(resp)

def _send_metadata_response(xml, filename, cache_seconds=0):
    flask = wiz.response._flask
    etag = hashlib.sha256(xml.encode("utf-8")).hexdigest()
    if_none_match = str(wiz.request.headers("If-None-Match", "") or "").strip()
    etag_candidates = {
        item.strip()[2:].strip() if item.strip().startswith("W/") else item.strip()
        for item in if_none_match.split(",")
        if item.strip()
    }
    if "*" in etag_candidates or etag in etag_candidates or f'"{etag}"' in etag_candidates:
        resp = flask.Response(status=304)
    else:
        resp = flask.Response(xml, mimetype="application/samlmetadata+xml")
        resp.headers["Content-Disposition"] = f'inline; filename="{filename}"'
    resp.set_etag(etag)
    resp.headers["Cache-Control"] = (
        f"public, max-age={int(cache_seconds)}"
        if int(cache_seconds or 0) > 0 else "no-store"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    wiz.response.response(resp)

segment = wiz.request.match("/api/saml/<action>")
action = segment.action if segment else None

# --- ReviewOps profile-specific SAML response defaults ---
if action == "reviewops-profile-config":
    profile = wiz.request.query("reviewops_profile", "")
    if wiz.request.method() == "POST":
        try:
            result = struct.metadata.configure_response_defaults(
                profile,
                sign_response=_strict_query_bool("sign_response", True),
                sign_assertion=_strict_query_bool("sign_assertion", True),
                omit_attributes=_strict_query_string_list("omit_attributes"),
                attribute_values=_strict_query_attribute_values("attribute_values"),
                response_options={
                    "encrypt_assertion": _strict_query_bool("encrypt_assertion", False),
                    "content_encryption_algorithm": wiz.request.query("content_encryption_algorithm", "aes256-gcm"),
                    "key_transport_algorithm": wiz.request.query("key_transport_algorithm", "rsa-oaep-sha256"),
                    "response_variant": wiz.request.query("response_variant", "standard"),
                    "time_offset_seconds": int(wiz.request.query("time_offset_seconds", 0)),
                    "assertion_ttl_seconds": int(wiz.request.query("assertion_ttl_seconds", 300)),
                },
            )
        except ValueError as e:
            wiz.response.status(400, message=str(e))
        wiz.response.status(200, data=result)
    if wiz.request.method() != "GET":
        wiz.response.status(405, message="profile SAML response 기본값은 GET 또는 POST만 허용합니다.")
    try:
        result = struct.metadata.response_defaults(profile)
    except ValueError as e:
        wiz.response.status(400, message=str(e))
    wiz.response.status(200, data=result)

if action == "reviewops-profile-clear":
    if wiz.request.method() != "POST":
        wiz.response.status(405, message="profile SAML response 기본값 초기화는 POST만 허용합니다.")
    try:
        result = struct.metadata.clear_response_defaults(wiz.request.query("reviewops_profile", ""))
    except ValueError as e:
        wiz.response.status(400, message=str(e))
    wiz.response.status(200, data=result)

# --- IdP Metadata (XML) ---
if action == "metadata":
    try:
        xml = struct.metadata.generate_xml()
    except ValueError as e:
        wiz.response.status(400, message=str(e))
    metadata_variant = str(wiz.request.query("metadata_variant", "standard") or "standard")
    lifetime = struct.metadata._metadata_lifetime()
    _send_metadata_response(
        xml,
        "idp-metadata.xml",
        lifetime["cache_seconds"] if metadata_variant == "standard" else 0,
    )

# --- ReviewOps profile-bound federation metadata (XML) ---
if action == "federation-metadata":
    try:
        xml = struct.metadata.generate_federation_xml(
            wiz.request.query("reviewops_profile", ""),
            federation_name=wiz.request.query("federation", ""),
        )
    except ValueError as e:
        wiz.response.status(400, message=str(e))
    metadata_variant = str(wiz.request.query("metadata_variant", "standard") or "standard")
    lifetime = struct.metadata._metadata_lifetime()
    _send_metadata_response(
        xml,
        "idp-federation-metadata.xml",
        lifetime["cache_seconds"] if metadata_variant == "standard" else 0,
    )

if action == "federation-info":
    try:
        info = struct.metadata.federation_info(
            wiz.request.query("reviewops_profile", ""),
            federation_name=wiz.request.query("federation", ""),
        )
    except ValueError as e:
        wiz.response.status(400, message=str(e))
    wiz.response.status(200, data=info)

# --- IdP Info (JSON) ---
if action == "idp-info":
    try:
        info = struct.metadata.info()
    except ValueError as e:
        wiz.response.status(400, message=str(e))
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
    params["reviewops_profile"] = wiz.request.query("reviewops_profile", "")
    if params["reviewops_profile"]:
        response_defaults = struct.metadata.response_defaults(
            params["reviewops_profile"]
        )
        params["omit_attributes"] = response_defaults["omit_attributes"]
        params["attribute_values"] = response_defaults["attribute_values"]
        for key, default in [
            ("encrypt_assertion", False),
            ("content_encryption_algorithm", "aes256-gcm"),
            ("key_transport_algorithm", "rsa-oaep-sha256"),
            ("response_variant", "standard"),
            ("time_offset_seconds", 0),
            ("assertion_ttl_seconds", 300),
        ]:
            params[key] = response_defaults.get(key, default)

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

    force_authn = str(state.get("force_authn", "false")).strip().lower() == "true"
    is_passive = str(state.get("is_passive", "false")).strip().lower() == "true"
    submitted_identity = bool(
        str(wiz.request.query("selected_user_id", "") or "").strip()
        or str(wiz.request.query("login_id", "") or "").strip()
        or str(wiz.request.query("password", "") or "").strip()
    )
    if force_authn and not submitted_identity:
        user = None

    if user is None:
        if is_passive:
            try:
                result = struct.process.build_authn_error_response({
                    "request_id": state.get("request_id", ""),
                    "acs_url": state.get("acs_url", ""),
                    "relay_state": state.get("relay_state", ""),
                    "reviewops_profile": state.get("reviewops_profile", ""),
                })
            except Exception as e:
                wiz.response.status(400, message=str(e))
            html_doc = _build_sso_post_html(
                result["acs_url"],
                result["response_b64"],
                result.get("relay_state", ""),
            )
            _send_html_response(html_doc)
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
            "omit_attributes": state.get("omit_attributes", []),
            "attribute_values": state.get("attribute_values", {}),
            "encrypt_assertion": state.get("encrypt_assertion", False),
            "content_encryption_algorithm": state.get("content_encryption_algorithm", "aes256-gcm"),
            "key_transport_algorithm": state.get("key_transport_algorithm", "rsa-oaep-sha256"),
            "response_variant": state.get("response_variant", "standard"),
            "time_offset_seconds": state.get("time_offset_seconds", 0),
            "assertion_ttl_seconds": state.get("assertion_ttl_seconds", 300),
            "session_index": state.get("session_index", ""),
            "authn_context_class_ref": state.get("authn_context_class_ref", ""),
            "authn_context_comparison": state.get("authn_context_comparison", "exact"),
            "authn_context_requested": state.get("authn_context_requested", []),
            "authn_instant": state.get("authn_instant", ""),
            "reviewops_profile": state.get("reviewops_profile", ""),
        })
    except Exception as e:
        wiz.response.status(400, message=str(e))
    html_doc = _build_sso_post_html(result["acs_url"], result["response_b64"], result.get("relay_state", ""))
    _send_html_response(html_doc)

# --- Debug Raw File ---
if action == "debug-raw":
    if not _is_admin():
        wiz.response.status(403, message="admin 권한이 필요합니다.")
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
    saml_response = wiz.request.query("SAMLResponse", "")
    saml_request = wiz.request.query("SAMLRequest", "")
    relay_state = wiz.request.query("RelayState", "")

    if saml_response:
        expected = struct.session.get("SAML_IDP_LOGOUT_CONTEXT", {})
        if not isinstance(expected, dict):
            expected = {}
        binding = "Redirect" if method == "GET" else "POST"
        redirect_signature_valid = None
        redirect_signature_error = ""
        if binding == "Redirect":
            try:
                raw_query = wiz.request.request().query_string.decode("ascii")
                redirect_signature_valid, redirect_signature_error = struct.process.verify_redirect_query_signature(
                    raw_query,
                    "SAMLResponse",
                    expected.get("sp_entity_id", ""),
                )
            except Exception as e:
                redirect_signature_valid = False
                redirect_signature_error = str(e)
        try:
            result = struct.process.parse_logout_response(
                saml_response,
                relay_state=relay_state,
                binding=binding,
                expected=expected,
                redirect_signature_valid=redirect_signature_valid,
                redirect_signature_error=redirect_signature_error,
            )
        except Exception as e:
            wiz.response.status(400, message=str(e))
        if result.get("valid") is True:
            invalidated = struct.process.invalidate_sessions(expected.get("session_ids", []))
            result["invalidated_sessions"] = invalidated
            struct.session.clear()
            struct.session.set(SAML_IDP_LOGOUT_RESULT=result)
            _send_html_response(_build_slo_result_html(result))
        struct.session.set(SAML_IDP_LOGOUT_RESULT=result)
        _send_html_response(_build_slo_result_html(result), status=400)

    if not saml_request:
        wiz.response.status(400, message="SAMLRequest 파라미터가 필요합니다.")

    binding = "Redirect" if method == "GET" else "POST"
    try:
        reviewops_profile = struct.metadata.reviewops_profile(wiz.request.query("reviewops_profile", ""))
        info = struct.metadata.info(reviewops_profile)
        parsed = struct.process.parse_logout_request(
            saml_request,
            relay_state=relay_state,
            binding=binding,
            raw_query=_raw_query_string(),
            expected_destination=info["slo_redirect" if binding == "Redirect" else "slo_post"],
            allow_unsigned=str(wiz.request.query("allow_unsigned", "false")).lower() == "true",
        )
    except Exception as e:
        wiz.response.status(400, message=str(e))

    matched = parsed.get("matched_sessions", [])
    session_ids = [s["id"] for s in matched if s.get("id")]
    if session_ids:
        struct.process.invalidate_sessions(session_ids)

    sp_entity_id = parsed.get("issuer", "")
    slo_destination = ""
    endpoint_result = {"standards_status": "compatibility", "warnings": []}
    try:
        endpoint_result = struct.process.resolve_slo_endpoint(
            sp_entity_id,
            binding=binding,
            for_response=True,
        )
        slo_destination = endpoint_result.get("url", "")
    except Exception as e:
        endpoint_result["warnings"] = [str(e)]

    resp_params = {
        "request_id": parsed.get("request_id", ""),
        "sp_entity_id": sp_entity_id,
        "destination": slo_destination,
        "relay_state": relay_state,
        "status_code": "urn:oasis:names:tc:SAML:2.0:status:Success",
        "sign": True,
        "reviewops_profile": reviewops_profile,
    }
    try:
        result = struct.process.build_logout_response(resp_params)
    except Exception as e:
        wiz.response.status(500, message=str(e))

    result["parsed_request"] = parsed
    result["invalidated_sessions"] = session_ids
    result["endpoint_status"] = endpoint_result.get("standards_status", "compatibility")
    result["compatibility_warnings"] = endpoint_result.get("warnings", [])
    if str(wiz.request.query("format", "") or "").strip().lower() == "json":
        wiz.response.status(200, data=result)
    if not result.get("destination"):
        wiz.response.status(400, message="등록된 SP SingleLogoutService URL을 찾을 수 없습니다.")
    struct.session.clear()
    if binding == "Redirect":
        wiz.response.redirect(_build_saml_redirect_url(
            result["destination"],
            "SAMLResponse",
            result["response_xml"],
            result.get("relay_state", ""),
            struct.metadata.get_key_pem() if result.get("signed") else "",
        ))
    html_doc = _build_saml_post_html(
        result["destination"],
        "SAMLResponse",
        result["response_b64"],
        result.get("relay_state", ""),
        title="SAML LogoutResponse 전송",
    )
    _send_html_response(html_doc)

# --- SLO: Parse LogoutRequest (debug) ---
if action == "slo-parse":
    ip = _client_ip()
    if not rate_limiter.check(f"slo-parse:{ip}", max_requests=30, window_seconds=60):
        wiz.response.status(429, message="요청이 너무 많습니다. 잠시 후 다시 시도해주세요.")
    saml_request = wiz.request.query("SAMLRequest", True)
    relay_state = wiz.request.query("RelayState", "")
    binding = wiz.request.query("binding", "POST")
    try:
        result = struct.process.parse_logout_request(
            saml_request,
            relay_state=relay_state,
            binding=binding,
            raw_query=_raw_query_string(),
            expected_destination=wiz.request.query("expected_destination", ""),
            allow_unsigned=str(wiz.request.query("allow_unsigned", "false")).lower() == "true",
        )
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
    params["reviewops_profile"] = wiz.request.query("reviewops_profile", "")

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
    params["reviewops_profile"] = wiz.request.query("reviewops_profile", "")
    relay_state = str(wiz.request.query("relay_state", "/") or "/")
    binding = str(wiz.request.query("binding", "POST") or "POST").strip().upper()
    if binding not in ("POST", "REDIRECT"):
        wiz.response.status(400, message="binding은 POST 또는 Redirect여야 합니다.")
    if len(relay_state.encode("utf-8")) > 80:
        wiz.response.status(400, message="SLO RelayState는 80 bytes를 넘을 수 없습니다.")
    params["binding"] = binding

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
    if str(wiz.request.query("deliver", "false") or "false").strip().lower() == "true":
        if not result.get("destination"):
            wiz.response.status(400, message="등록된 SP SingleLogoutService URL을 찾을 수 없습니다.")
        try:
            response_info = struct.metadata.info(params["reviewops_profile"])
            response_destination = response_info[
                "slo_redirect" if binding == "REDIRECT" else "slo_post"
            ]
        except Exception as e:
            wiz.response.status(400, message=str(e))
        matched_sessions = struct.process._match_sessions(
            params["sp_entity_id"],
            params["session_indexes"],
            params["nameid_value"],
        )
        struct.session.set(SAML_IDP_LOGOUT_CONTEXT={
            "request_id": result["request_id"],
            "sp_entity_id": params["sp_entity_id"],
            "relay_state": relay_state,
            "response_destination": response_destination,
            "session_ids": [item.get("id") for item in matched_sessions if item.get("id")],
        })
        if binding == "REDIRECT":
            wiz.response.redirect(_build_saml_redirect_url(
                result["destination"],
                "SAMLRequest",
                result["request_xml"],
                relay_state,
                struct.metadata.get_key_pem() if result.get("signed") else "",
            ))
        html_doc = _build_saml_post_html(
            result["destination"],
            "SAMLRequest",
            result["request_b64"],
            relay_state,
            title="SAML LogoutRequest 전송",
        )
        _send_html_response(html_doc)
    wiz.response.status(200, data=result)

if action == "slo-result":
    result = struct.session.get("SAML_IDP_LOGOUT_RESULT", {})
    if not isinstance(result, dict) or not result:
        wiz.response.status(404, message="최근 IdP 시작 SLO 검증 결과가 없습니다.")
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
