import html
import json
import urllib.parse

struct = wiz.model("portal/oidcidp/struct")
session = wiz.model("portal/season/session").use()
rate_limiter = wiz.model("portal/idpcore/struct/rate_limiter")


def _json_response(payload, status=200):
	flask = wiz.response._flask
	resp = flask.Response(
		json.dumps(payload, ensure_ascii=False),
		mimetype="application/json",
	)
	resp.headers["Cache-Control"] = "no-store"
	resp.headers["Pragma"] = "no-cache"
	wiz.response.set_status(status)
	wiz.response.response(resp)


def _html_response(body, status=200):
	flask = wiz.response._flask
	resp = flask.Response(body, mimetype="text/html")
	resp.headers["Cache-Control"] = "no-store"
	resp.headers["Pragma"] = "no-cache"
	wiz.response.set_status(status)
	wiz.response.response(resp)


def _html_form_post(action, payload):
	inputs = []
	for key, value in payload.items():
		inputs.append(
			f'<input type="hidden" name="{html.escape(str(key), quote=True)}" value="{html.escape(str(value), quote=True)}"/>'
		)
	body = """<!DOCTYPE html>
<html lang="ko">
<head><meta charset="utf-8"/><title>OIDC Form Post</title></head>
<body onload="document.forms[0].submit()">
<form method="post" action="%s">
%s
</form>
</body>
</html>""" % (action, "\n".join(inputs))
	_html_response(body)


def _client_ip():
	try:
		return wiz.request.ip()
	except Exception:
		return "unknown"


def _current_user():
	user_id = str(session.get("id", "")).strip()
	if user_id:
		user = struct.core.user.get(id=user_id)
		if user is not None:
			return user

	username = str(session.get("username", "")).strip()
	if username:
		user = struct.core.user.get(username=username)
		if user is not None:
			return user

	email = str(session.get("email", "")).strip()
	if email:
		for row in struct.core.user.list_active():
			if row.get("email", "") == email:
				return row

	return None


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


def _set_session_user(user):
	session.set(
		id=user.get("id", ""),
		username=user.get("username", ""),
		email=user.get("email", ""),
		name=user.get("display_name", user.get("username", "")),
		role=user.get("role", "tester"),
	)


def _authorize_params():
	allowed = [
		"client_id",
		"redirect_uri",
		"response_type",
		"response_mode",
		"scope",
		"state",
		"nonce",
		"prompt",
		"max_age",
		"acr_values",
		"code_challenge",
		"code_challenge_method",
		"claims",
		"user_id",
	]
	params = {}
	query = dict(wiz.request.query())
	for key in allowed:
		if key in query and query.get(key) is not None:
			params[key] = query.get(key)
	return params


def _resolve_login_user():
	selected_user_id = str(wiz.request.query("selected_user_id", "")).strip()
	if selected_user_id:
		user = _find_active_user(user_id=selected_user_id)
		if user is None:
			raise Exception("선택한 테스트 사용자를 찾을 수 없습니다.")
		if str(user.get("role", "")).strip() == "admin" or str(user.get("username", "")).strip() == "admin":
			raise Exception("admin 계정은 목록에서 바로 선택할 수 없습니다. 관리자 로그인 폼을 사용해주세요.")
		_set_session_user(user)
		return user

	login_id = str(wiz.request.query("login_id", "")).strip()
	password = wiz.request.query("password", "")
	if login_id or password:
		if not rate_limiter.check(f"oidc-authorize-login:{_client_ip()}", max_requests=10, window_seconds=300):
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

	return _current_user()


def _hidden_authorize_inputs(params, extra=None):
	payload = dict(params or {})
	if extra:
		payload.update(extra)
	lines = []
	for key, value in payload.items():
		if key in ["selected_user_id", "login_id", "password"]:
			continue
		if value is None:
			value = ""
		lines.append(
			f'<input type="hidden" name="{html.escape(str(key), quote=True)}" value="{html.escape(str(value), quote=True)}"/>'
		)
	return "\n                ".join(lines)


def _authorize_href(params, extra=None):
	payload = dict(params or {})
	if extra:
		payload.update(extra)
	query = {}
	for key, value in payload.items():
		if value is None:
			continue
		text = str(value)
		if text == "":
			continue
		query[key] = text
	return f"/api/oidc/authorize?{urllib.parse.urlencode(query)}"


def _build_authorize_prompt_html(params, error_message=""):
	client_id = str(params.get("client_id", "")).strip()
	client = None
	try:
		client = struct.registry.get(client_id=client_id)
	except Exception:
		client = None

	service_label = client.get("client_name", "") if client else ""
	if not service_label:
		service_label = client_id or "OIDC Client"
	redirect_uri = str(params.get("redirect_uri", "")).strip()
	if not redirect_uri and client:
		redirect_uri = (client.get("redirect_uris") or [""])[0]
	scope_text = str(params.get("scope", "openid")).strip() or "openid"
	response_type = str(params.get("response_type", "code")).strip() or "code"

	try:
		users = struct.core.user.list_active()
	except Exception:
		users = []

	cards = []
	for user in users:
		if str(user.get("role", "")).strip() == "admin" or str(user.get("username", "")).strip() == "admin":
			continue
		display_name = str(user.get("display_name", user.get("username", ""))).strip() or str(user.get("username", "")).strip()
		username = str(user.get("username", "")).strip()
		email_value = str(user.get("email", "")).strip()
		role = str(user.get("role", "tester")).strip() or "tester"
		authorize_href = _authorize_href(params, {"selected_user_id": user.get("id", "")})
		cards.append(f"""
			<div class=\"account-card\">
				<a href=\"{html.escape(authorize_href, quote=True)}\" target=\"_top\" class=\"account-button\">
					<span class=\"account-name\">{html.escape(display_name)}</span>
					<span class=\"account-meta\">{html.escape(username)}{(' · ' + html.escape(email_value)) if email_value else ''}</span>
					<span class=\"account-role\">{html.escape(role)}</span>
				</a>
			</div>
		""")

	error_block = ""
	if error_message:
		error_block = f'<div class="notice error">{html.escape(error_message)}</div>'

	empty_block = ""
	if len(cards) == 0:
		empty_block = '<div class="notice">선택 가능한 활성 테스트 계정이 없습니다. 아래 폼으로 관리자 로그인을 진행하세요.</div>'

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
			--bg-1: #eef7ff;
			--bg-2: #fbfdff;
			--ink: #172033;
			--muted: #5a6578;
			--line: rgba(40, 84, 129, 0.14);
			--brand: #0b6acb;
			--brand-deep: #094e95;
			--panel: rgba(255, 255, 255, 0.92);
			--warn: #a33b22;
			--shadow: 0 24px 60px rgba(29, 58, 97, 0.12);
		}}
		* {{ box-sizing: border-box; }}
		body {{
			margin: 0;
			min-height: 100vh;
			font-family: \"Segoe UI\", \"Noto Sans KR\", sans-serif;
			color: var(--ink);
			background:
				radial-gradient(circle at top left, rgba(169, 214, 255, 0.72), transparent 30%),
				radial-gradient(circle at bottom right, rgba(86, 176, 255, 0.18), transparent 28%),
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
		.eyebrow {{ font-size: 11px; letter-spacing: 0.22em; text-transform: uppercase; color: var(--brand); font-weight: 700; }}
		h1 {{ margin: 14px 0 0; font-size: 34px; line-height: 1.1; }}
		p {{ margin: 0; }}
		.summary {{ margin-top: 18px; color: var(--muted); font-size: 14px; line-height: 1.7; }}
		.meta-grid {{ display: grid; gap: 14px; margin-top: 28px; }}
		.meta {{ padding: 16px 18px; border-radius: 20px; background: rgba(11, 106, 203, 0.05); border: 1px solid rgba(11, 106, 203, 0.08); }}
		.meta-label {{ font-size: 11px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--muted); font-weight: 700; }}
		.meta-value {{ margin-top: 8px; font-size: 14px; font-weight: 600; word-break: break-all; }}
		.notice {{ margin-bottom: 16px; border-radius: 16px; padding: 14px 16px; font-size: 13px; line-height: 1.6; background: rgba(11, 106, 203, 0.06); color: var(--muted); }}
		.notice.error {{ background: rgba(163, 59, 34, 0.08); color: var(--warn); }}
		.section-title {{ font-size: 14px; font-weight: 700; margin-bottom: 12px; }}
		.account-grid {{ display: grid; gap: 12px; }}
		.account-card {{ margin: 0; }}
		.account-button {{ width: 100%; display: block; border: 1px solid var(--line); border-radius: 18px; background: #fff; padding: 16px; text-align: left; cursor: pointer; text-decoration: none; transition: border-color .16s ease, transform .16s ease, box-shadow .16s ease; }}
		.account-button:hover {{ border-color: rgba(11, 106, 203, 0.35); transform: translateY(-1px); box-shadow: 0 14px 30px rgba(26, 58, 92, 0.08); }}
		.account-name {{ display: block; font-size: 15px; font-weight: 700; color: var(--ink); }}
		.account-meta {{ display: block; margin-top: 6px; font-size: 13px; color: var(--muted); word-break: break-all; }}
		.account-role {{ display: inline-flex; margin-top: 10px; padding: 4px 9px; border-radius: 999px; background: rgba(11, 106, 203, 0.08); color: var(--brand); font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .08em; }}
		.form-shell {{ margin-top: 22px; border-top: 1px solid var(--line); padding-top: 22px; }}
		.form-grid {{ display: grid; gap: 14px; }}
		.label {{ display: block; font-size: 12px; color: var(--muted); font-weight: 700; margin-bottom: 6px; }}
		.input {{ width: 100%; border-radius: 14px; border: 1px solid var(--line); padding: 12px 14px; font-size: 14px; color: var(--ink); background: rgba(255,255,255,0.96); }}
		.input:focus {{ outline: none; border-color: rgba(11, 106, 203, 0.42); box-shadow: 0 0 0 3px rgba(11, 106, 203, 0.08); }}
		.submit {{ border: 0; border-radius: 16px; background: linear-gradient(135deg, var(--brand), var(--brand-deep)); color: #fff; font-weight: 700; font-size: 14px; padding: 13px 16px; cursor: pointer; }}
		.help {{ margin-top: 10px; color: var(--muted); font-size: 12px; line-height: 1.6; }}
		@media (max-width: 920px) {{ .shell {{ grid-template-columns: 1fr; }} .hero {{ order: 2; }} .auth {{ order: 1; }} }}
	</style>
</head>
<body>
	<div class=\"shell\">
		<section class=\"panel hero\">
			<p class=\"eyebrow\">OIDC Authorization</p>
			<h1>등록된 서비스 로그인을 계속하려면 테스트 계정을 선택하세요.</h1>
			<p class=\"summary\">현재 authorize 요청은 로그인 세션이 없는 상태입니다. 빠른 계정 선택으로 바로 진행하거나, 관리자 계정으로 로그인한 뒤 같은 authorize 요청을 이어서 처리할 수 있습니다.</p>
			<div class=\"meta-grid\">
				<div class=\"meta\">
					<p class=\"meta-label\">Client</p>
					<p class=\"meta-value\">{html.escape(service_label)}</p>
				</div>
				<div class=\"meta\">
					<p class=\"meta-label\">Redirect URI</p>
					<p class=\"meta-value\">{html.escape(redirect_uri or 'RP 기본 redirect_uri 사용')}</p>
				</div>
				<div class=\"meta\">
					<p class=\"meta-label\">Scope / Response Type</p>
					<p class=\"meta-value\">{html.escape(scope_text)} / {html.escape(response_type)}</p>
				</div>
			</div>
		</section>

		<section class=\"panel auth\">
			{error_block}
			<div class=\"section-title\">빠른 테스트 계정 선택</div>
			{empty_block}
			<div class=\"account-grid\">{''.join(cards)}</div>

			<div class=\"form-shell\">
				<div class=\"section-title\">관리자 계정 로그인</div>
				<form method=\"post\" action=\"/api/oidc/authorize\" class=\"form-grid\">
					{_hidden_authorize_inputs(params)}
					<div>
						<label class=\"label\" for=\"login_id\">사용자명 또는 이메일</label>
						<input id=\"login_id\" class=\"input\" type=\"text\" name=\"login_id\" placeholder=\"admin\" autocomplete=\"username\"/>
					</div>
					<div>
						<label class=\"label\" for=\"password\">비밀번호</label>
						<input id=\"password\" class=\"input\" type=\"password\" name=\"password\" placeholder=\"비밀번호\" autocomplete=\"current-password\"/>
					</div>
					<button type=\"submit\" class=\"submit\">로그인 후 authorize 계속</button>
				</form>
				<p class=\"help\">보안 정책상 비밀번호 로그인은 관리자 계정만 허용합니다. 일반 테스트 계정은 위의 빠른 선택 카드로 authorize 흐름을 이어서 검증하세요.</p>
			</div>
		</section>
	</div>
</body>
</html>"""


segment = wiz.request.match("/api/oidc/<path:action>")
if segment is None:
	wiz.response.status(404)

action = str(segment.action or "").strip("/")

if action.startswith("debug/raw/"):
	key = action.split("/", 2)[2] if action.count("/") >= 2 else ""
	try:
		payload = struct.flow.get_debug_raw(key)
	except Exception as e:
		if hasattr(e, "error"):
			_json_response({
				"error": getattr(e, "error", "not_found"),
				"error_description": getattr(e, "description", str(e)),
			}, status=getattr(e, "status", 404))
		_json_response({
			"error": "not_found",
			"error_description": str(e),
		}, status=404)
	_json_response(payload)

if action == "jwks":
	_json_response(struct.provider.jwks_public())

if action == "userinfo":
	auth_header = str(wiz.request.headers("Authorization", "")).strip()
	access_token = ""
	if auth_header.lower().startswith("bearer "):
		access_token = auth_header.split(" ", 1)[1].strip()
	if not access_token:
		access_token = str(wiz.request.query("access_token", "")).strip()
	if access_token:
		try:
			userinfo = struct.flow.userinfo(access_token)
		except Exception as e:
			if hasattr(e, "error"):
				_json_response({
					"error": getattr(e, "error", "invalid_token"),
					"error_description": getattr(e, "description", str(e)),
				}, status=getattr(e, "status", 401))
			_json_response({
				"error": "invalid_token",
				"error_description": str(e),
			}, status=401)
		_json_response(userinfo)

	user = _current_user()
	if user is None:
		_json_response({
			"error": "login_required",
			"error_description": "userinfo endpoint requires an authenticated session.",
		}, status=401)
	claims = dict(user.get("oidc_claims", {}) or {})
	if "sub" not in claims:
		claims["sub"] = user.get("id", "")
	if "preferred_username" not in claims:
		claims["preferred_username"] = user.get("username", "")
	if "email" not in claims:
		claims["email"] = user.get("email", "")
	if "name" not in claims:
		claims["name"] = user.get("display_name", user.get("username", ""))
	_json_response(claims)

if action == "token":
	request_data = dict(wiz.request.query())
	auth_header = str(wiz.request.headers("Authorization", "")).strip()
	try:
		result = struct.flow.token(request_data, auth_header=auth_header)
	except Exception as e:
		if hasattr(e, "error"):
			_json_response({
				"error": getattr(e, "error", "invalid_request"),
				"error_description": getattr(e, "description", str(e)),
			}, status=getattr(e, "status", 400))
		_json_response({
			"error": "invalid_request",
			"error_description": str(e),
		}, status=400)
	_json_response(result.get("token_response", {}))

if action == "authorize":
	params = _authorize_params()
	prompt_values = str(params.get("prompt", "")).split()
	if not params.get("user_id"):
		user = _current_user()
		if user is not None:
			params["user_id"] = user.get("id", "")

	if not params.get("user_id") and "none" not in prompt_values:
		try:
			user = _resolve_login_user()
		except Exception as e:
			_html_response(_build_authorize_prompt_html(params, error_message=str(e)), status=401)
		if user is None:
			_html_response(_build_authorize_prompt_html(params))
		params["user_id"] = user.get("id", "")

	try:
		result = struct.flow.authorize(params)
	except Exception as e:
		if getattr(e, "error", "") == "login_required" and "none" not in prompt_values:
			_html_response(
				_build_authorize_prompt_html(params, error_message=getattr(e, "description", str(e))),
				status=getattr(e, "status", 401),
			)
		if hasattr(e, "error"):
			_json_response({
				"error": getattr(e, "error", "invalid_request"),
				"error_description": getattr(e, "description", str(e)),
			}, status=getattr(e, "status", 400))
		_json_response({
			"error": "invalid_request",
			"error_description": str(e),
		}, status=400)

	if result.get("form_post"):
		form_post = result.get("form_post") or {}
		_html_form_post(form_post.get("action", ""), form_post.get("payload", {}))

	redirect_target = str(result.get("redirect_target", "")).strip()
	if redirect_target:
		wiz.response.redirect(redirect_target)
	_json_response(result)

if action == "logout":
	params = dict(wiz.request.query())
	if not params.get("user_id"):
		user = _current_user()
		if user is not None:
			params["user_id"] = user.get("id", "")
	try:
		result = struct.preview.simulate_logout(params)
	except Exception as e:
		_json_response({
			"error": "invalid_request",
			"error_description": str(e),
		}, status=400)

	redirect_target = str(result.get("redirect_target", "")).strip()
	if redirect_target:
		wiz.response.redirect(redirect_target)
	_json_response(result)

_json_response({
	"error": "not_found",
	"error_description": f"unsupported oidc endpoint: {action}",
}, status=404)
