import base64
import datetime
import hashlib
import json
import re
import urllib.parse
import uuid


class OIDCFlowError(Exception):
    def __init__(self, error, description, status=400):
        super().__init__(description)
        self.error = error
        self.description = description
        self.status = status


def _b64u(data):
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


class Flow:
    def __init__(self, struct):
        self.struct = struct

    def _preview(self):
        return self.struct.preview

    def _code_db(self):
        return self.struct.db("oidc_authorization_code")

    def _token_db(self):
        return self.struct.db("oidc_token_log")

    def _debug_fs(self):
        return wiz.project.fs("metadata", "oidc", "debug")

    def _now(self):
        return datetime.datetime.now()

    def _parse_datetime(self, value):
        if value in [None, ""]:
            return None
        if isinstance(value, str):
            try:
                return datetime.datetime.fromisoformat(value)
            except Exception:
                try:
                    return datetime.datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
                except Exception:
                    return None
        return value

    def _normalize_object(self, value, default=None):
        if default is None:
            default = {}
        if isinstance(value, dict):
            return value
        if value in [None, ""]:
            return default
        try:
            parsed = json.loads(value)
        except Exception:
            return default
        if isinstance(parsed, dict):
            return parsed
        return default

    def _current_user(self):
        user_id = str(self.struct.session.get("id", "")).strip()
        if user_id:
            user = self.struct.core.user.get(id=user_id)
            if user is not None and not self.struct.core.user.is_expired(user):
                return user

        username = str(self.struct.session.get("username", "")).strip()
        if username:
            user = self.struct.core.user.get(username=username)
            if user is not None and not self.struct.core.user.is_expired(user):
                return user

        email = str(self.struct.session.get("email", "")).strip()
        if email:
            for row in self.struct.core.user.list_active():
                if row.get("email", "") == email:
                    return row
        return None

    def _resolve_user(self, user_id=""):
        user_id = str(user_id or "").strip()
        if user_id:
            user = self.struct.core.user.get(id=user_id)
            if user is None or self.struct.core.user.is_expired(user):
                raise OIDCFlowError("invalid_request", "사용자를 찾을 수 없거나 만료되었습니다.", 400)
            return user
        return self._current_user()

    def _safe_client(self, client):
        item = dict(client or {})
        item.pop("client_secret", None)
        return item

    def _safe_user(self, user):
        item = dict(user or {})
        item.pop("password_hash", None)
        return item

    def _generate_debug_key(self):
        random_value = self.struct.core.db("idp_debug_payload").random(24)
        return f"oidc_{random_value}"

    def _write_debug_raw(self, key, payload):
        self._debug_fs().write.json(f"{key}.json", payload)
        return f"{key}.json"

    def _create_debug_entry(self, category, client, user, summary, payload):
        key = self._generate_debug_key()
        raw_path = self._write_debug_raw(key, payload)
        self.struct.core.debug_payload.create({
            "key": key,
            "protocol": "oidc",
            "category": category,
            "target_type": "client",
            "target_id": client.get("client_id", ""),
            "payload_format": "json",
            "summary": dict(summary),
            "raw_path": raw_path,
        })
        return key

    def _update_debug_entry(self, key, summary_updates=None, payload=None):
        row = self.struct.core.debug_payload.get(key=key) or {}
        summary = dict(row.get("summary", {}) or {})
        if isinstance(summary_updates, dict):
            summary.update(summary_updates)

        data = {}
        if summary_updates is not None:
            data["summary"] = summary
        if payload is not None:
            data["raw_path"] = self._write_debug_raw(key, payload)
        if data:
            self.struct.core.debug_payload.update(data, key=key)

    def get_debug_raw(self, key):
        key = str(key or "").strip()
        if not re.match(r"^[a-zA-Z0-9_\-]+$", key):
            raise OIDCFlowError("invalid_request", "Invalid debug key", 400)
        fs = self._debug_fs()
        fname = f"{key}.json"
        if not fs.exists(fname):
            raise OIDCFlowError("not_found", f"Debug file not found: {key}", 404)
        return fs.read.json(fname, default={})

    def generate_code_challenge(self, code_verifier, method="S256"):
        method = str(method or "S256").strip() or "S256"
        code_verifier = str(code_verifier or "")
        if method == "plain":
            return code_verifier
        if method != "S256":
            raise OIDCFlowError("invalid_request", "지원하지 않는 code_challenge_method입니다.", 400)
        return _b64u(hashlib.sha256(code_verifier.encode("utf-8")).digest())

    def _build_claim_release(self, client, user, scope_text, claims_value, preset_id=""):
        preview = self._preview()
        requested_scopes = preview._normalize_scope(scope_text)
        if len(requested_scopes) == 0:
            requested_scopes = ["openid"]
        if "openid" not in requested_scopes:
            raise OIDCFlowError("invalid_scope", "openid scope가 필요합니다.", 400)

        unsupported_scopes = [scope for scope in requested_scopes if scope not in (client.get("scope_policy") or [])]
        if unsupported_scopes:
            raise OIDCFlowError(
                "invalid_scope",
                f"허용되지 않은 scope가 포함되어 있습니다: {', '.join(unsupported_scopes)}",
                400,
            )

        claims_param = preview._parse_json(claims_value, {})
        available_claims = preview._available_claims(user, preset_id=preset_id)
        requested_claims = preview._collect_claim_names(claims_param)
        preset_claims = preview._preset_claim_keys(preset_id)
        scope_claim_map = preview._scope_claim_map()

        release_order = []
        for scope in requested_scopes:
            release_order.extend(scope_claim_map.get(scope, []))
        release_order.extend(preset_claims)
        release_order.extend(client.get("claims_policy") or [])
        release_order.extend(requested_claims)
        if "sub" not in release_order:
            release_order.insert(0, "sub")

        released_claims = {}
        missing_claims = []
        seen = set()
        for claim in release_order:
            claim = str(claim or "").strip()
            if claim == "" or claim in seen:
                continue
            seen.add(claim)
            if claim in available_claims:
                released_claims[claim] = available_claims[claim]
            else:
                missing_claims.append(claim)

        return {
            "requested_scopes": requested_scopes,
            "requested_claims": requested_claims,
            "released_claims": released_claims,
            "missing_claims": missing_claims,
            "claims_param": claims_param,
        }

    def authorize(self, params):
        client_id = str(params.get("client_id", "")).strip()
        if client_id == "":
            raise OIDCFlowError("invalid_client", "client_id가 필요합니다.", 400)
        client = self.struct.registry.get(client_id=client_id)
        if client is None:
            raise OIDCFlowError("invalid_client", "등록되지 않은 client_id입니다.", 400)
        if client.get("expired"):
            raise OIDCFlowError("invalid_client", "만료된 RP입니다.", 400)

        prompt = str(params.get("prompt", "")).strip()
        user = self._resolve_user(params.get("user_id", ""))
        if user is None:
            if "none" in prompt.split():
                raise OIDCFlowError("login_required", "prompt=none 요청에는 활성 세션이 필요합니다.", 401)
            raise OIDCFlowError("login_required", "authorize endpoint requires an authenticated session or explicit user_id.", 401)

        redirect_uri = str(params.get("redirect_uri", "")).strip()
        if redirect_uri == "":
            redirect_uri = (client.get("redirect_uris") or [""])[0]
        if redirect_uri not in (client.get("redirect_uris") or []):
            raise OIDCFlowError("invalid_request", "허용되지 않은 redirect_uri입니다.", 400)

        response_type = str(params.get("response_type", "code")).strip() or "code"
        if response_type not in (client.get("response_types") or []):
            raise OIDCFlowError("unsupported_response_type", "등록된 RP가 허용하지 않는 response_type입니다.", 400)
        if response_type != "code":
            raise OIDCFlowError("unsupported_response_type", "현재 실제 authorize route는 response_type=code만 지원합니다.", 400)
        if "authorization_code" not in (client.get("grant_types") or []):
            raise OIDCFlowError("unauthorized_client", "이 RP는 authorization_code grant를 허용하지 않습니다.", 400)

        response_mode = str(params.get("response_mode", "query")).strip() or "query"
        if response_mode not in ["query", "fragment", "form_post"]:
            raise OIDCFlowError("invalid_request", "지원하지 않는 response_mode입니다.", 400)

        state = str(params.get("state", "")).strip()
        nonce = str(params.get("nonce", "")).strip()
        scope_text = str(params.get("scope", "openid")).strip() or "openid"
        max_age = str(params.get("max_age", "")).strip()
        acr_values = str(params.get("acr_values", "")).strip()
        preset_id = str(params.get("preset_id", "")).strip()
        code_challenge = str(params.get("code_challenge", "")).strip()
        code_challenge_method = str(params.get("code_challenge_method", "S256")).strip() or "S256"

        if code_challenge and code_challenge_method not in ["S256", "plain"]:
            raise OIDCFlowError("invalid_request", "지원하지 않는 code_challenge_method입니다.", 400)
        if client.get("token_endpoint_auth_method") == "none" and code_challenge == "":
            raise OIDCFlowError("invalid_request", "public client는 PKCE code_challenge가 필요합니다.", 400)

        release = self._build_claim_release(
            client,
            user,
            scope_text,
            params.get("claims", "{}"),
            preset_id=preset_id,
        )
        warnings = []
        if release["missing_claims"]:
            warnings.append(
                f"해당 사용자가 제공하지 않는 claim이 있습니다: {', '.join(release['missing_claims'])}"
            )

        authorize_request = {
            "client_id": client["client_id"],
            "redirect_uri": redirect_uri,
            "response_type": response_type,
            "scope": " ".join(release["requested_scopes"]),
            "state": state,
            "nonce": nonce,
            "prompt": prompt,
            "max_age": max_age,
            "acr_values": acr_values,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method if code_challenge else "",
        }
        if release["claims_param"]:
            authorize_request["claims"] = release["claims_param"]
        authorize_url_payload = {
            key: value
            for key, value in authorize_request.items()
            if value not in ["", None, {}]
        }
        authorize_url = self.struct.provider.info()["authorization_endpoint"]
        raw_authorize_url = f"{authorize_url}?{urllib.parse.urlencode(authorize_url_payload, doseq=True)}"

        now = self._now()
        code = f"code_{uuid.uuid4().hex[:24]}"
        expires = now + datetime.timedelta(minutes=10)
        redirect_payload = {"code": code}
        if state:
            redirect_payload["state"] = state
        redirect_target = self._preview()._build_redirect_target(redirect_uri, redirect_payload, response_mode)
        form_post = None
        if response_mode == "form_post":
            form_post = {
                "action": redirect_uri,
                "payload": redirect_payload,
            }

        debug_payload = {
            "authorize_request": authorize_request,
            "authorize_context": {
                "client": self._safe_client(client),
                "user": self._safe_user(user),
                "consent": {
                    "auto_approved": True,
                    "requested_scopes": release["requested_scopes"],
                    "requested_claims": release["requested_claims"],
                    "released_claims": list(release["released_claims"].keys()),
                    "missing_claims": release["missing_claims"],
                },
                "warnings": warnings,
            },
            "authorize_response": {
                "redirect_mode": response_mode,
                "redirect_target": redirect_target,
                "redirect_payload": redirect_payload,
                "form_post": form_post,
                "authorization_code": code,
                "expires_at": expires.isoformat(),
            },
        }
        summary = {
            "client_id": client["client_id"],
            "client_name": client.get("client_name", ""),
            "user_id": user.get("id", ""),
            "user_display": user.get("display_name") or user.get("username", ""),
            "response_type": response_type,
            "scope": " ".join(release["requested_scopes"]),
            "status": "authorized",
            "redirect_uri": redirect_uri,
        }
        debug_key = self._create_debug_entry("authorize", client, user, summary, debug_payload)

        self._code_db().insert({
            "code": code,
            "client_id": client["client_id"],
            "user_id": user.get("id", ""),
            "redirect_uri": redirect_uri,
            "scope": " ".join(release["requested_scopes"]),
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method if code_challenge else "",
            "claims": release["claims_param"],
            "released_claims": release["released_claims"],
            "extra": {
                "prompt": prompt,
                "max_age": max_age,
                "acr_values": acr_values,
                "response_mode": response_mode,
                "preset_id": preset_id,
            },
            "debug_key": debug_key,
            "auth_time": now,
            "expires": expires,
            "consumed": None,
            "created": now,
        })

        return {
            "status": "success",
            "history_key": debug_key,
            "debug_raw_url": f"/api/oidc/debug/raw/{debug_key}",
            "raw_authorize_url": raw_authorize_url,
            "request": authorize_request,
            "client": self._safe_client(client),
            "user": {
                "id": user.get("id", ""),
                "username": user.get("username", ""),
                "display_name": user.get("display_name", ""),
                "email": user.get("email", ""),
            },
            "consent": {
                "auto_approved": True,
                "requested_scopes": release["requested_scopes"],
                "requested_claims": release["requested_claims"],
                "released_claims": list(release["released_claims"].keys()),
                "missing_claims": release["missing_claims"],
            },
            "warnings": warnings,
            "redirect_uri": redirect_uri,
            "redirect_mode": response_mode,
            "redirect_target": redirect_target,
            "redirect_payload": redirect_payload,
            "form_post": form_post,
            "authorization_code": code,
            "code_expires_at": expires.isoformat(),
        }

    def _authenticate_client(self, request_data, auth_header=""):
        request_data = dict(request_data or {})
        auth_header = str(auth_header or "").strip()
        provided_client_id = str(request_data.get("client_id", "")).strip()
        provided_client_secret = str(request_data.get("client_secret", "")).strip()
        used_method = ""

        if auth_header.lower().startswith("basic "):
            used_method = "client_secret_basic"
            try:
                decoded = base64.b64decode(auth_header.split(" ", 1)[1]).decode("utf-8")
                provided_client_id, provided_client_secret = decoded.split(":", 1)
            except Exception:
                raise OIDCFlowError("invalid_client", "Authorization Basic 헤더가 올바르지 않습니다.", 401)
        elif provided_client_secret:
            used_method = "client_secret_post"
        else:
            used_method = "none"

        if provided_client_id == "":
            raise OIDCFlowError("invalid_client", "client_id가 필요합니다.", 401)

        client = self.struct.registry.get(client_id=provided_client_id)
        if client is None:
            raise OIDCFlowError("invalid_client", "등록되지 않은 client_id입니다.", 401)

        expected_method = str(client.get("token_endpoint_auth_method", "client_secret_basic")).strip() or "client_secret_basic"
        if expected_method == "private_key_jwt":
            raise OIDCFlowError("invalid_client", "private_key_jwt client authentication은 아직 지원하지 않습니다.", 401)

        if expected_method == "none":
            return client, "none"

        if expected_method != used_method:
            raise OIDCFlowError("invalid_client", "RP에 등록된 client authentication 방식과 요청이 일치하지 않습니다.", 401)
        if provided_client_secret != client.get("client_secret", ""):
            raise OIDCFlowError("invalid_client", "client secret이 올바르지 않습니다.", 401)
        return client, used_method

    def _verify_pkce(self, code_row, code_verifier):
        code_challenge = str(code_row.get("code_challenge", "")).strip()
        if code_challenge == "":
            return

        code_verifier = str(code_verifier or "").strip()
        if code_verifier == "":
            raise OIDCFlowError("invalid_grant", "code_verifier가 필요합니다.", 400)

        method = str(code_row.get("code_challenge_method", "S256")).strip() or "S256"
        expected = self.generate_code_challenge(code_verifier, method)
        if expected != code_challenge:
            raise OIDCFlowError("invalid_grant", "PKCE 검증에 실패했습니다.", 400)

    def _build_userinfo(self, user, released_claims):
        userinfo = dict(released_claims or {})
        if "sub" not in userinfo:
            userinfo["sub"] = user.get("id", "")
        if "preferred_username" not in userinfo and user.get("username"):
            userinfo["preferred_username"] = user.get("username", "")
        if "email" not in userinfo and user.get("email"):
            userinfo["email"] = user.get("email", "")
        if "name" not in userinfo:
            userinfo["name"] = user.get("display_name", user.get("username", ""))
        return userinfo

    def token(self, request_data, auth_header=""):
        request_data = dict(request_data or {})
        grant_type = str(request_data.get("grant_type", "authorization_code")).strip() or "authorization_code"
        if grant_type != "authorization_code":
            raise OIDCFlowError("unsupported_grant_type", "authorization_code grant만 지원합니다.", 400)

        client, used_method = self._authenticate_client(request_data, auth_header=auth_header)
        code_value = str(request_data.get("code", "")).strip()
        redirect_uri = str(request_data.get("redirect_uri", "")).strip()
        code_verifier = str(request_data.get("code_verifier", "")).strip()
        if code_value == "":
            raise OIDCFlowError("invalid_grant", "code가 필요합니다.", 400)

        code_row = self._code_db().get(code=code_value)
        if code_row is None:
            raise OIDCFlowError("invalid_grant", "존재하지 않는 authorization code입니다.", 400)

        expires = self._parse_datetime(code_row.get("expires"))
        consumed = self._parse_datetime(code_row.get("consumed"))
        debug_key = str(code_row.get("debug_key", "")).strip()
        existing_log = None
        if debug_key:
            existing_log = self._token_db().get(debug_key=debug_key)
        if expires and expires < self._now():
            raise OIDCFlowError("invalid_grant", "만료된 authorization code입니다.", 400)
        if consumed is not None or existing_log is not None:
            raise OIDCFlowError("invalid_grant", "이미 사용된 authorization code입니다.", 400)
        if code_row.get("client_id") != client.get("client_id"):
            raise OIDCFlowError("invalid_grant", "authorization code가 다른 RP에 발급되었습니다.", 400)
        if redirect_uri != str(code_row.get("redirect_uri", "")).strip():
            raise OIDCFlowError("invalid_grant", "redirect_uri가 최초 authorize 요청과 일치하지 않습니다.", 400)

        self._verify_pkce(code_row, code_verifier)

        user = self.struct.core.user.get(id=code_row.get("user_id", ""))
        if user is None or self.struct.core.user.is_expired(user):
            raise OIDCFlowError("invalid_grant", "사용자를 찾을 수 없거나 만료되었습니다.", 400)

        released_claims = self._normalize_object(code_row.get("released_claims"), {})
        extra = self._normalize_object(code_row.get("extra"), {})
        scope = str(code_row.get("scope", "")).strip()
        provider = self.struct.provider

        access_issued = provider.issue_access_token(
            client.get("client_id", ""),
            user.get("id", ""),
            scope=scope,
            extra_claims={
                "client_id": client.get("client_id", ""),
                "username": user.get("username", ""),
                "claims": released_claims,
            },
        )
        id_token_claims = dict(released_claims)
        acr_values = str(extra.get("acr_values", "")).strip()
        if acr_values:
            id_token_claims["acr"] = acr_values.split()[0]
        id_issued = provider.issue_id_token(
            client.get("client_id", ""),
            user.get("id", ""),
            extra_claims=id_token_claims,
            nonce=str(code_row.get("nonce", "")).strip(),
        )
        userinfo = self._build_userinfo(user, released_claims)

        token_response = {
            "access_token": access_issued["token"],
            "id_token": id_issued["token"],
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": scope,
        }
        request_view = {
            "grant_type": grant_type,
            "code": code_value,
            "redirect_uri": redirect_uri,
            "client_id": client.get("client_id", ""),
            "client_auth_method": used_method,
        }
        if code_verifier:
            request_view["code_verifier"] = code_verifier

        now = self._now()
        self._token_db().insert({
            "client_id": client.get("client_id", ""),
            "user_id": user.get("id", ""),
            "grant_type": grant_type,
            "access_token_jti": access_issued["payload"].get("jti", ""),
            "id_token_jti": id_issued["payload"].get("jti", ""),
            "debug_key": code_row.get("debug_key", ""),
            "raw_request": request_view,
            "raw_response": {
                "token_response": token_response,
                "access_token_payload": access_issued["payload"],
                "id_token_payload": id_issued["payload"],
                "userinfo": userinfo,
            },
            "created": now,
        })
        self._code_db().update({"consumed": now}, code=code_value)

        if debug_key:
            debug_payload = self.get_debug_raw(debug_key)
            debug_payload["token_request"] = request_view
            debug_payload["token_response"] = token_response
            debug_payload["access_token_payload"] = access_issued["payload"]
            debug_payload["id_token_payload"] = id_issued["payload"]
            debug_payload["userinfo"] = userinfo
            self._update_debug_entry(debug_key, {
                "status": "token_issued",
                "client_id": client.get("client_id", ""),
                "user_id": user.get("id", ""),
            }, debug_payload)

        return {
            "request": request_view,
            "token_response": token_response,
            "id_token": id_issued["token"],
            "id_token_payload": id_issued["payload"],
            "access_token_payload": access_issued["payload"],
            "userinfo": userinfo,
            "debug_key": debug_key,
            "debug_raw_url": f"/api/oidc/debug/raw/{debug_key}" if debug_key else "",
        }

    def userinfo(self, access_token):
        access_token = str(access_token or "").strip()
        if access_token == "":
            raise OIDCFlowError("invalid_token", "access token이 필요합니다.", 401)
        try:
            decoded = self.struct.provider.decode_without_verify(access_token)
        except Exception:
            raise OIDCFlowError("invalid_token", "access token 형식이 올바르지 않습니다.", 401)

        payload = decoded.get("payload", {}) if isinstance(decoded, dict) else {}
        if payload.get("token_use") != "access_token":
            raise OIDCFlowError("invalid_token", "access token이 아닙니다.", 401)

        exp = payload.get("exp")
        if exp not in [None, ""]:
            try:
                if int(exp) < int(datetime.datetime.utcnow().timestamp()):
                    raise OIDCFlowError("invalid_token", "만료된 access token입니다.", 401)
            except OIDCFlowError:
                raise
            except Exception:
                raise OIDCFlowError("invalid_token", "access token 만료 정보가 올바르지 않습니다.", 401)

        userinfo = {}
        jti = str(payload.get("jti", "")).strip()
        if jti:
            row = self._token_db().get(access_token_jti=jti)
            if row is not None:
                raw_response = self._normalize_object(row.get("raw_response"), {})
                userinfo = self._normalize_object(raw_response.get("userinfo"), {})

        if not userinfo:
            userinfo = self._normalize_object(payload.get("claims"), {})

        if not userinfo:
            user = self.struct.core.user.get(id=payload.get("sub", ""))
            if user is None:
                raise OIDCFlowError("invalid_token", "access token에 연결된 사용자를 찾을 수 없습니다.", 401)
            userinfo = self._build_userinfo(user, {})

        if "sub" not in userinfo:
            userinfo["sub"] = payload.get("sub", "")
        return userinfo

    def simulate_authorization_code_flow(self, params):
        simulate_params = dict(params or {})
        code_verifier = str(simulate_params.get("code_verifier", "")).strip()
        code_challenge = str(simulate_params.get("code_challenge", "")).strip()
        code_challenge_method = str(simulate_params.get("code_challenge_method", "S256")).strip() or "S256"

        if code_verifier and not code_challenge:
            simulate_params["code_challenge"] = self.generate_code_challenge(code_verifier, code_challenge_method)
        elif code_challenge and not code_verifier and code_challenge_method == "plain":
            code_verifier = code_challenge

        authorize_result = self.authorize(simulate_params)
        client = self.struct.registry.get(client_id=authorize_result["client"].get("client_id", ""))
        token_request = {
            "grant_type": "authorization_code",
            "code": authorize_result["authorization_code"],
            "redirect_uri": authorize_result["redirect_uri"],
            "code_verifier": code_verifier,
        }
        auth_header = ""
        auth_method = client.get("token_endpoint_auth_method", "client_secret_basic")
        if auth_method == "client_secret_basic":
            basic = f"{client.get('client_id', '')}:{client.get('client_secret', '')}"
            auth_header = f"Basic {base64.b64encode(basic.encode('utf-8')).decode('utf-8')}"
        elif auth_method == "client_secret_post":
            token_request["client_id"] = client.get("client_id", "")
            token_request["client_secret"] = client.get("client_secret", "")
        else:
            token_request["client_id"] = client.get("client_id", "")

        token_result = self.token(token_request, auth_header=auth_header)
        userinfo = self.userinfo(token_result["token_response"]["access_token"])

        authorize_result["token_request"] = token_result["request"]
        authorize_result["token_response"] = token_result["token_response"]
        authorize_result["id_token"] = token_result["id_token"]
        authorize_result["id_token_payload"] = token_result["id_token_payload"]
        authorize_result["access_token_payload"] = token_result["access_token_payload"]
        authorize_result["userinfo"] = userinfo
        authorize_result["history_key"] = token_result["debug_key"] or authorize_result.get("history_key", "")
        authorize_result["debug_raw_url"] = token_result["debug_raw_url"] or authorize_result.get("debug_raw_url", "")
        return authorize_result


Model = Flow