import datetime
import json
import re
import urllib.parse
import uuid


class Preview:
    def __init__(self, struct):
        self.struct = struct

    def authorize_options(self):
        return {
            "response_types": self.struct.registry.response_type_options(),
            "response_modes": ["query", "fragment", "form_post"],
            "code_challenge_methods": ["S256", "plain"],
            "error_modes": ["", "access_denied", "login_required", "consent_required", "invalid_request"],
        }

    def history(self, category, limit=8):
        rows = self.struct.core.debug_payload.list(protocol="oidc", category=category)
        result = []
        for row in rows[:limit]:
            item = dict(row)
            summary = item.get("summary", {})
            if isinstance(summary, str):
                try:
                    summary = json.loads(summary)
                except Exception:
                    summary = {}
            item["summary"] = summary
            created = item.get("created")
            if created and hasattr(created, "isoformat"):
                item["created"] = created.isoformat()
            result.append(item)
        return result

    def _parse_bool(self, value):
        return str(value or "").lower() in ["1", "true", "yes", "on"]

    def _parse_json(self, value, default=None):
        if default is None:
            default = {}
        if value in [None, ""]:
            return default
        if isinstance(value, (dict, list)):
            return value
        try:
            return json.loads(value)
        except Exception:
            return default

    def _normalize_scope(self, value):
        if isinstance(value, list):
            items = value
        else:
            items = str(value or "").strip().split()
        result = []
        seen = set()
        for item in items:
            token = str(item).strip()
            if token == "" or token in seen:
                continue
            seen.add(token)
            result.append(token)
        return result

    def _collect_claim_names(self, value):
        data = self._parse_json(value, {})
        result = []
        seen = set()

        def push(name):
            name = str(name or "").strip()
            if name == "" or name in seen:
                return
            seen.add(name)
            result.append(name)

        def walk(item, nested=False):
            if isinstance(item, list):
                for sub in item:
                    walk(sub, nested=nested)
                return
            if not isinstance(item, dict):
                return
            for key, value in item.items():
                if key in ["userinfo", "id_token"] and isinstance(value, dict):
                    walk(value, nested=True)
                    continue
                push(key)
                if nested and isinstance(value, dict):
                    for sub_key in value.keys():
                        if sub_key in ["essential", "value", "values"]:
                            continue
                        push(sub_key)

        walk(data)
        return result

    def _resolve_template(self, value, user):
        if isinstance(value, list):
            return [self._resolve_template(item, user) for item in value]
        if isinstance(value, dict):
            return {key: self._resolve_template(item, user) for key, item in value.items()}
        if not isinstance(value, str):
            return value

        def stringify_template_value(item):
            if isinstance(item, (dict, list)):
                return json.dumps(item)
            if item is None:
                return ""
            return str(item)

        def replacer(match):
            key = match.group(1)
            if "." in key:
                top, sub = key.split(".", 1)
                obj = user.get(top)
                if isinstance(obj, dict):
                    return stringify_template_value(obj.get(sub, ""))
                if isinstance(obj, str):
                    try:
                        parsed = json.loads(obj)
                        if isinstance(parsed, dict):
                            return stringify_template_value(parsed.get(sub, ""))
                    except Exception:
                        pass
                return ""
            return stringify_template_value(user.get(key, ""))

        return re.sub(r"\{\{(\w+(?:\.\w+)?)\}\}", replacer, value)

    def _scope_claim_map(self):
        return {
            "openid": ["sub"],
            "profile": ["name", "preferred_username", "profile", "organization", "department", "zoneinfo"],
            "email": ["email", "email_verified"],
            "groups": ["groups"],
            "address": ["address"],
            "phone": ["phone_number", "phone_number_verified"],
            "offline_access": [],
        }

    def _available_claims(self, user, preset_id=""):
        core = self.struct.core
        profile = core.normalize_object(user.get("profile"), {})
        available = {
            "sub": user.get("id", ""),
            "preferred_username": user.get("username", ""),
            "name": user.get("display_name", user.get("username", "")),
            "profile": profile,
            "zoneinfo": "Asia/Seoul",
        }

        if user.get("email"):
            available["email"] = user.get("email")
            available["email_verified"] = True

        if profile.get("groups") not in [None, ""]:
            available["groups"] = profile.get("groups")
        if profile.get("organization") not in [None, ""]:
            available["organization"] = profile.get("organization")
        if profile.get("department") not in [None, ""]:
            available["department"] = profile.get("department")

        if preset_id:
            preset = core.attribute_preset.get(id=preset_id)
            payload = preset.get("payload", {}) if preset else {}
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except Exception:
                    payload = {}
            claims = payload.get("claims", {}) if isinstance(payload, dict) else {}
            if isinstance(claims, dict):
                available.update(self._resolve_template(claims, user))

        user_claims = core.normalize_object(user.get("oidc_claims"), {})
        if user_claims:
            available.update(self._resolve_template(user_claims, user))

        return available

    def _preset_claim_keys(self, preset_id=""):
        if preset_id == "":
            return []
        preset = self.struct.core.attribute_preset.get(id=preset_id)
        payload = preset.get("payload", {}) if preset else {}
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                payload = {}
        claims = payload.get("claims", {}) if isinstance(payload, dict) else {}
        if not isinstance(claims, dict):
            return []
        return list(claims.keys())

    def _build_redirect_target(self, redirect_uri, payload, response_mode):
        if response_mode == "form_post":
            return redirect_uri
        encoded = urllib.parse.urlencode(payload, doseq=True)
        if response_mode == "fragment":
            return f"{redirect_uri}#{encoded}"
        separator = "&" if "?" in redirect_uri else "?"
        return f"{redirect_uri}{separator}{encoded}"

    def _create_debug_entry(self, category, target_id, summary):
        return self.struct.core.debug_payload.create({
            "protocol": "oidc",
            "category": category,
            "target_type": "client",
            "target_id": target_id,
            "summary": summary,
        })

    def simulate_authorize(self, params):
        client_id = str(params.get("client_id", "")).strip()
        user_id = str(params.get("user_id", "")).strip()
        redirect_uri = str(params.get("redirect_uri", "")).strip()
        response_type = str(params.get("response_type", "code")).strip() or "code"
        response_mode = str(params.get("response_mode", "")).strip()
        scope_text = str(params.get("scope", "openid profile email")).strip() or "openid"
        state = str(params.get("state", "")).strip()
        nonce = str(params.get("nonce", "")).strip()
        prompt = str(params.get("prompt", "")).strip()
        max_age = str(params.get("max_age", "")).strip()
        acr_values = str(params.get("acr_values", "")).strip()
        code_challenge = str(params.get("code_challenge", "")).strip()
        code_challenge_method = str(params.get("code_challenge_method", "S256")).strip() or "S256"
        error_mode = str(params.get("error_mode", "")).strip()
        preset_id = str(params.get("preset_id", "")).strip()

        client = self.struct.registry.get(client_id=client_id)
        user = self.struct.core.user.get(id=user_id)
        if user is None:
            raise Exception("사용자를 찾을 수 없습니다.")

        if redirect_uri == "":
            redirect_uri = (client.get("redirect_uris") or [""])[0]
        if redirect_uri not in (client.get("redirect_uris") or []):
            raise Exception("허용되지 않은 redirect_uri입니다.")

        requested_scopes = self._normalize_scope(scope_text)
        if len(requested_scopes) == 0:
            requested_scopes = ["openid"]

        unsupported_scopes = [scope for scope in requested_scopes if scope not in (client.get("scope_policy") or [])]
        if unsupported_scopes:
            raise Exception(f"허용되지 않은 scope가 포함되어 있습니다: {', '.join(unsupported_scopes)}")

        if response_type not in (client.get("response_types") or []):
            raise Exception("등록된 RP가 허용하지 않는 response_type입니다.")

        if "code" in response_type.split() and "authorization_code" not in (client.get("grant_types") or []):
            raise Exception("이 RP는 authorization_code grant를 허용하지 않습니다.")

        available_claims = self._available_claims(user, preset_id=preset_id)
        requested_claims = self._collect_claim_names(params.get("claims"))
        preset_claims = self._preset_claim_keys(preset_id)
        scope_claim_map = self._scope_claim_map()

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

        response_mode = response_mode or ("query" if response_type == "code" else "fragment")
        warnings = []
        if response_mode == "query" and any(token_part in response_type.split() for token_part in ["id_token", "token"]):
            warnings.append("front-channel token 응답은 일반적으로 fragment 또는 form_post를 사용합니다.")
        if code_challenge and code_challenge_method not in ["S256", "plain"]:
            warnings.append("알 수 없는 PKCE method입니다. UI 검증용으로만 표시합니다.")
        if missing_claims:
            warnings.append(f"해당 사용자가 제공하지 않는 claim이 있습니다: {', '.join(missing_claims)}")
        if error_mode:
            warnings.append(f"강제 오류 모드가 활성화되었습니다: {error_mode}")

        provider = self.struct.provider
        authorize_request = {
            "client_id": client["client_id"],
            "redirect_uri": redirect_uri,
            "response_type": response_type,
            "scope": " ".join(requested_scopes),
            "state": state,
            "nonce": nonce,
            "prompt": prompt,
            "max_age": max_age,
            "acr_values": acr_values,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method if code_challenge else "",
        }
        claims_param = self._parse_json(params.get("claims"), {})
        if claims_param:
            authorize_request["claims"] = claims_param
        authorize_url_payload = {key: value for key, value in authorize_request.items() if value not in ["", None, {}]}
        authorize_url = self.struct.provider.info()["authorization_endpoint"]
        raw_authorize_url = f"{authorize_url}?{urllib.parse.urlencode(authorize_url_payload, doseq=True)}"

        redirect_payload = {}
        authorization_code = ""
        access_token = ""
        id_token = ""
        id_token_payload = {}
        userinfo = {}
        token_response = {}
        status = "success"

        if error_mode:
            status = "error"
            redirect_payload["error"] = error_mode
            if state:
                redirect_payload["state"] = state
        else:
            if "code" in response_type.split():
                authorization_code = f"code_{uuid.uuid4().hex[:24]}"
                redirect_payload["code"] = authorization_code
            if state:
                redirect_payload["state"] = state

            access_token = f"atk_{uuid.uuid4().hex}"
            userinfo = dict(released_claims)
            if "sub" not in userinfo:
                userinfo["sub"] = user.get("id", "")

            token_claims = dict(released_claims)
            if acr_values:
                token_claims["acr"] = acr_values.split()[0]
            issued = provider.issue_id_token(client["client_id"], user.get("id", ""), extra_claims=token_claims, nonce=nonce)
            id_token = issued["token"]
            id_token_payload = issued["payload"]

            if response_type != "code":
                if "token" in response_type.split():
                    redirect_payload["access_token"] = access_token
                    redirect_payload["token_type"] = "Bearer"
                    redirect_payload["expires_in"] = 3600
                    redirect_payload["scope"] = " ".join(requested_scopes)
                if "id_token" in response_type.split():
                    redirect_payload["id_token"] = id_token

            token_response = {
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": " ".join(requested_scopes),
                "access_token": access_token,
                "id_token": id_token,
            }

        redirect_target = self._build_redirect_target(redirect_uri, redirect_payload, response_mode)
        form_post = None
        if response_mode == "form_post":
            form_post = {
                "action": redirect_uri,
                "payload": redirect_payload,
            }

        debug_key = self._create_debug_entry("authorize", client["client_id"], {
            "client_id": client["client_id"],
            "client_name": client.get("client_name", ""),
            "user_id": user.get("id", ""),
            "user_display": user.get("display_name") or user.get("username", ""),
            "response_type": response_type,
            "scope": " ".join(requested_scopes),
            "status": status,
            "redirect_uri": redirect_uri,
            "error_mode": error_mode,
        })

        return {
            "status": status,
            "history_key": debug_key,
            "raw_authorize_url": raw_authorize_url,
            "request": authorize_request,
            "client": client,
            "user": {
                "id": user.get("id", ""),
                "username": user.get("username", ""),
                "display_name": user.get("display_name", ""),
                "email": user.get("email", ""),
            },
            "consent": {
                "requested_scopes": requested_scopes,
                "requested_claims": requested_claims,
                "released_claims": list(released_claims.keys()),
                "missing_claims": missing_claims,
            },
            "warnings": warnings,
            "redirect_uri": redirect_uri,
            "redirect_mode": response_mode,
            "redirect_target": redirect_target,
            "redirect_payload": redirect_payload,
            "form_post": form_post,
            "authorization_code": authorization_code,
            "token_response": token_response,
            "userinfo": userinfo,
            "id_token": id_token,
            "id_token_payload": id_token_payload,
        }

    def simulate_logout(self, params):
        client_id = str(params.get("client_id", "")).strip()
        user_id = str(params.get("user_id", "")).strip()
        state = str(params.get("state", "")).strip()
        requested_redirect = str(params.get("post_logout_redirect_uri", "")).strip()
        id_token_hint = str(params.get("id_token_hint", "")).strip()
        local_session_clear = self._parse_bool(params.get("local_session_clear", True))

        client = self.struct.registry.get(client_id=client_id)
        provider = self.struct.provider
        warnings = []
        decoded_hint = {}
        user = None

        if id_token_hint:
            decoded = provider.decode_without_verify(id_token_hint)
            decoded_hint = decoded.get("payload", {})
            audience = decoded_hint.get("aud", "")
            if isinstance(audience, list):
                client_match = client_id in audience
            else:
                client_match = audience == client_id
            if client_match is False:
                warnings.append("id_token_hint의 aud가 선택한 RP와 일치하지 않습니다.")
            if user_id:
                user = self.struct.core.user.get(id=user_id)
                if user and decoded_hint.get("sub") and decoded_hint.get("sub") != user.get("id"):
                    warnings.append("id_token_hint의 sub가 선택한 사용자와 일치하지 않습니다.")
            elif decoded_hint.get("sub"):
                user = self.struct.core.user.get(id=decoded_hint.get("sub"))

        if user is None and user_id:
            user = self.struct.core.user.get(id=user_id)

        if not id_token_hint:
            if user is None:
                raise Exception("사용자 또는 id_token_hint가 필요합니다.")
            issued = provider.issue_id_token(client["client_id"], user.get("id", ""), extra_claims={
                "preferred_username": user.get("username", ""),
                "name": user.get("display_name", user.get("username", "")),
            })
            id_token_hint = issued["token"]
            decoded_hint = issued["payload"]

        allowed_redirects = client.get("post_logout_redirect_uris") or []
        redirect_target = requested_redirect
        if redirect_target:
            if redirect_target not in allowed_redirects:
                raise Exception("허용되지 않은 post_logout_redirect_uri입니다.")
        elif allowed_redirects:
            redirect_target = allowed_redirects[0]
        else:
            redirect_target = provider.info()["issuer"]
            warnings.append("등록된 post_logout_redirect_uri가 없어 issuer로 복귀합니다.")

        session_match = {
            "client_match": False,
            "user_match": False,
            "matched": False,
        }
        audience = decoded_hint.get("aud", "")
        if isinstance(audience, list):
            session_match["client_match"] = client_id in audience
        else:
            session_match["client_match"] = audience in ["", client_id]
        if user is not None:
            session_match["user_match"] = decoded_hint.get("sub", user.get("id", "")) == user.get("id", "")
        else:
            session_match["user_match"] = decoded_hint.get("sub", "") != ""
        session_match["matched"] = session_match["client_match"] and session_match["user_match"]
        if session_match["matched"] is False:
            warnings.append("세션 힌트와 선택 정보가 완전히 일치하지 않습니다.")

        request_payload = {
            "id_token_hint": id_token_hint,
            "post_logout_redirect_uri": requested_redirect or "",
            "state": state,
        }
        request_payload = {key: value for key, value in request_payload.items() if value not in ["", None]}
        end_session_endpoint = provider.info()["end_session_endpoint"]
        end_session_url = end_session_endpoint
        if request_payload:
            end_session_url = f"{end_session_endpoint}?{urllib.parse.urlencode(request_payload, doseq=True)}"

        debug_key = self._create_debug_entry("logout", client["client_id"], {
            "client_id": client["client_id"],
            "client_name": client.get("client_name", ""),
            "user_id": user.get("id", "") if user else decoded_hint.get("sub", ""),
            "redirect_target": redirect_target,
            "matched": session_match["matched"],
        })

        return {
            "history_key": debug_key,
            "client": client,
            "user": {
                "id": user.get("id", "") if user else decoded_hint.get("sub", ""),
                "username": user.get("username", "") if user else "",
                "display_name": user.get("display_name", "") if user else "",
            },
            "decoded_id_token_hint": decoded_hint,
            "session_match": session_match,
            "warnings": warnings,
            "redirect_target": redirect_target,
            "end_session_url": end_session_url,
            "request": request_payload,
            "id_token_hint": id_token_hint,
            "local_session_clear": {
                "cleared": local_session_clear,
                "message": "UI 검증용 시뮬레이션에서 local session clear를 표시했습니다." if local_session_clear else "local session clear를 건너뛰었습니다.",
            },
        }


Model = Preview