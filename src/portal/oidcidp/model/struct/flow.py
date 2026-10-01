import base64
import datetime
import hashlib
import hmac
import ipaddress
import json
import re
import socket
import time
import urllib.parse
import urllib.request
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


class OIDCFlowError(Exception):
    def __init__(self, error, description, status=400):
        super().__init__(description)
        self.error = error
        self.description = description
        self.status = status


def _b64u(data):
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64u_decode(value):
    value = str(value or "")
    return base64.urlsafe_b64decode(
        f"{value}{'=' * ((4 - len(value) % 4) % 4)}".encode("ascii")
    )


PKCE_VERIFIER_PATTERN = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
CLIENT_ASSERTION_ALGORITHMS = ["HS256", "RS256", "PS256", "ES256"]
SENSITIVE_FIELD_PATTERN = re.compile(
    r"(?:password|secret|token|assertion|code_verifier|private[_-]?key|cookie)",
    re.IGNORECASE,
)


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

    def _mask_value(self, value, key=""):
        if isinstance(value, dict):
            return {
                str(item_key): self._mask_value(item_value, str(item_key))
                for item_key, item_value in value.items()
            }
        if isinstance(value, list):
            return [self._mask_value(item, key) for item in value]
        if SENSITIVE_FIELD_PATTERN.search(str(key or "")):
            text = str(value or "")
            if not text:
                return ""
            return {
                "masked": True,
                "length": len(text),
                "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()[:16],
            }
        return value

    def _profile_settings(self, reviewops_profile):
        try:
            return self.struct.provider.profile_settings(reviewops_profile)
        except (AttributeError, ValueError):
            return {
                "subject_source": "sub",
                "claim_overrides": {},
                "userinfo_claim_overrides": {},
                "omit_claims": [],
                "id_token_only_claims": [],
                "userinfo_only_claims": [],
                "distributed_claims": {},
                "id_token_signing_alg": "RS256",
                "response_variant": "standard",
                "time_offset_seconds": 0,
                "token_ttl_seconds": 600,
                "refresh_token_ttl_seconds": 2592000,
                "session_ttl_seconds": 28800,
                "acr": "",
                "amr": ["pwd"],
            }

    def _claim_path(self, claims, path, fallback=""):
        current = claims
        for part in str(path or "").split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return fallback
        return current

    def _apply_profile_claims(self, claims, settings, target):
        result = dict(claims or {})
        result.update(settings.get("claim_overrides", {}) or {})
        if target == "id_token":
            result.update(settings.get("id_token_claim_overrides", {}) or {})
            excluded = set(settings.get("userinfo_only_claims", []) or [])
        else:
            result.update(settings.get("userinfo_claim_overrides", {}) or {})
            excluded = set(settings.get("id_token_only_claims", []) or [])
        excluded.update(settings.get("omit_claims", []) or [])
        for claim in excluded:
            result.pop(claim, None)
        if target == "userinfo":
            distributed = settings.get("distributed_claims", {}) or {}
            claim_names = {}
            claim_sources = {}
            for index, (claim, source) in enumerate(distributed.items(), start=1):
                if claim not in result or not isinstance(source, dict):
                    continue
                source_id = f"src{index}"
                claim_names[claim] = source_id
                claim_sources[source_id] = dict(source)
                result.pop(claim, None)
            if claim_names:
                result["_claim_names"] = claim_names
                result["_claim_sources"] = claim_sources
        return result

    def _current_user(self):
        session_auth_time = self.struct.session.get("oidc_auth_time", "")
        if session_auth_time:
            reviewops_profile = self._active_reviewops_profile()
            settings = self._profile_settings(reviewops_profile)
            ttl_seconds = int(settings.get("session_ttl_seconds", 28800) or 28800)
            auth_time = self._parse_datetime(session_auth_time)
            if auth_time is None or self._session_age_seconds(auth_time) >= ttl_seconds:
                self.struct.session.clear()
                return None

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
            user = self.struct.core.user.get(email=email)
            if user is not None and not self.struct.core.user.is_expired(user):
                return user
        return None

    def _session_age_seconds(self, auth_time):
        current = self._now()
        if auth_time.tzinfo is not None:
            auth_time = auth_time.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        if current.tzinfo is not None:
            current = current.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return max(0, (current - auth_time).total_seconds())

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

    def _active_reviewops_profile(self):
        try:
            return self.struct.provider.reviewops_profile()
        except ValueError as e:
            raise OIDCFlowError("invalid_request", str(e), 400)

    def _client_reviewops_profile(self, client):
        extra = self._normalize_object((client or {}).get("extra"), {})
        configured_profile = extra.get("reviewops_profile", "")
        if configured_profile is None:
            configured_profile = ""
        try:
            return self.struct.provider.reviewops_profile(configured_profile)
        except ValueError:
            raise OIDCFlowError("invalid_client", "RP의 reviewops_profile 설정이 올바르지 않습니다.", 401)

    def _require_matching_reviewops_profile(self, client):
        active_profile = self._active_reviewops_profile()
        client_profile = self._client_reviewops_profile(client)
        if active_profile != client_profile:
            raise OIDCFlowError("invalid_client", "RP와 요청 endpoint의 reviewops_profile이 일치하지 않습니다.", 401)
        return active_profile

    def _generate_debug_key(self):
        random_value = self.struct.core.db("idp_debug_payload").random(24)
        return f"oidc_{random_value}"

    def _write_debug_raw(self, key, payload):
        self._debug_fs().write.json(f"{key}.json", self._mask_value(payload))
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
            "summary": self._mask_value(dict(summary)),
            "raw_path": raw_path,
        })
        return key

    def _update_debug_entry(self, key, summary_updates=None, payload=None):
        row = self.struct.core.debug_payload.get(key=key) or {}
        summary = dict(row.get("summary", {}) or {})
        if isinstance(summary_updates, dict):
            summary.update(self._mask_value(summary_updates))

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
        if PKCE_VERIFIER_PATTERN.fullmatch(code_verifier) is None:
            raise OIDCFlowError(
                "invalid_request",
                "code_verifier는 43~128자의 RFC 7636 허용 문자로 입력해야 합니다.",
                400,
            )
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
        if client.get("expired") or client.get("active") is False:
            raise OIDCFlowError("invalid_client", "만료되었거나 비활성화된 RP입니다.", 400)
        reviewops_profile = self._require_matching_reviewops_profile(client)
        settings = self._profile_settings(reviewops_profile)

        prompt = str(params.get("prompt", "")).strip()
        prompt_values = prompt.split()
        if len(prompt_values) != len(set(prompt_values)):
            raise OIDCFlowError("invalid_request", "prompt 값은 중복할 수 없습니다.", 400)
        if "none" in prompt_values and len(prompt_values) > 1:
            raise OIDCFlowError("invalid_request", "prompt=none은 다른 prompt 값과 함께 사용할 수 없습니다.", 400)
        if any(value not in {"none", "login", "consent", "select_account"} for value in prompt_values):
            raise OIDCFlowError("invalid_request", "지원하지 않는 prompt 값입니다.", 400)
        if not str(params.get("user_id", "")).strip() and any(value in prompt_values for value in ["login", "select_account"]):
            raise OIDCFlowError("login_required", "새 사용자 인증이 필요합니다.", 401)
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
        if max_age:
            try:
                if int(max_age) < 0:
                    raise ValueError()
            except ValueError:
                raise OIDCFlowError("invalid_request", "max_age는 0 이상의 정수여야 합니다.", 400)
            session_auth_time = self._parse_datetime(self.struct.session.get("oidc_auth_time", ""))
            if not str(params.get("user_id", "")).strip() and (
                session_auth_time is None
                or self._session_age_seconds(session_auth_time) > int(max_age)
            ):
                raise OIDCFlowError("login_required", "max_age 이내의 사용자 인증이 필요합니다.", 401)
        acr_values = str(params.get("acr_values", "")).strip()
        preset_id = str(params.get("preset_id", "")).strip()
        code_challenge = str(params.get("code_challenge", "")).strip()
        code_challenge_method = str(params.get("code_challenge_method", "S256")).strip() or "S256"

        requested_scope_values = self._preview()._normalize_scope(scope_text)
        if "offline_access" in requested_scope_values:
            if "refresh_token" not in (client.get("grant_types") or []):
                raise OIDCFlowError(
                    "invalid_scope",
                    "offline_access scope에는 refresh_token grant 등록이 필요합니다.",
                    400,
                )
            if "consent" not in prompt_values:
                raise OIDCFlowError(
                    "consent_required",
                    "offline_access scope에는 prompt=consent가 필요합니다.",
                    400,
                )

        if code_challenge and code_challenge_method not in ["S256", "plain"]:
            raise OIDCFlowError("invalid_request", "지원하지 않는 code_challenge_method입니다.", 400)
        if client.get("token_endpoint_auth_method") == "none" and code_challenge == "":
            raise OIDCFlowError("invalid_request", "Public Client는 PKCE code_challenge가 필요합니다.", 400)
        if client.get("token_endpoint_auth_method") == "none" and code_challenge_method != "S256":
            allow_plain = bool((client.get("extra") or {}).get("allow_plain_pkce"))
            if not allow_plain:
                raise OIDCFlowError("invalid_request", "Public Client는 PKCE S256을 사용해야 합니다.", 400)
        if code_challenge_method == "plain" and code_challenge and PKCE_VERIFIER_PATTERN.fullmatch(code_challenge) is None:
            raise OIDCFlowError("invalid_request", "PKCE plain 값의 길이 또는 문자가 올바르지 않습니다.", 400)
        if code_challenge_method == "S256" and code_challenge and re.fullmatch(r"[A-Za-z0-9_-]{43}", code_challenge) is None:
            raise OIDCFlowError("invalid_request", "PKCE S256 code_challenge 형식이 올바르지 않습니다.", 400)

        release = self._build_claim_release(
            client,
            user,
            scope_text,
            params.get("claims", "{}"),
            preset_id=preset_id,
        )
        selected_acr = str(settings.get("acr", "") or "").strip()
        if not selected_acr and acr_values:
            selected_acr = acr_values.split()[0]
        acr_request = (release["claims_param"].get("id_token", {}) or {}).get("acr", {}) if isinstance(release["claims_param"], dict) else {}
        if isinstance(acr_request, dict) and acr_request.get("essential") is True:
            requested_acr = acr_request.get("values") or [acr_request.get("value")]
            requested_acr = [str(value) for value in requested_acr if value]
            if requested_acr and selected_acr not in requested_acr:
                raise OIDCFlowError("access_denied", "요청된 Essential ACR을 충족할 수 없습니다.", 403)
        warnings = []
        if code_challenge_method == "plain" and code_challenge:
            warnings.append("PKCE plain은 호환 시험으로 처리됩니다. 표준 프로필에서는 S256을 사용하세요.")
        if settings.get("response_variant", "standard") != "standard":
            warnings.append("표준과 다른 OIDC 응답 변형이 활성화되었습니다.")
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
        authorize_separator = "&" if "?" in authorize_url else "?"
        raw_authorize_url = f"{authorize_url}{authorize_separator}{urllib.parse.urlencode(authorize_url_payload, doseq=True)}"

        now = self._now()
        session_user_id = str(self.struct.session.get("id", "")).strip()
        explicit_user_id = str(params.get("user_id", "")).strip()
        same_session_user = bool(session_user_id and session_user_id == explicit_user_id)
        auth_time = (
            self._parse_datetime(self.struct.session.get("oidc_auth_time", ""))
            if same_session_user else None
        ) or now
        session_sid = (
            str(self.struct.session.get("oidc_sid", "")).strip()
            if same_session_user else ""
        ) or f"sid-{uuid.uuid4().hex}"
        code = f"code_{uuid.uuid4().hex[:24]}"
        expires = now + datetime.timedelta(minutes=10)
        redirect_payload = {"code": code, "iss": self.struct.provider.issuer(reviewops_profile)}
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
                    "auto_approved": "consent" not in prompt_values,
                    "explicit": "consent" in prompt_values,
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

        code_extra = {
            "prompt": prompt,
            "max_age": max_age,
            "acr_values": acr_values,
            "response_mode": response_mode,
            "preset_id": preset_id,
            "session_auth_time": auth_time.isoformat(),
            "session_sid": session_sid,
            "selected_acr": selected_acr,
        }
        if reviewops_profile:
            code_extra["reviewops_profile"] = reviewops_profile

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
            "extra": code_extra,
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
                "auto_approved": "consent" not in prompt_values,
                "explicit": "consent" in prompt_values,
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

    def end_session(self, params):
        """Validate an RP-Initiated Logout request without changing session state."""
        params = dict(params or {})
        explicit_client_id = str(params.get("client_id", "") or "").strip()
        id_token_hint = str(params.get("id_token_hint", "") or "").strip()
        logout_hint = str(params.get("logout_hint", "") or "").strip()
        requested_redirect = str(params.get("post_logout_redirect_uri", "") or "").strip()
        state = str(params.get("state", "") or "").strip()
        ui_locales = str(params.get("ui_locales", "") or "").strip()

        provider = self.struct.provider
        profile = self._active_reviewops_profile()
        expected_issuer = provider.issuer(profile)
        client = None
        decoded_hint = {}
        hint_valid = False
        hint_error = ""
        warnings = []

        if explicit_client_id:
            client = self.struct.registry.get(client_id=explicit_client_id)
            if client is None or client.get("expired") or client.get("active") is False:
                raise OIDCFlowError("invalid_request", "등록된 활성 RP를 찾을 수 없습니다.", 400)
            self._require_matching_reviewops_profile(client)

        if id_token_hint:
            hint_client_id = ""
            try:
                unverified = provider.decode_without_verify(id_token_hint)
                unverified_payload = unverified.get("payload", {})
                audience = unverified_payload.get("aud", [])
                audiences = audience if isinstance(audience, list) else [audience]
                audiences = [str(value) for value in audiences if str(value)]
                authorized_party = str(unverified_payload.get("azp", "") or "").strip()
                if explicit_client_id:
                    hint_client_id = explicit_client_id
                elif authorized_party and authorized_party in audiences:
                    hint_client_id = authorized_party
                elif len(audiences) == 1:
                    hint_client_id = audiences[0]
                else:
                    raise ValueError("id_token_hint의 RP를 하나로 확인할 수 없습니다.")

                hint_client = self.struct.registry.get(client_id=hint_client_id)
                if hint_client is None or hint_client.get("expired") or hint_client.get("active") is False:
                    raise ValueError("id_token_hint에 연결된 활성 RP를 찾을 수 없습니다.")
                self._require_matching_reviewops_profile(hint_client)
                decoded = provider.verify_jwt(
                    id_token_hint,
                    allowed_algs=["RS256", "PS256", "ES256", "HS256"],
                    secret=hint_client.get("client_secret", ""),
                    allow_expired=True,
                    expected_issuer=expected_issuer,
                )
                decoded_hint = decoded.get("payload", {})
                verified_audience = decoded_hint.get("aud", [])
                verified_audiences = verified_audience if isinstance(verified_audience, list) else [verified_audience]
                verified_audiences = [str(value) for value in verified_audiences]
                if hint_client_id not in verified_audiences:
                    raise ValueError("id_token_hint의 audience가 RP와 일치하지 않습니다.")
                verified_azp = str(decoded_hint.get("azp", "") or "").strip()
                if len(verified_audiences) > 1 and verified_azp != hint_client_id:
                    raise ValueError("여러 audience를 가진 id_token_hint에는 일치하는 azp가 필요합니다.")
                if int(decoded_hint.get("iat", 0) or 0) > int(time.time()) + 60:
                    raise ValueError("id_token_hint의 iat가 현재 시각보다 늦습니다.")
                if explicit_client_id and explicit_client_id != hint_client_id:
                    raise ValueError("client_id가 id_token_hint를 발급받은 RP와 일치하지 않습니다.")
                client = hint_client
                hint_valid = True
            except Exception as error:
                hint_error = str(error) or "id_token_hint를 검증하지 못했습니다."
                decoded_hint = {}
                warnings.append("id_token_hint를 신뢰할 수 없어 RP 복귀 주소를 사용하지 않습니다.")

        redirect_target = ""
        redirect_validation_error = ""
        if requested_redirect:
            if client is None:
                redirect_validation_error = "유효한 RP를 확인할 수 없어 post_logout_redirect_uri를 사용하지 않습니다."
            elif requested_redirect not in (client.get("post_logout_redirect_uris") or []):
                redirect_validation_error = "등록되지 않은 post_logout_redirect_uri는 사용하지 않습니다."
            elif not id_token_hint or hint_valid:
                redirect_target = requested_redirect
        if redirect_validation_error:
            warnings.append(redirect_validation_error)

        if redirect_target and state:
            parsed = urllib.parse.urlsplit(redirect_target)
            query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            query.append(("state", state))
            redirect_target = urllib.parse.urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), parsed.fragment)
            )

        current_user_id = str(self.struct.session.get("id", "") or "").strip()
        current_sid = str(self.struct.session.get("oidc_sid", "") or "").strip()
        hint_subject = str(decoded_hint.get("sub", "") or "").strip()
        hint_sid = str(decoded_hint.get("sid", "") or "").strip()
        user_match = bool(hint_valid and current_user_id and hint_subject == current_user_id)
        sid_match = bool(hint_valid and current_sid and hint_sid and hint_sid == current_sid)
        session_match = sid_match if current_sid and hint_sid else user_match
        logout_hint_match = bool(
            logout_hint
            and logout_hint in {
                current_user_id,
                current_sid,
                str(self.struct.session.get("username", "") or "").strip(),
                str(self.struct.session.get("email", "") or "").strip(),
            }
        )

        if id_token_hint and hint_valid and not session_match:
            warnings.append("id_token_hint가 현재 브라우저 세션과 일치하지 않아 사용자 확인이 필요합니다.")
        if logout_hint and not logout_hint_match:
            warnings.append("logout_hint가 현재 브라우저 세션과 일치하지 않습니다.")

        return {
            "client": self.struct.registry.public_view(client) if client is not None else None,
            "client_id": client.get("client_id", "") if client is not None else "",
            "decoded_id_token_hint": decoded_hint,
            "id_token_hint_valid": hint_valid,
            "id_token_hint_error": hint_error,
            "session_match": {
                "matched": session_match,
                "sid_match": sid_match,
                "user_match": user_match,
                "logout_hint_match": logout_hint_match,
            },
            "post_logout_redirect_uri": requested_redirect,
            "redirect_validation_error": redirect_validation_error,
            "redirect_target": redirect_target,
            "state": state,
            "ui_locales": ui_locales,
            "has_active_session": bool(current_user_id or current_sid),
            "confirmation_required": True,
            "standards_status": "rejected" if hint_error or redirect_validation_error else "standard",
            "warnings": warnings,
        }

    def _load_remote_jwks(self, uri):
        parsed = urllib.parse.urlparse(str(uri or ""))
        if parsed.scheme not in ["https", "http"] or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise OIDCFlowError("invalid_client", "원격 JWKS URL 형식이 올바르지 않습니다.", 401)
        try:
            addresses = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
            for address in addresses:
                ip = ipaddress.ip_address(address[4][0])
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                    raise OIDCFlowError("invalid_client", "원격 JWKS 주소가 허용되지 않습니다.", 401)
        except OIDCFlowError:
            raise
        except Exception:
            raise OIDCFlowError("invalid_client", "원격 JWKS 주소를 확인할 수 없습니다.", 401)
        request = urllib.request.Request(uri, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                if response.status != 200:
                    raise ValueError("unexpected status")
                content_length = int(response.headers.get("Content-Length", "0") or 0)
                if content_length > 256 * 1024:
                    raise ValueError("JWKS too large")
                raw = response.read(256 * 1024 + 1)
                if len(raw) > 256 * 1024:
                    raise ValueError("JWKS too large")
                data = json.loads(raw.decode("utf-8"))
        except Exception:
            raise OIDCFlowError("invalid_client", "원격 JWKS를 안전하게 읽지 못했습니다.", 401)
        return self.struct.registry._normalize_jwks(data)

    def _client_jwks(self, client):
        jwks = client.get("jwks")
        if isinstance(jwks, str):
            jwks = self._normalize_object(jwks, {})
        if isinstance(jwks, dict) and jwks.get("keys"):
            return jwks
        uri = str((client.get("extra") or {}).get("jwks_uri", "")).strip()
        if uri:
            return self._load_remote_jwks(uri)
        raise OIDCFlowError("invalid_client", "private_key_jwt 검증용 JWKS가 없습니다.", 401)

    def _verify_client_jws(self, assertion, client, expected_method):
        parts = str(assertion or "").split(".")
        if len(parts) != 3:
            raise OIDCFlowError("invalid_client", "client_assertion JWT 형식이 올바르지 않습니다.", 401)
        try:
            header = json.loads(_b64u_decode(parts[0]).decode("utf-8"))
            payload = json.loads(_b64u_decode(parts[1]).decode("utf-8"))
            signature = _b64u_decode(parts[2])
        except Exception:
            raise OIDCFlowError("invalid_client", "client_assertion JWT를 해석할 수 없습니다.", 401)
        alg = str(header.get("alg", ""))
        expected_algs = ["HS256"] if expected_method == "client_secret_jwt" else ["RS256", "PS256", "ES256"]
        if alg not in expected_algs:
            raise OIDCFlowError("invalid_client", "client_assertion signing algorithm이 허용되지 않습니다.", 401)
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        verified = False
        if alg == "HS256":
            expected = hmac.new(
                str(client.get("client_secret", "")).encode("utf-8"),
                signing_input,
                hashlib.sha256,
            ).digest()
            verified = hmac.compare_digest(expected, signature)
        else:
            kid = str(header.get("kid", ""))
            keys = self._client_jwks(client).get("keys", [])
            candidates = [
                jwk for jwk in keys
                if isinstance(jwk, dict)
                and (not kid or str(jwk.get("kid", "")) == kid)
                and (not jwk.get("alg") or jwk.get("alg") == alg)
            ]
            if not kid and len(candidates) != 1:
                raise OIDCFlowError("invalid_client", "client_assertion에 kid가 필요합니다.", 401)
            for jwk in candidates:
                try:
                    key = self.struct.provider.public_key_from_jwk(jwk)
                    if alg == "RS256":
                        key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
                    elif alg == "PS256":
                        key.verify(
                            signature,
                            signing_input,
                            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                            hashes.SHA256(),
                        )
                    else:
                        if len(signature) != 64:
                            raise ValueError("invalid ES256 signature")
                        der = encode_dss_signature(
                            int.from_bytes(signature[:32], "big"),
                            int.from_bytes(signature[32:], "big"),
                        )
                        key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
                    verified = True
                    break
                except Exception:
                    continue
        if not verified:
            raise OIDCFlowError("invalid_client", "client_assertion signature 검증에 실패했습니다.", 401)
        return payload

    def _remember_client_assertion(self, client_id, jti, expires):
        key = hashlib.sha256(f"{client_id}:{jti}".encode("utf-8")).hexdigest()
        path = f"client-assertion-{key}.json"
        fs = self.struct.provider._fs()
        if fs.exists(path):
            previous = fs.read.json(path, default={})
            if int(previous.get("expires", 0) or 0) >= int(time.time()):
                raise OIDCFlowError("invalid_client", "이미 사용된 client_assertion입니다.", 401)
        fs.write.json(path, {"client_id": client_id, "jti_sha256": key, "expires": int(expires)}, indent=2)

    def _validate_client_assertion(self, assertion, assertion_type, client, expected_method):
        if assertion_type != CLIENT_ASSERTION_TYPE:
            raise OIDCFlowError("invalid_client", "client_assertion_type이 올바르지 않습니다.", 401)
        payload = self._verify_client_jws(assertion, client, expected_method)
        client_id = str(client.get("client_id", ""))
        if payload.get("iss") != client_id or payload.get("sub") != client_id:
            raise OIDCFlowError("invalid_client", "client_assertion의 iss와 sub가 client_id와 일치해야 합니다.", 401)
        audience = payload.get("aud", [])
        audience = audience if isinstance(audience, list) else [audience]
        info = self.struct.provider.info()
        if not set(audience).intersection({info["token_endpoint"], info["issuer"]}):
            raise OIDCFlowError("invalid_client", "client_assertion audience가 token endpoint와 일치하지 않습니다.", 401)
        now = int(time.time())
        try:
            issued = int(payload["iat"])
            expires = int(payload["exp"])
        except Exception:
            raise OIDCFlowError("invalid_client", "client_assertion에는 정수 iat와 exp가 필요합니다.", 401)
        if issued > now + 60 or expires < now - 60 or expires <= issued or expires - issued > 300:
            raise OIDCFlowError("invalid_client", "client_assertion 유효 시간이 허용 범위를 벗어났습니다.", 401)
        jti = str(payload.get("jti", "")).strip()
        if not jti or len(jti) > 255:
            raise OIDCFlowError("invalid_client", "client_assertion에는 올바른 jti가 필요합니다.", 401)
        self._remember_client_assertion(client_id, jti, expires)

    def _authenticate_client(self, request_data, auth_header=""):
        request_data = dict(request_data or {})
        auth_header = str(auth_header or "").strip()
        provided_client_id = str(request_data.get("client_id", "")).strip()
        provided_client_secret = str(request_data.get("client_secret", "")).strip()
        assertion = str(request_data.get("client_assertion", "")).strip()
        assertion_type = str(request_data.get("client_assertion_type", "")).strip()
        used_method = ""

        if auth_header and not auth_header.lower().startswith("basic "):
            raise OIDCFlowError("invalid_client", "지원하지 않는 Authorization 방식입니다.", 401)
        if assertion and (auth_header or provided_client_secret):
            raise OIDCFlowError("invalid_client", "client authentication 방식을 하나만 사용하세요.", 401)

        if auth_header.lower().startswith("basic "):
            used_method = "client_secret_basic"
            try:
                decoded = base64.b64decode(auth_header.split(" ", 1)[1]).decode("utf-8")
                provided_client_id, provided_client_secret = decoded.split(":", 1)
                provided_client_id = urllib.parse.unquote(provided_client_id)
                provided_client_secret = urllib.parse.unquote(provided_client_secret)
            except Exception:
                raise OIDCFlowError("invalid_client", "Authorization Basic 헤더가 올바르지 않습니다.", 401)
        elif assertion:
            used_method = "jwt"
        elif provided_client_secret:
            used_method = "client_secret_post"
        else:
            used_method = "none"

        if provided_client_id == "":
            raise OIDCFlowError("invalid_client", "client_id가 필요합니다.", 401)

        client = self.struct.registry.get(client_id=provided_client_id)
        if client is None:
            raise OIDCFlowError("invalid_client", "등록되지 않은 client_id입니다.", 401)
        self._require_matching_reviewops_profile(client)
        if client.get("expired") or client.get("active") is False:
            raise OIDCFlowError("invalid_client", "만료되었거나 비활성화된 RP입니다.", 401)

        expected_method = str(client.get("token_endpoint_auth_method", "client_secret_basic")).strip() or "client_secret_basic"
        if expected_method in ["client_secret_jwt", "private_key_jwt"]:
            if used_method != "jwt":
                raise OIDCFlowError("invalid_client", "등록된 JWT client authentication 방식이 필요합니다.", 401)
            self._validate_client_assertion(assertion, assertion_type, client, expected_method)
            return client, expected_method

        if expected_method == "none":
            if auth_header or provided_client_secret or assertion:
                raise OIDCFlowError("invalid_client", "Public Client는 client credential을 보낼 수 없습니다.", 401)
            return client, "none"

        if expected_method != used_method:
            raise OIDCFlowError("invalid_client", "RP에 등록된 client authentication 방식과 요청이 일치하지 않습니다.", 401)
        if not hmac.compare_digest(provided_client_secret, str(client.get("client_secret", ""))):
            raise OIDCFlowError("invalid_client", "client secret이 올바르지 않습니다.", 401)
        return client, used_method

    def _verify_pkce(self, code_row, code_verifier):
        code_challenge = str(code_row.get("code_challenge", "")).strip()
        if code_challenge == "":
            return

        code_verifier = str(code_verifier or "").strip()
        if code_verifier == "":
            raise OIDCFlowError("invalid_grant", "code_verifier가 필요합니다.", 400)
        if PKCE_VERIFIER_PATTERN.fullmatch(code_verifier) is None:
            raise OIDCFlowError("invalid_grant", "code_verifier 길이 또는 문자가 올바르지 않습니다.", 400)

        method = str(code_row.get("code_challenge_method", "S256")).strip() or "S256"
        expected = self.generate_code_challenge(code_verifier, method)
        if not hmac.compare_digest(expected, code_challenge):
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

    def _revoke_refresh_descendants(self, parent_jti, revoked_at=None):
        """Consume every issued descendant after refresh-token reuse is detected."""
        parent_jti = str(parent_jti or "").strip()
        if not parent_jti:
            return 0
        revoked_at = revoked_at or self._now()
        database = self._token_db()
        pending = [parent_jti]
        visited = set()
        revoked = 0
        while pending and len(visited) < 100:
            current = pending.pop()
            if current in visited:
                continue
            visited.add(current)
            for child in database.rows(refresh_token_parent_jti=current):
                child_jti = str(child.get("refresh_token_jti", "")).strip()
                if self._parse_datetime(child.get("refresh_token_consumed")) is None:
                    database.update(
                        {"refresh_token_consumed": revoked_at},
                        id=child.get("id"),
                        refresh_token_consumed=None,
                    )
                    revoked += 1
                if child_jti:
                    pending.append(child_jti)
        return revoked

    def _refresh_token_grant(self, request_data, client, used_method):
        refresh_token = str(request_data.get("refresh_token", "")).strip()
        if not refresh_token:
            raise OIDCFlowError("invalid_grant", "refresh_token이 필요합니다.", 400)
        if "refresh_token" not in (client.get("grant_types") or []):
            raise OIDCFlowError("unauthorized_client", "이 RP는 refresh_token grant를 허용하지 않습니다.", 400)

        provider = self.struct.provider
        profile_name = self._active_reviewops_profile()
        try:
            decoded = provider.verify_jwt(
                refresh_token,
                allowed_algs=["RS256"],
                expected_issuer=provider.issuer(profile_name),
            )
        except Exception:
            raise OIDCFlowError("invalid_grant", "refresh token signature 또는 유효 시간이 올바르지 않습니다.", 400)

        payload = decoded.get("payload", {}) if isinstance(decoded, dict) else {}
        audience = payload.get("aud", [])
        audiences = audience if isinstance(audience, list) else [audience]
        if payload.get("token_use") != "refresh_token" or client.get("client_id") not in audiences:
            raise OIDCFlowError("invalid_grant", "다른 용도 또는 RP의 refresh token입니다.", 400)

        refresh_jti = str(payload.get("jti", "")).strip()
        if not refresh_jti:
            raise OIDCFlowError("invalid_grant", "refresh token jti가 없습니다.", 400)
        row = self._token_db().get(refresh_token_jti=refresh_jti)
        if row is None or row.get("client_id") != client.get("client_id"):
            raise OIDCFlowError("invalid_grant", "등록되지 않은 refresh token입니다.", 400)
        if self._parse_datetime(row.get("refresh_token_consumed")) is not None:
            self._revoke_refresh_descendants(refresh_jti)
            raise OIDCFlowError("invalid_grant", "이미 사용된 refresh token입니다.", 400)
        refresh_expires = self._parse_datetime(row.get("refresh_token_expires"))
        if refresh_expires is not None and refresh_expires <= self._now():
            raise OIDCFlowError("invalid_grant", "만료된 refresh token입니다.", 400)

        original_scopes = [item for item in str(payload.get("scope", "")).split() if item]
        requested_scope = str(request_data.get("scope", "")).strip()
        requested_scopes = [item for item in requested_scope.split() if item] if requested_scope else original_scopes
        if not requested_scopes or not set(requested_scopes).issubset(set(original_scopes)):
            raise OIDCFlowError("invalid_scope", "refresh 요청 scope는 최초 scope의 일부여야 합니다.", 400)
        scope = " ".join(requested_scopes)

        user = self.struct.core.user.get(id=row.get("user_id", ""))
        if user is None or self.struct.core.user.is_expired(user):
            raise OIDCFlowError("invalid_grant", "refresh token에 연결된 사용자를 찾을 수 없거나 만료되었습니다.", 400)

        # Claim the token before issuing its replacement. Including the NULL
        # predicate makes concurrent exchanges a compare-and-set operation.
        consumed_at = self._now()
        self._token_db().update(
            {"refresh_token_consumed": consumed_at},
            id=row.get("id"),
            refresh_token_consumed=None,
        )
        claimed = self._token_db().get(id=row.get("id"))
        claimed_at = self._parse_datetime((claimed or {}).get("refresh_token_consumed"))
        if claimed_at != consumed_at:
            self._revoke_refresh_descendants(refresh_jti, revoked_at=consumed_at)
            raise OIDCFlowError("invalid_grant", "이미 사용된 refresh token입니다.", 400)

        previous_raw = self._normalize_object(row.get("raw_response"), {})
        userinfo = self._normalize_object(previous_raw.get("userinfo"), {})
        subject = str(payload.get("sub", "")).strip()
        if not subject:
            raise OIDCFlowError("invalid_grant", "refresh token subject가 없습니다.", 400)
        if not userinfo:
            userinfo = self._build_userinfo(user, {"sub": subject})
        userinfo["sub"] = subject

        settings = self._profile_settings(profile_name)
        access_issued = provider.issue_access_token(
            client.get("client_id", ""),
            subject,
            scope=scope,
            extra_claims={
                "client_id": client.get("client_id", ""),
                "username": user.get("username", ""),
                "claims": userinfo,
            },
            time_offset_seconds=settings.get("time_offset_seconds", 0),
            reviewops_profile=profile_name,
        )
        previous_id_token = self._normalize_object(previous_raw.get("id_token_payload"), {})
        id_token_claims = {
            key: value
            for key, value in userinfo.items()
            if key not in {"sub", "iss", "aud", "exp", "iat", "auth_time", "jti", "sid", "nonce", "at_hash"}
        }
        signing_alg = str(settings.get("id_token_signing_alg", "RS256"))
        if signing_alg == "HS256" and client.get("token_endpoint_auth_method") == "none":
            raise OIDCFlowError("invalid_request", "Public Client에는 HS256 ID Token을 발급할 수 없습니다.", 400)
        id_issued = provider.issue_id_token(
            client.get("client_id", ""),
            subject,
            extra_claims=id_token_claims,
            ttl_seconds=settings.get("token_ttl_seconds", 600),
            auth_time=previous_id_token.get("auth_time"),
            sid=str(previous_id_token.get("sid", "")),
            acr=str(previous_id_token.get("acr", "") or settings.get("acr", "")),
            amr=previous_id_token.get("amr") or settings.get("amr", ["pwd"]),
            access_token=access_issued["token"],
            signing_alg=signing_alg,
            signing_secret=client.get("client_secret", ""),
            response_variant=settings.get("response_variant", "standard"),
            time_offset_seconds=settings.get("time_offset_seconds", 0),
            reviewops_profile=profile_name,
        )
        refresh_issued = provider.issue_refresh_token(
            client.get("client_id", ""),
            subject,
            scope=scope,
            ttl_seconds=settings.get("refresh_token_ttl_seconds", 2592000),
            parent_jti=refresh_jti,
            reviewops_profile=profile_name,
        )

        token_response = {
            "access_token": access_issued["token"],
            "id_token": id_issued["token"],
            "refresh_token": refresh_issued["token"],
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": scope,
        }
        now = self._now()
        self._token_db().insert({
            "client_id": client.get("client_id", ""),
            "user_id": user.get("id", ""),
            "grant_type": "refresh_token",
            "access_token_jti": access_issued["payload"].get("jti", ""),
            "id_token_jti": id_issued["payload"].get("jti", ""),
            "refresh_token_jti": refresh_issued["payload"].get("jti", ""),
            "refresh_token_parent_jti": refresh_jti,
            "refresh_token_expires": datetime.datetime.fromtimestamp(
                int(refresh_issued["payload"]["exp"]), datetime.timezone.utc
            ).replace(tzinfo=None),
            "refresh_token_consumed": None,
            "debug_key": row.get("debug_key", ""),
            "raw_request": self._mask_value({
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client.get("client_id", ""),
                "client_auth_method": used_method,
                "scope": scope,
            }),
            "raw_response": {
                "token_response": self._mask_value(token_response),
                "access_token_payload": access_issued["payload"],
                "id_token_payload": id_issued["payload"],
                "userinfo": userinfo,
            },
            "created": now,
        })
        return {
            "request": {
                "grant_type": "refresh_token",
                "client_id": client.get("client_id", ""),
                "client_auth_method": used_method,
                "scope": scope,
            },
            "token_response": token_response,
            "id_token": id_issued["token"],
            "id_token_payload": id_issued["payload"],
            "access_token_payload": access_issued["payload"],
            "userinfo": userinfo,
            "debug_key": row.get("debug_key", ""),
        }

    def token(self, request_data, auth_header=""):
        request_data = dict(request_data or {})
        grant_type = str(request_data.get("grant_type", "authorization_code")).strip() or "authorization_code"
        client, used_method = self._authenticate_client(request_data, auth_header=auth_header)
        if grant_type == "refresh_token":
            return self._refresh_token_grant(request_data, client, used_method)
        if grant_type != "authorization_code":
            raise OIDCFlowError(
                "unsupported_grant_type",
                "authorization_code와 refresh_token grant만 지원합니다.",
                400,
            )
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

        code_extra = self._normalize_object(code_row.get("extra"), {})
        code_profile = str(code_extra.get("reviewops_profile", ""))
        if code_profile != self._active_reviewops_profile():
            raise OIDCFlowError("invalid_grant", "authorization code의 reviewops_profile이 token endpoint와 일치하지 않습니다.", 400)

        self._verify_pkce(code_row, code_verifier)

        user = self.struct.core.user.get(id=code_row.get("user_id", ""))
        if user is None or self.struct.core.user.is_expired(user):
            raise OIDCFlowError("invalid_grant", "사용자를 찾을 수 없거나 만료되었습니다.", 400)

        released_claims = self._normalize_object(code_row.get("released_claims"), {})
        extra = code_extra
        scope = str(code_row.get("scope", "")).strip()
        provider = self.struct.provider
        profile_name = str(extra.get("reviewops_profile", ""))
        settings = self._profile_settings(profile_name)
        merged_subject_claims = dict(released_claims)
        merged_subject_claims.update(settings.get("claim_overrides", {}) or {})
        subject_source = str(settings.get("subject_source", "sub") or "sub")
        subject = self._claim_path(merged_subject_claims, subject_source, user.get("id", ""))
        if isinstance(subject, (dict, list)) or not str(subject).strip():
            raise OIDCFlowError("invalid_request", "OIDC subject_source 결과는 비어 있지 않은 문자열이어야 합니다.", 400)
        subject = str(subject)
        id_token_claims = self._apply_profile_claims(released_claims, settings, "id_token")
        id_token_claims.pop("sub", None)
        userinfo_claims = self._apply_profile_claims(released_claims, settings, "userinfo")
        userinfo_claims["sub"] = subject
        signing_alg = str(settings.get("id_token_signing_alg", "RS256"))
        if signing_alg == "HS256" and client.get("token_endpoint_auth_method") == "none":
            raise OIDCFlowError("invalid_request", "Public Client에는 HS256 ID Token을 발급할 수 없습니다.", 400)

        access_issued = provider.issue_access_token(
            client.get("client_id", ""),
            subject,
            scope=scope,
            extra_claims={
                "client_id": client.get("client_id", ""),
                "username": user.get("username", ""),
                "claims": userinfo_claims,
            },
            time_offset_seconds=settings.get("time_offset_seconds", 0),
            reviewops_profile=profile_name,
        )
        auth_time = self._parse_datetime(extra.get("session_auth_time")) or self._parse_datetime(code_row.get("auth_time")) or self._now()
        auth_time_epoch = int(auth_time.replace(tzinfo=datetime.timezone.utc).timestamp()) if auth_time.tzinfo is None else int(auth_time.timestamp())
        id_issued = provider.issue_id_token(
            client.get("client_id", ""),
            subject,
            extra_claims=id_token_claims,
            nonce=str(code_row.get("nonce", "")).strip(),
            ttl_seconds=settings.get("token_ttl_seconds", 600),
            auth_time=auth_time_epoch,
            sid=str(extra.get("session_sid", "")),
            acr=str(extra.get("selected_acr", "") or settings.get("acr", "")),
            amr=settings.get("amr", ["pwd"]),
            access_token=access_issued["token"],
            signing_alg=signing_alg,
            signing_secret=client.get("client_secret", ""),
            response_variant=settings.get("response_variant", "standard"),
            time_offset_seconds=settings.get("time_offset_seconds", 0),
            reviewops_profile=profile_name,
        )
        userinfo = self._build_userinfo(user, userinfo_claims)
        userinfo["sub"] = subject

        refresh_issued = None
        if (
            "offline_access" in scope.split()
            and "refresh_token" in (client.get("grant_types") or [])
        ):
            refresh_issued = provider.issue_refresh_token(
                client.get("client_id", ""),
                subject,
                scope=scope,
                ttl_seconds=settings.get("refresh_token_ttl_seconds", 2592000),
                reviewops_profile=profile_name,
            )

        token_response = {
            "access_token": access_issued["token"],
            "id_token": id_issued["token"],
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": scope,
        }
        if refresh_issued is not None:
            token_response["refresh_token"] = refresh_issued["token"]
        request_view = {
            "grant_type": grant_type,
            "code": code_value,
            "redirect_uri": redirect_uri,
            "client_id": client.get("client_id", ""),
            "client_auth_method": used_method,
        }
        if code_verifier:
            request_view["code_verifier_fingerprint"] = hashlib.sha256(
                code_verifier.encode("utf-8")
            ).hexdigest()[:16]

        now = self._now()
        self._token_db().insert({
            "client_id": client.get("client_id", ""),
            "user_id": user.get("id", ""),
            "grant_type": grant_type,
            "access_token_jti": access_issued["payload"].get("jti", ""),
            "id_token_jti": id_issued["payload"].get("jti", ""),
            "refresh_token_jti": (
                refresh_issued["payload"].get("jti", "")
                if refresh_issued is not None else ""
            ),
            "refresh_token_parent_jti": "",
            "refresh_token_expires": (
                datetime.datetime.fromtimestamp(
                    int(refresh_issued["payload"]["exp"]), datetime.timezone.utc
                ).replace(tzinfo=None)
                if refresh_issued is not None else None
            ),
            "refresh_token_consumed": None,
            "debug_key": code_row.get("debug_key", ""),
            "raw_request": self._mask_value(request_view),
            "raw_response": {
                "token_response": self._mask_value(token_response),
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
            decoded = self.struct.provider.verify_jwt(
                access_token,
                allowed_algs=["RS256"],
                expected_issuer=self.struct.provider.issuer(),
            )
        except Exception:
            raise OIDCFlowError("invalid_token", "access token signature 또는 유효 시간이 올바르지 않습니다.", 401)

        payload = decoded.get("payload", {}) if isinstance(decoded, dict) else {}
        if payload.get("token_use") != "access_token":
            raise OIDCFlowError("invalid_token", "access token이 아닙니다.", 401)
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
        elif auth_method == "client_secret_jwt":
            token_request["client_id"] = client.get("client_id", "")
            now = int(time.time())
            token_request["client_assertion_type"] = CLIENT_ASSERTION_TYPE
            token_request["client_assertion"] = self.struct.provider.sign_jwt(
                {
                    "iss": client.get("client_id", ""),
                    "sub": client.get("client_id", ""),
                    "aud": self.struct.provider.info()["token_endpoint"],
                    "iat": now,
                    "exp": now + 120,
                    "jti": f"sim-{uuid.uuid4().hex}",
                },
                headers={"alg": "HS256"},
                secret=client.get("client_secret", ""),
            )
        elif auth_method == "private_key_jwt":
            raise OIDCFlowError(
                "invalid_client",
                "private_key_jwt 시뮬레이션은 RP private key를 보관하지 않으므로 token endpoint에서 직접 검증하세요.",
                400,
            )
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
