import datetime
import json


DEFAULT_GRANT_TYPES = ["authorization_code", "refresh_token"]
DEFAULT_RESPONSE_TYPES = ["code"]
DEFAULT_SCOPE_POLICY = ["openid", "profile", "email"]


class Registry:
    def __init__(self, struct):
        self.struct = struct

    def db(self):
        return self.struct.db("oidc_rp_client")

    def _run_with_recovery(self, callback):
        try:
            return callback()
        except Exception as e:
            if self.struct.should_repair_storage(e) and self.struct.repair_storage():
                return callback()
            raise

    def _rows(self, **kwargs):
        return self._run_with_recovery(lambda: self.db().rows(**kwargs))

    def _get_row(self, **kwargs):
        return self._run_with_recovery(lambda: self.db().get(**kwargs))

    def _insert_row(self, data):
        return self._run_with_recovery(lambda: self.db().insert(data))

    def _update_row(self, data, **where):
        return self._run_with_recovery(lambda: self.db().update(data, **where))

    def _delete_row(self, **where):
        return self._run_with_recovery(lambda: self.db().delete(**where))

    def auth_method_options(self):
        return [
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
            "none",
        ]

    def grant_type_options(self):
        return [
            "authorization_code",
            "refresh_token",
            "implicit",
            "client_credentials",
        ]

    def response_type_options(self):
        return [
            "code",
            "id_token",
            "token",
            "code id_token",
            "code token",
            "id_token token",
            "code id_token token",
        ]

    def scope_options(self):
        return [
            "openid",
            "profile",
            "email",
            "groups",
            "address",
            "phone",
            "offline_access",
        ]

    def _protected_client_ids(self):
        try:
            config = wiz.config("idp")
            return list(getattr(config, "PROTECTED_OIDC_CLIENT_IDS", []) or [])
        except Exception:
            return []

    def _get_ttl_hours(self):
        try:
            config = wiz.config("idp")
            return int(getattr(config, "OIDC_RP_TTL_HOURS", getattr(config, "TEMPORARY_ACCOUNT_TTL_HOURS", 24)) or 24)
        except Exception:
            return 24

    def _parse_datetime(self, value):
        if value in [None, ""]:
            return None
        if isinstance(value, str):
            try:
                return datetime.datetime.fromisoformat(value)
            except Exception:
                return None
        return value

    def _normalize_list(self, value):
        if value is None:
            return []
        if isinstance(value, list):
            items = value
        else:
            text = str(value).strip()
            if text == "":
                return []
            try:
                parsed = json.loads(text)
                if isinstance(parsed, list):
                    items = parsed
                else:
                    items = [parsed]
            except Exception:
                items = []
                for line in text.replace("\r", "\n").split("\n"):
                    for chunk in line.split(","):
                        items.append(chunk)

        result = []
        seen = set()
        for item in items:
            value = str(item).strip()
            if value == "" or value in seen:
                continue
            seen.add(value)
            result.append(value)
        return result

    def _normalize_object(self, value, default=None):
        if default is None:
            default = {}
        if value in [None, ""]:
            return default
        if isinstance(value, dict):
            return value
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
        return default

    def _normalize_jwks(self, value):
        if value in [None, ""]:
            return None
        if isinstance(value, dict):
            return value
        try:
            parsed = json.loads(value)
        except Exception:
            raise Exception("JWKS JSON 형식이 올바르지 않습니다.")
        if not isinstance(parsed, dict):
            raise Exception("JWKS는 JSON 객체여야 합니다.")
        return parsed

    def _serialize(self, row):
        if row is None:
            return None
        item = dict(row)
        for key in [
            "redirect_uris",
            "post_logout_redirect_uris",
            "grant_types",
            "response_types",
            "scope_policy",
            "claims_policy",
            "jwks",
            "extra",
        ]:
            value = item.get(key)
            if isinstance(value, str):
                try:
                    item[key] = json.loads(value)
                except Exception:
                    item[key] = [] if key != "extra" else {}

        for key in ["created", "updated"]:
            value = item.get(key)
            if value and hasattr(value, "isoformat"):
                item[key] = value.isoformat()

        value = item.get("expires")
        if value and hasattr(value, "isoformat"):
            item["expires"] = value.isoformat()

        item["public_client"] = item.get("token_endpoint_auth_method") == "none"
        item["protected"] = item.get("client_id") in self._protected_client_ids()
        item["can_delete"] = item["protected"] is False
        item["expired"] = self.is_expired(item)
        return item

    def is_expired(self, row):
        expires = self._parse_datetime(row.get("expires"))
        if expires is None:
            return False
        return expires < datetime.datetime.now()

    def list(self):
        rows = self._rows(orderby="-created")
        return [self._serialize(row) for row in rows]

    def get(self, id=None, client_id=None):
        if id:
            return self._serialize(self._get_row(id=id))
        if client_id:
            return self._serialize(self._get_row(client_id=client_id))
        raise Exception("id or client_id required")

    def _build_payload(self, item, current=None):
        current = dict(current or {})

        client_name = str(item.get("client_name", current.get("client_name", ""))).strip()
        if client_name == "":
            raise Exception("client_name은 필수입니다.")

        redirect_uris = self._normalize_list(item.get("redirect_uris"))
        if len(redirect_uris) == 0:
            raise Exception("redirect_uri를 하나 이상 입력해주세요.")

        post_logout_redirect_uris = self._normalize_list(item.get("post_logout_redirect_uris"))
        grant_types = self._normalize_list(item.get("grant_types")) or list(DEFAULT_GRANT_TYPES)
        response_types = self._normalize_list(item.get("response_types")) or list(DEFAULT_RESPONSE_TYPES)
        scope_policy = self._normalize_list(item.get("scope_policy")) or list(DEFAULT_SCOPE_POLICY)
        claims_policy = self._normalize_list(item.get("claims_policy"))

        token_endpoint_auth_method = str(item.get("token_endpoint_auth_method", current.get("token_endpoint_auth_method", "client_secret_basic"))).strip() or "client_secret_basic"
        public_client = str(item.get("public_client", "false")).lower() in ["1", "true", "yes", "on"]

        if token_endpoint_auth_method not in self.auth_method_options():
            raise Exception("지원하지 않는 client authentication 방식입니다.")

        if public_client or token_endpoint_auth_method == "none":
            token_endpoint_auth_method = "none"
            public_client = True

        jwks = self._normalize_jwks(item.get("jwks"))
        extra = self._normalize_object(current.get("extra"), {})
        extra.update(self._normalize_object(item.get("extra"), {}))

        jwks_uri = str(item.get("jwks_uri", "")).strip()
        extra.pop("jwks_uri", None)
        extra.pop("warning_public_flow", None)

        if jwks_uri:
            extra["jwks_uri"] = jwks_uri

        if public_client and any(resp in ["token", "id_token token"] for resp in response_types):
            extra["warning_public_flow"] = "public client with front-channel tokens"

        if str(extra.get("notes", "")).strip() == "":
            extra.pop("notes", None)

        return {
            "client_name": client_name,
            "redirect_uris": redirect_uris,
            "post_logout_redirect_uris": post_logout_redirect_uris,
            "grant_types": grant_types,
            "response_types": response_types,
            "scope_policy": scope_policy,
            "claims_policy": claims_policy,
            "token_endpoint_auth_method": token_endpoint_auth_method,
            "jwks": jwks,
            "extra": extra,
            "public_client": public_client,
        }

    def register(self, data):
        item = dict(data)
        payload = self._build_payload(item)

        now = datetime.datetime.now()
        db = self.db()
        client_id = f"rp_{db.random(20)}"
        client_secret = "" if payload["public_client"] else f"secret_{db.random(32)}"
        protected = client_id in self._protected_client_ids()
        expires = None if protected else now + datetime.timedelta(hours=self._get_ttl_hours())

        payload.pop("public_client", None)
        data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "expires": expires,
            "created": now,
            "updated": now,
        }
        data.update(payload)
        self._insert_row(data)
        return self.get(client_id=client_id)

    def update(self, id, data):
        current = self.get(id=id)
        if current is None:
            raise Exception("등록된 RP를 찾을 수 없습니다.")

        payload = self._build_payload(dict(data), current=current)
        now = datetime.datetime.now()
        client_secret = current.get("client_secret", "")

        if payload["public_client"]:
            client_secret = ""
        elif client_secret == "":
            client_secret = f"secret_{self.db().random(32)}"

        payload.pop("public_client", None)
        payload["client_secret"] = client_secret
        payload["updated"] = now
        self._update_row(payload, id=id)
        return self.get(id=id)

    def extend_validity(self, id, ttl_hours=None):
        item = self.get(id=id)
        if item.get("expires") is None:
            raise Exception("이미 영구 보관 중인 RP입니다.")

        if ttl_hours is None:
            ttl_hours = self._get_ttl_hours()
        ttl_hours = int(ttl_hours)
        if ttl_hours <= 0:
            raise Exception("ttl_hours는 1 이상이어야 합니다.")

        now = datetime.datetime.now()
        current_expires = self._parse_datetime(item.get("expires"))
        baseline = current_expires if current_expires and current_expires > now else now
        expires = baseline + datetime.timedelta(hours=ttl_hours)
        self._update_row({
            "expires": expires,
            "updated": now,
        }, id=id)
        return self.get(id=id)

    def set_unlimited(self, id):
        item = self.get(id=id)
        if item.get("expires") is None:
            return item

        now = datetime.datetime.now()
        self._update_row({
            "expires": None,
            "updated": now,
        }, id=id)
        return self.get(id=id)

    def delete(self, id):
        item = self.get(id=id)
        if item.get("protected"):
            raise Exception("보호된 RP는 삭제할 수 없습니다.")
        self._delete_row(id=id)
        return True


Model = Registry