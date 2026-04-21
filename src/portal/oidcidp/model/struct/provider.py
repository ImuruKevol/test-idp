import base64
import datetime
import json
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def _b64u(data):
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64u_int(value):
    length = max(1, (int(value).bit_length() + 7) // 8)
    return _b64u(int(value).to_bytes(length, "big"))


class Provider:
    def __init__(self, struct):
        self.struct = struct

    def _config(self):
        try:
            return wiz.config("idp")
        except Exception:
            return None

    def _fs(self):
        return wiz.project.fs("metadata", "oidc")

    def _path(self, key, fallback):
        config = self._config()
        if config is None:
            return fallback
        try:
            value = getattr(config, key)
        except Exception:
            value = fallback
        return str(value or fallback)

    def issuer(self):
        config = self._config()
        issuer = ""
        if config is not None:
            try:
                issuer = str(getattr(config, "OIDC_ISSUER", "") or "").strip()
            except Exception:
                issuer = ""
        if issuer:
            return issuer.rstrip("/")

        host = wiz.request.headers("Host", "localhost:3034")
        scheme = wiz.request.headers("X-Forwarded-Proto", "http")
        return f"{scheme}://{host}".rstrip("/")

    def _jwk_pair(self, key, kid):
        public_numbers = key.public_key().public_numbers()
        private_numbers = key.private_numbers()
        public_jwk = {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": _b64u_int(public_numbers.n),
            "e": _b64u_int(public_numbers.e),
        }
        private_jwk = dict(public_jwk)
        private_jwk.update({
            "d": _b64u_int(private_numbers.d),
            "p": _b64u_int(private_numbers.p),
            "q": _b64u_int(private_numbers.q),
            "dp": _b64u_int(private_numbers.dmp1),
            "dq": _b64u_int(private_numbers.dmq1),
            "qi": _b64u_int(private_numbers.iqmp),
        })
        return public_jwk, private_jwk

    def ensure_keys(self):
        fs = self._fs()
        if fs.exists("jwks_public.json") and fs.exists("signing-key.pem"):
            return

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        kid = f"oidc-{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        public_jwk, private_jwk = self._jwk_pair(key, kid)

        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        fs.write("signing-key.pem", private_pem)
        fs.write.json("jwks_public.json", {"keys": [public_jwk]})
        fs.write.json("jwks_private.json", {"keys": [private_jwk]})

    def jwks_public(self):
        self.ensure_keys()
        return self._fs().read.json("jwks_public.json", default={"keys": []})

    def jwks_private(self):
        self.ensure_keys()
        return self._fs().read.json("jwks_private.json", default={"keys": []})

    def _private_key(self):
        self.ensure_keys()
        pem = self._fs().read("signing-key.pem")
        return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)

    def supported_scopes(self):
        return self.struct.registry.scope_options()

    def supported_claims(self):
        base_claims = [
            "sub",
            "preferred_username",
            "name",
            "email",
            "email_verified",
            "groups",
            "profile",
            "organization",
            "department",
            "zoneinfo",
        ]
        seen = set(base_claims)
        presets = self.struct.core.attribute_preset.list(protocol="oidc")
        for preset in presets:
            payload = preset.get("payload", {})
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except Exception:
                    payload = {}
            claims = payload.get("claims", {}) if isinstance(payload, dict) else {}
            if not isinstance(claims, dict):
                continue
            for key in claims.keys():
                key = str(key).strip()
                if key and key not in seen:
                    base_claims.append(key)
                    seen.add(key)
        return base_claims

    def info(self):
        issuer = self.issuer()
        discovery_path = self._path("OIDC_DISCOVERY_PATH", "/.well-known/openid-configuration")
        jwks_path = self._path("OIDC_JWKS_PATH", "/api/oidc/jwks")
        authorize_path = self._path("OIDC_AUTHORIZE_PATH", "/api/oidc/authorize")
        token_path = self._path("OIDC_TOKEN_PATH", "/api/oidc/token")
        userinfo_path = self._path("OIDC_USERINFO_PATH", "/api/oidc/userinfo")
        logout_path = self._path("OIDC_LOGOUT_PATH", "/api/oidc/logout")

        jwks = self.jwks_public()
        keys = jwks.get("keys", []) if isinstance(jwks, dict) else []
        kid = keys[0].get("kid", "") if keys else ""

        return {
            "issuer": issuer,
            "discovery_endpoint": f"{issuer}{discovery_path}",
            "jwks_uri": f"{issuer}{jwks_path}",
            "authorization_endpoint": f"{issuer}{authorize_path}",
            "token_endpoint": f"{issuer}{token_path}",
            "userinfo_endpoint": f"{issuer}{userinfo_path}",
            "end_session_endpoint": f"{issuer}{logout_path}",
            "dynamic_client_registration_supported": False,
            "scopes_supported": self.supported_scopes(),
            "claims_supported": self.supported_claims(),
            "response_types_supported": self.struct.registry.response_type_options(),
            "grant_types_supported": self.struct.registry.grant_type_options(),
            "token_endpoint_auth_methods_supported": self.struct.registry.auth_method_options(),
            "id_token_signing_alg_values_supported": ["RS256"],
            "subject_types_supported": ["public"],
            "kid": kid,
            "metadata_root": "metadata/oidc",
            "jwks_public_path": "metadata/oidc/jwks_public.json",
            "jwks_private_path": "metadata/oidc/jwks_private.json",
        }

    def discovery(self):
        info = self.info()
        return {
            "issuer": info["issuer"],
            "authorization_endpoint": info["authorization_endpoint"],
            "token_endpoint": info["token_endpoint"],
            "userinfo_endpoint": info["userinfo_endpoint"],
            "jwks_uri": info["jwks_uri"],
            "end_session_endpoint": info["end_session_endpoint"],
            "response_types_supported": info["response_types_supported"],
            "grant_types_supported": info["grant_types_supported"],
            "token_endpoint_auth_methods_supported": info["token_endpoint_auth_methods_supported"],
            "scopes_supported": info["scopes_supported"],
            "claims_supported": info["claims_supported"],
            "subject_types_supported": info["subject_types_supported"],
            "id_token_signing_alg_values_supported": info["id_token_signing_alg_values_supported"],
            "request_parameter_supported": False,
            "claims_parameter_supported": True,
            "dynamic_client_registration_supported": info["dynamic_client_registration_supported"],
        }

    def sign_jwt(self, payload, headers=None):
        header = {
            "alg": "RS256",
            "kid": self.info()["kid"],
            "typ": "JWT",
        }
        if isinstance(headers, dict):
            header.update(headers)

        header_b64 = _b64u(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        payload_b64 = _b64u(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        signing_input = f"{header_b64}.{payload_b64}"
        signature = self._private_key().sign(
            signing_input.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return f"{signing_input}.{_b64u(signature)}"

    def issue_id_token(self, client_id, subject, extra_claims=None, nonce="", ttl_seconds=600):
        now = int(datetime.datetime.utcnow().timestamp())
        payload = {
            "iss": self.issuer(),
            "aud": client_id,
            "sub": subject,
            "iat": now,
            "exp": now + int(ttl_seconds),
            "auth_time": now,
            "jti": f"idt-{uuid.uuid4().hex}",
        }
        if nonce:
            payload["nonce"] = nonce
        if isinstance(extra_claims, dict):
            payload.update(extra_claims)
        return {
            "token": self.sign_jwt(payload),
            "payload": payload,
        }

    def issue_access_token(self, client_id, subject, scope="", extra_claims=None, ttl_seconds=3600):
        now = int(datetime.datetime.utcnow().timestamp())
        payload = {
            "iss": self.issuer(),
            "aud": client_id,
            "sub": subject,
            "iat": now,
            "exp": now + int(ttl_seconds),
            "jti": f"atk-{uuid.uuid4().hex}",
            "scope": str(scope or "").strip(),
            "token_use": "access_token",
        }
        if isinstance(extra_claims, dict):
            payload.update(extra_claims)
        return {
            "token": self.sign_jwt(payload, headers={"typ": "at+jwt"}),
            "payload": payload,
        }

    def decode_without_verify(self, token):
        parts = str(token or "").split(".")
        if len(parts) < 2:
            raise Exception("JWT 형식이 올바르지 않습니다.")

        def decode_part(value):
            padding_len = (4 - (len(value) % 4)) % 4
            decoded = base64.urlsafe_b64decode(f"{value}{'=' * padding_len}".encode("utf-8"))
            return json.loads(decoded.decode("utf-8"))

        return {
            "header": decode_part(parts[0]),
            "payload": decode_part(parts[1]),
        }


Model = Provider