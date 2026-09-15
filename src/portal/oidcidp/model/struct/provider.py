import base64
import datetime
import hashlib
import hmac
import json
import re
import time
import urllib.parse
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)


def _b64u(data):
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64u_decode(value):
    value = str(value or "")
    return base64.urlsafe_b64decode(
        f"{value}{'=' * ((4 - len(value) % 4) % 4)}".encode("ascii")
    )


def _b64u_int(value):
    length = max(1, (int(value).bit_length() + 7) // 8)
    return _b64u(int(value).to_bytes(length, "big"))


REVIEWOPS_PROFILE_PATTERN = re.compile(r"^[a-z0-9-]{1,64}$")
OIDC_CLAIM_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
OIDC_SIGNING_ALGORITHMS = ["RS256", "PS256", "ES256", "HS256"]
OIDC_RESPONSE_VARIANTS = [
    "standard",
    "wrong_issuer",
    "wrong_audience",
    "expired",
    "future_iat",
    "unknown_kid",
    "bad_signature",
    "alg_none",
]
SENSITIVE_PROFILE_NAMES = {
    "password",
    "otp",
    "secret",
    "client_secret",
    "code",
    "token",
    "private_key",
    "cookie",
}


def normalize_reviewops_profile(value):
    value = "" if value is None else str(value)
    if value == "":
        return ""
    if REVIEWOPS_PROFILE_PATTERN.fullmatch(value) is None:
        raise ValueError("reviewops_profile은 영문 소문자, 숫자, 하이픈만 사용해 1~64자로 입력해야 합니다.")
    return value


def append_reviewops_profile(url, profile):
    profile = normalize_reviewops_profile(profile)
    if profile == "":
        return url
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{urllib.parse.urlencode({'reviewops_profile': profile})}"


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

    def reviewops_profile(self, value=None):
        if value is None:
            value = wiz.request.query("reviewops_profile", "")
        return normalize_reviewops_profile(value)

    def _base_issuer(self):
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

    def issuer(self, reviewops_profile=None):
        issuer = self._base_issuer()
        profile = self.reviewops_profile(reviewops_profile)
        if profile:
            return f"{issuer}/reviewops/oidc/{profile}"
        return issuer

    def _rsa_jwk_pair(self, key, kid):
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

    def _ec_jwk_pair(self, key, kid):
        public_numbers = key.public_key().public_numbers()
        private_numbers = key.private_numbers()
        public_jwk = {
            "kty": "EC",
            "use": "sig",
            "alg": "ES256",
            "kid": kid,
            "crv": "P-256",
            "x": _b64u(public_numbers.x.to_bytes(32, "big")),
            "y": _b64u(public_numbers.y.to_bytes(32, "big")),
        }
        private_jwk = dict(public_jwk)
        private_jwk["d"] = _b64u(private_numbers.private_value.to_bytes(32, "big"))
        return public_jwk, private_jwk

    def _read_existing_kid(self, kty, fallback, alg=""):
        fs = self._fs()
        if not fs.exists("jwks_public.json"):
            return fallback
        data = fs.read.json("jwks_public.json", default={})
        keys = data.get("keys", []) if isinstance(data, dict) else []
        for item in keys:
            if (
                isinstance(item, dict)
                and item.get("kty") == kty
                and (not alg or item.get("alg") == alg)
                and item.get("kid")
            ):
                return str(item["kid"])
        return fallback

    def _serialize_private_key(self, key):
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

    def ensure_keys(self):
        fs = self._fs()
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S")

        rsa_path = "signing-key-rsa.pem"
        legacy_path = "signing-key.pem"
        if fs.exists(rsa_path):
            rsa_key = serialization.load_pem_private_key(
                fs.read(rsa_path).encode("utf-8"), password=None
            )
        elif fs.exists(legacy_path):
            rsa_key = serialization.load_pem_private_key(
                fs.read(legacy_path).encode("utf-8"), password=None
            )
            fs.write(rsa_path, self._serialize_private_key(rsa_key))
        else:
            rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            rsa_pem = self._serialize_private_key(rsa_key)
            fs.write(rsa_path, rsa_pem)
            fs.write(legacy_path, rsa_pem)

        ec_path = "signing-key-ec.pem"
        if fs.exists(ec_path):
            ec_key = serialization.load_pem_private_key(
                fs.read(ec_path).encode("utf-8"), password=None
            )
        else:
            ec_key = ec.generate_private_key(ec.SECP256R1())
            fs.write(ec_path, self._serialize_private_key(ec_key))

        rsa_kid = self._read_existing_kid("RSA", f"oidc-rsa-{stamp}", "RS256")
        ps_kid = self._read_existing_kid("RSA", f"oidc-ps-{stamp}", "PS256")
        ec_kid = self._read_existing_kid("EC", f"oidc-ec-{stamp}", "ES256")
        rsa_public, rsa_private = self._rsa_jwk_pair(rsa_key, rsa_kid)
        ps_public, ps_private = self._rsa_jwk_pair(rsa_key, ps_kid)
        ps_public["alg"] = "PS256"
        ps_private["alg"] = "PS256"
        ec_public, ec_private = self._ec_jwk_pair(ec_key, ec_kid)
        fs.write.json("jwks_public.json", {"keys": [rsa_public, ps_public, ec_public]}, indent=2)
        fs.write.json("jwks_private.json", {"keys": [rsa_private, ps_private, ec_private]}, indent=2)

    def jwks_public(self):
        self.ensure_keys()
        return self._fs().read.json("jwks_public.json", default={"keys": []})

    def jwks_private(self):
        self.ensure_keys()
        return self._fs().read.json("jwks_private.json", default={"keys": []})

    def _private_key(self, alg="RS256"):
        self.ensure_keys()
        path = "signing-key-ec.pem" if alg == "ES256" else "signing-key-rsa.pem"
        pem = self._fs().read(path)
        return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)

    def public_key_from_jwk(self, jwk):
        if not isinstance(jwk, dict):
            raise ValueError("JWK는 JSON 객체여야 합니다.")
        kty = str(jwk.get("kty", ""))
        if kty == "RSA":
            return rsa.RSAPublicNumbers(
                int.from_bytes(_b64u_decode(jwk.get("e", "")), "big"),
                int.from_bytes(_b64u_decode(jwk.get("n", "")), "big"),
            ).public_key()
        if kty == "EC" and jwk.get("crv") == "P-256":
            return ec.EllipticCurvePublicNumbers(
                int.from_bytes(_b64u_decode(jwk.get("x", "")), "big"),
                int.from_bytes(_b64u_decode(jwk.get("y", "")), "big"),
                ec.SECP256R1(),
            ).public_key()
        raise ValueError("지원하지 않는 JWK key type입니다.")

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

    def info(self, reviewops_profile=None):
        profile = self.reviewops_profile(reviewops_profile)
        base_issuer = self._base_issuer()
        issuer = self.issuer(profile)
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
            "discovery_endpoint": append_reviewops_profile(f"{base_issuer}{discovery_path}", profile),
            "jwks_uri": append_reviewops_profile(f"{base_issuer}{jwks_path}", profile),
            "authorization_endpoint": append_reviewops_profile(f"{base_issuer}{authorize_path}", profile),
            "token_endpoint": append_reviewops_profile(f"{base_issuer}{token_path}", profile),
            "userinfo_endpoint": append_reviewops_profile(f"{base_issuer}{userinfo_path}", profile),
            "end_session_endpoint": append_reviewops_profile(f"{base_issuer}{logout_path}", profile),
            "dynamic_client_registration_supported": False,
            "scopes_supported": self.supported_scopes(),
            "claims_supported": self.supported_claims(),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "token_endpoint_auth_methods_supported": self.struct.registry.auth_method_options(),
            "id_token_signing_alg_values_supported": list(OIDC_SIGNING_ALGORITHMS),
            "token_endpoint_auth_signing_alg_values_supported": ["HS256", "RS256", "PS256", "ES256"],
            "code_challenge_methods_supported": ["S256", "plain"],
            "subject_types_supported": ["public"],
            "kid": kid,
            "metadata_root": "metadata/oidc",
            "display_name": "Debug OIDC Provider",
            "contacts": ["technical@nanoha.kr", "security@nanoha.kr"],
            "jwks_public_path": "metadata/oidc/jwks_public.json",
            "jwks_private_path": "metadata/oidc/jwks_private.json",
        }

    def discovery(self, reviewops_profile=None, discovery_variant=None):
        info = self.info(reviewops_profile)
        document = {
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
            "token_endpoint_auth_signing_alg_values_supported": info["token_endpoint_auth_signing_alg_values_supported"],
            "code_challenge_methods_supported": info["code_challenge_methods_supported"],
            "request_parameter_supported": False,
            "claims_parameter_supported": True,
            "authorization_response_iss_parameter_supported": True,
            "service_documentation": f"{self._base_issuer()}/",
            "dynamic_client_registration_supported": info["dynamic_client_registration_supported"],
        }
        if discovery_variant is None:
            try:
                discovery_variant = wiz.request.query("discovery_variant", "standard")
            except Exception:
                discovery_variant = "standard"
        discovery_variant = str(discovery_variant or "standard")
        if discovery_variant == "wrong_issuer":
            document["issuer"] = f"{document['issuer']}/invalid"
        elif discovery_variant == "missing_token_endpoint":
            document.pop("token_endpoint", None)
        elif discovery_variant == "bad_jwks_uri":
            document["jwks_uri"] = f"{self._base_issuer()}/invalid-jwks"
        elif discovery_variant == "query_issuer":
            document["issuer"] = f"{document['issuer']}?compatibility=true"
        elif discovery_variant == "fragment_issuer":
            document["issuer"] = f"{document['issuer']}#compatibility"
        elif discovery_variant != "standard":
            raise ValueError("지원하지 않는 discovery_variant입니다.")
        if discovery_variant != "standard":
            document["reviewops_compatibility"] = {
                "status": "compatibility",
                "variant": discovery_variant,
                "message": "표준과 다른 Discovery 응답이 활성화되었습니다.",
            }
        return document

    def sign_jwt(self, payload, headers=None, secret=""):
        header = {
            "alg": "RS256",
            "typ": "JWT",
        }
        if isinstance(headers, dict):
            header.update(headers)
        alg = str(header.get("alg", "RS256"))
        if alg not in OIDC_SIGNING_ALGORITHMS and alg != "none":
            raise ValueError("지원하지 않는 JWT signing algorithm입니다.")
        if "kid" not in header and alg != "HS256" and alg != "none":
            kty = "EC" if alg == "ES256" else "RSA"
            header["kid"] = next(
                (
                    str(item.get("kid", ""))
                    for item in self.jwks_public().get("keys", [])
                    if item.get("kty") == kty and item.get("alg") == alg
                ),
                "",
            )

        header_b64 = _b64u(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        payload_b64 = _b64u(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        signing_input = f"{header_b64}.{payload_b64}"
        data = signing_input.encode("ascii")
        if alg == "none":
            signature = b""
        elif alg == "HS256":
            if not secret:
                raise ValueError("HS256 JWT signing에는 client secret이 필요합니다.")
            signature = hmac.new(str(secret).encode("utf-8"), data, hashlib.sha256).digest()
        elif alg == "PS256":
            signature = self._private_key(alg).sign(
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                hashes.SHA256(),
            )
        elif alg == "ES256":
            der_signature = self._private_key(alg).sign(data, ec.ECDSA(hashes.SHA256()))
            r_value, s_value = decode_dss_signature(der_signature)
            signature = r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big")
        else:
            signature = self._private_key(alg).sign(
                data,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        return f"{signing_input}.{_b64u(signature)}"

    def verify_jwt(self, token, allowed_algs=None, secret="", allow_expired=False, expected_issuer=None):
        parts = str(token or "").split(".")
        if len(parts) != 3:
            raise ValueError("JWT 형식이 올바르지 않습니다.")
        decoded = self.decode_without_verify(token)
        header = decoded["header"]
        payload = decoded["payload"]
        alg = str(header.get("alg", ""))
        allowed = list(allowed_algs or OIDC_SIGNING_ALGORITHMS)
        if alg not in allowed or alg == "none":
            raise ValueError("허용되지 않은 JWT signing algorithm입니다.")
        data = f"{parts[0]}.{parts[1]}".encode("ascii")
        signature = _b64u_decode(parts[2])

        if alg == "HS256":
            if not secret:
                raise ValueError("HS256 JWT 검증에 client secret이 필요합니다.")
            expected = hmac.new(str(secret).encode("utf-8"), data, hashlib.sha256).digest()
            if not hmac.compare_digest(expected, signature):
                raise ValueError("JWT signature 검증에 실패했습니다.")
        else:
            kid = str(header.get("kid", ""))
            candidates = [
                item
                for item in self.jwks_public().get("keys", [])
                if (not kid or item.get("kid") == kid)
                and (not item.get("alg") or item.get("alg") == alg)
            ]
            verified = False
            for jwk in candidates:
                try:
                    key = self.public_key_from_jwk(jwk)
                    if alg == "PS256":
                        key.verify(
                            signature,
                            data,
                            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                            hashes.SHA256(),
                        )
                    elif alg == "ES256":
                        if len(signature) != 64:
                            raise ValueError("ES256 signature 길이가 올바르지 않습니다.")
                        der_signature = encode_dss_signature(
                            int.from_bytes(signature[:32], "big"),
                            int.from_bytes(signature[32:], "big"),
                        )
                        key.verify(der_signature, data, ec.ECDSA(hashes.SHA256()))
                    else:
                        key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
                    verified = True
                    break
                except Exception:
                    continue
            if not verified:
                raise ValueError("JWT signature 검증에 실패했습니다.")

        now = int(time.time())
        if not allow_expired and payload.get("exp") is not None and int(payload["exp"]) < now:
            raise ValueError("JWT가 만료되었습니다.")
        if payload.get("nbf") is not None and int(payload["nbf"]) > now + 60:
            raise ValueError("JWT의 nbf가 아직 유효하지 않습니다.")
        if expected_issuer is not None and payload.get("iss") != expected_issuer:
            raise ValueError("JWT issuer가 일치하지 않습니다.")
        return decoded

    def at_hash(self, access_token):
        digest = hashlib.sha256(str(access_token).encode("ascii")).digest()
        return _b64u(digest[: len(digest) // 2])

    def issue_id_token(
        self,
        client_id,
        subject,
        extra_claims=None,
        nonce="",
        ttl_seconds=600,
        auth_time=None,
        sid="",
        acr="",
        amr=None,
        access_token="",
        signing_alg="RS256",
        signing_secret="",
        response_variant="standard",
        time_offset_seconds=0,
        reviewops_profile=None,
    ):
        now = int(time.time()) + int(time_offset_seconds or 0)
        payload = {
            "iss": self.issuer(reviewops_profile),
            "aud": client_id,
            "sub": subject,
            "iat": now,
            "exp": now + int(ttl_seconds),
            "auth_time": int(auth_time if auth_time is not None else now),
            "jti": f"idt-{uuid.uuid4().hex}",
        }
        if nonce:
            payload["nonce"] = nonce
        if sid:
            payload["sid"] = sid
        if acr:
            payload["acr"] = acr
        if amr:
            payload["amr"] = list(amr) if isinstance(amr, (list, tuple)) else [str(amr)]
        if access_token:
            payload["at_hash"] = self.at_hash(access_token)
        if isinstance(extra_claims, dict):
            payload.update(extra_claims)
        if response_variant == "wrong_issuer":
            payload["iss"] = f"{payload['iss']}/invalid"
        elif response_variant == "wrong_audience":
            payload["aud"] = f"{client_id}-invalid"
        elif response_variant == "expired":
            payload["iat"] = now - 7200
            payload["exp"] = now - 3600
        elif response_variant == "future_iat":
            payload["iat"] = now + 3600
            payload["exp"] = now + 7200

        effective_alg = "none" if response_variant == "alg_none" else signing_alg
        headers = {"alg": effective_alg}
        if response_variant == "unknown_kid":
            headers["kid"] = f"unknown-{uuid.uuid4().hex[:12]}"
        if effective_alg == "RS256" and response_variant == "standard":
            token = self.sign_jwt(payload)
        else:
            token = self.sign_jwt(payload, headers=headers, secret=signing_secret)
        if response_variant == "bad_signature" and token:
            token = f"{token[:-1]}{'A' if token[-1] != 'A' else 'B'}"
        return {
            "token": token,
            "payload": payload,
            "alg": effective_alg,
            "variant": response_variant,
        }

    def issue_access_token(self, client_id, subject, scope="", extra_claims=None, ttl_seconds=3600, time_offset_seconds=0, reviewops_profile=None):
        now = int(time.time()) + int(time_offset_seconds or 0)
        payload = {
            "iss": self.issuer(reviewops_profile),
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
            decoded = _b64u_decode(value)
            return json.loads(decoded.decode("utf-8"))

        return {
            "header": decode_part(parts[0]),
            "payload": decode_part(parts[1]),
        }

    def _profile_path(self, reviewops_profile):
        profile = self.reviewops_profile(reviewops_profile)
        if not profile:
            raise ValueError("OIDC 실행 설정에는 reviewops_profile이 필요합니다.")
        return f"reviewops-profile-{profile}.json"

    def _normalize_claim_names(self, value, field):
        if value is None:
            return []
        if not isinstance(value, (list, tuple)) or len(value) > 32:
            raise ValueError(f"{field}는 최대 32개의 Claim 이름 배열이어야 합니다.")
        result = []
        for item in value:
            name = str(item or "").strip()
            if OIDC_CLAIM_NAME_PATTERN.fullmatch(name) is None:
                raise ValueError(f"{field}에 올바르지 않은 Claim 이름이 있습니다.")
            if name not in result:
                result.append(name)
        return result

    def _normalize_claim_object(self, value, field):
        if value is None:
            return {}
        if not isinstance(value, dict) or len(value) > 32:
            raise ValueError(f"{field}는 최대 32개의 Claim을 가진 JSON 객체여야 합니다.")
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 32768:
            raise ValueError(f"{field}는 32KB를 넘을 수 없습니다.")
        for name in value:
            normalized = str(name or "").strip()
            if OIDC_CLAIM_NAME_PATTERN.fullmatch(normalized) is None:
                raise ValueError(f"{field}에 올바르지 않은 Claim 이름이 있습니다.")
            if any(part in normalized.lower() for part in SENSITIVE_PROFILE_NAMES):
                raise ValueError(f"{field}에 비밀정보 이름을 사용할 수 없습니다.")
        return value

    def normalize_profile_settings(self, value):
        if not isinstance(value, dict):
            raise ValueError("OIDC 실행 설정은 JSON 객체여야 합니다.")
        subject_source = str(value.get("subject_source", "sub") or "sub").strip()
        if OIDC_CLAIM_NAME_PATTERN.fullmatch(subject_source) is None:
            raise ValueError("subject_source는 올바른 Claim 경로여야 합니다.")
        signing_alg = str(value.get("id_token_signing_alg", "RS256") or "RS256")
        if signing_alg not in OIDC_SIGNING_ALGORITHMS:
            raise ValueError("지원하지 않는 ID Token signing algorithm입니다.")
        response_variant = str(value.get("response_variant", "standard") or "standard")
        if response_variant not in OIDC_RESPONSE_VARIANTS:
            raise ValueError("지원하지 않는 OIDC response variant입니다.")
        time_offset = int(value.get("time_offset_seconds", 0) or 0)
        if abs(time_offset) > 86400:
            raise ValueError("time_offset_seconds는 -86400~86400 범위여야 합니다.")
        token_ttl = int(value.get("token_ttl_seconds", 600) or 600)
        if token_ttl < 1 or token_ttl > 86400:
            raise ValueError("token_ttl_seconds는 1~86400 범위여야 합니다.")
        session_ttl = int(value.get("session_ttl_seconds", 28800) or 28800)
        if session_ttl < 1 or session_ttl > 604800:
            raise ValueError("session_ttl_seconds는 1~604800 범위여야 합니다.")
        amr = self._normalize_claim_names(value.get("amr", ["pwd"]), "amr")
        distributed_claims = value.get("distributed_claims", {}) or {}
        if not isinstance(distributed_claims, dict) or len(distributed_claims) > 16:
            raise ValueError("distributed_claims는 최대 16개의 Claim 설정을 가진 JSON 객체여야 합니다.")
        normalized_distributed = {}
        for name, source in distributed_claims.items():
            if OIDC_CLAIM_NAME_PATTERN.fullmatch(str(name or "")) is None or not isinstance(source, dict):
                raise ValueError("distributed_claims 형식이 올바르지 않습니다.")
            endpoint = str(source.get("endpoint", "") or "").strip()
            parsed = urllib.parse.urlparse(endpoint)
            if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
                raise ValueError("분산 Claim endpoint는 HTTPS 절대 URL이어야 합니다.")
            normalized_distributed[str(name)] = {"endpoint": endpoint}
        return {
            "subject_source": subject_source,
            "claim_overrides": self._normalize_claim_object(value.get("claim_overrides", {}), "claim_overrides"),
            "userinfo_claim_overrides": self._normalize_claim_object(value.get("userinfo_claim_overrides", {}), "userinfo_claim_overrides"),
            "id_token_claim_overrides": self._normalize_claim_object(value.get("id_token_claim_overrides", {}), "id_token_claim_overrides"),
            "omit_claims": self._normalize_claim_names(value.get("omit_claims", []), "omit_claims"),
            "id_token_only_claims": self._normalize_claim_names(value.get("id_token_only_claims", []), "id_token_only_claims"),
            "userinfo_only_claims": self._normalize_claim_names(value.get("userinfo_only_claims", []), "userinfo_only_claims"),
            "distributed_claims": normalized_distributed,
            "id_token_signing_alg": signing_alg,
            "response_variant": response_variant,
            "time_offset_seconds": time_offset,
            "token_ttl_seconds": token_ttl,
            "session_ttl_seconds": session_ttl,
            "acr": str(value.get("acr", "") or "").strip()[:512],
            "amr": amr,
        }

    def profile_settings(self, reviewops_profile):
        profile = self.reviewops_profile(reviewops_profile)
        defaults = self.normalize_profile_settings({})
        defaults.update(self.profile_standards(defaults))
        defaults.update({"reviewops_profile": profile, "configured": False})
        if not profile:
            return defaults
        fs = self._fs()
        path = self._profile_path(profile)
        if not fs.exists(path):
            return defaults
        raw = fs.read.json(path, default={})
        try:
            normalized = self.normalize_profile_settings(raw)
        except (TypeError, ValueError):
            return defaults
        normalized.update(self.profile_standards(normalized))
        normalized.update({"reviewops_profile": profile, "configured": True})
        return normalized

    def list_profiles(self):
        profiles = []
        prefix = "reviewops-profile-"
        suffix = ".json"
        for filename in self._fs().files():
            name = str(filename or "")
            if not name.startswith(prefix) or not name.endswith(suffix):
                continue
            profile = name[len(prefix):-len(suffix)]
            try:
                settings = self.profile_settings(profile)
            except ValueError:
                continue
            profiles.append({
                "name": profile,
                "standards_status": settings.get("standards_status", "standard"),
                "standards_warnings": settings.get("standards_warnings", []),
                "id_token_signing_alg": settings.get("id_token_signing_alg", "RS256"),
                "response_variant": settings.get("response_variant", "standard"),
            })
        return sorted(profiles, key=lambda item: item["name"])

    def profile_standards(self, settings):
        warnings = []
        if settings.get("id_token_signing_alg") == "HS256":
            warnings.append("HS256 ID Token은 confidential client 호환 시험용입니다.")
        if settings.get("response_variant", "standard") != "standard":
            warnings.append("표준과 다른 OIDC 응답 변형이 활성화되었습니다.")
        if int(settings.get("time_offset_seconds", 0) or 0) != 0:
            warnings.append("토큰 시간이 현재 시각에서 이동되어 있습니다.")
        return {
            "standards_status": "compatibility" if warnings else "standard",
            "standards_warnings": warnings,
        }

    def configure_profile(self, reviewops_profile, settings):
        profile = self.reviewops_profile(reviewops_profile)
        path = self._profile_path(profile)
        normalized = self.normalize_profile_settings(settings)
        payload = dict(normalized)
        payload.update(self.profile_standards(normalized))
        payload["reviewops_profile"] = profile
        self._fs().write.json(path, payload, indent=2)
        payload["configured"] = True
        return payload

    def clear_profile(self, reviewops_profile):
        profile = self.reviewops_profile(reviewops_profile)
        path = self._profile_path(profile)
        fs = self._fs()
        if fs.exists(path):
            fs.delete(path)
        result = self.profile_settings(profile)
        result["cleared"] = True
        return result


Model = Provider
