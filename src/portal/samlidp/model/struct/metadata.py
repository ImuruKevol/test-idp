import os
import base64
import datetime
import hashlib
import re
import urllib.parse
from lxml import etree
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from signxml import XMLSigner, methods

NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata"
NS_DS = "http://www.w3.org/2000/09/xmldsig#"
NS_ALG = "urn:oasis:names:tc:SAML:metadata:algsupport"
NS_REMD = "http://refeds.org/metadata"
BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
BINDING_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

REVIEWOPS_PROFILE_PATTERN = re.compile(r"^[a-z0-9-]{1,64}$")
SAML_ATTRIBUTE_OID_PATTERN = re.compile(r"^urn:oid:\d+(?:\.\d+)+$")
MAX_OMIT_ATTRIBUTES = 32
MAX_ATTRIBUTE_VALUES = 32
MAX_ATTRIBUTE_NAME_LENGTH = 512
MAX_ATTRIBUTE_VALUE_COUNT = 16
MAX_ATTRIBUTE_VALUE_LENGTH = 2048
DEFAULT_METADATA_VALIDITY_MINUTES = 1440
DEFAULT_METADATA_CACHE_MINUTES = 15
MAX_FEDERATION_ENTITIES = 50
MAX_QUICK_IDPS = 20
MAX_QUICK_FEDERATION_NAME_LENGTH = 57
FEDERATION_PATTERN = re.compile(r"^[a-z0-9-]{1,64}$")
INBOUND_CONTENT_ENCRYPTION_ALGORITHMS = [
    "http://www.w3.org/2009/xmlenc11#aes128-gcm",
    "http://www.w3.org/2009/xmlenc11#aes192-gcm",
    "http://www.w3.org/2009/xmlenc11#aes256-gcm",
]
INBOUND_KEY_TRANSPORT_ALGORITHMS = [
    "http://www.w3.org/2009/xmlenc11#rsa-oaep",
    "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
]


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


class Metadata:
    def __init__(self, struct):
        self.struct = struct

    def _cert_fs(self):
        return wiz.project.fs("metadata", "saml", "idp")

    def _generate_keypair(self, common_name, purpose):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test IdP"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        signing = purpose == "signing"
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=signing,
                    content_commitment=False,
                    key_encipherment=not signing,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=None,
                    decipher_only=None,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        return key_pem, cert_pem

    def _ensure_keypair(self):
        fs = self._cert_fs()
        pairs = [
            ("idp-key.pem", "idp-cert.pem", "Test SAML IdP Signing", "signing"),
            (
                "idp-encryption-key.pem",
                "idp-encryption-cert.pem",
                "Test SAML IdP Encryption",
                "encryption",
            ),
        ]
        for key_path, cert_path, common_name, purpose in pairs:
            if fs.exists(key_path) and fs.exists(cert_path):
                continue
            key_pem, cert_pem = self._generate_keypair(common_name, purpose)
            fs.write(key_path, key_pem)
            fs.write(cert_path, cert_pem)

    def get_cert_pem(self):
        self._ensure_keypair()
        fs = self._cert_fs()
        return fs.read("idp-cert.pem")

    def get_key_pem(self):
        self._ensure_keypair()
        fs = self._cert_fs()
        return fs.read("idp-key.pem")

    def get_cert_body(self):
        pem = self.get_cert_pem()
        lines = pem.strip().split("\n")
        body_lines = [l for l in lines if not l.startswith("-----")]
        return "".join(body_lines)

    def get_encryption_cert_pem(self):
        self._ensure_keypair()
        return self._cert_fs().read("idp-encryption-cert.pem")

    def get_encryption_key_pem(self):
        self._ensure_keypair()
        return self._cert_fs().read("idp-encryption-key.pem")

    def get_encryption_cert_body(self):
        pem = self.get_encryption_cert_pem()
        return "".join(
            line for line in pem.strip().split("\n")
            if not line.startswith("-----")
        )

    def _base_url(self):
        config = wiz.config("season")
        base_url = None
        try:
            base_url = config.get("saml_base_url", None)
        except Exception:
            pass
        if not base_url:
            host = wiz.request.headers("Host", "localhost:3034")
            scheme = wiz.request.headers("X-Forwarded-Proto", "http")
            base_url = f"{scheme}://{host}"
        return base_url.rstrip("/")

    def _idp_config_value(self, key, default):
        try:
            config = wiz.config("idp")
            return getattr(config, key, default)
        except Exception:
            return default

    def _metadata_lifetime(self):
        validity_minutes = int(self._idp_config_value(
            "SAML_METADATA_VALIDITY_MINUTES",
            DEFAULT_METADATA_VALIDITY_MINUTES,
        ) or DEFAULT_METADATA_VALIDITY_MINUTES)
        cache_minutes = int(self._idp_config_value(
            "SAML_METADATA_CACHE_MINUTES",
            DEFAULT_METADATA_CACHE_MINUTES,
        ) or DEFAULT_METADATA_CACHE_MINUTES)
        validity_minutes = max(5, min(validity_minutes, 10080))
        cache_minutes = max(1, min(cache_minutes, validity_minutes))
        bucket_seconds = cache_minutes * 60
        now_epoch = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        generated_epoch = now_epoch - (now_epoch % bucket_seconds)
        generated_at = datetime.datetime.fromtimestamp(
            generated_epoch,
            datetime.timezone.utc,
        )
        valid_until = generated_at + datetime.timedelta(minutes=validity_minutes)
        return {
            "generated_at": generated_at,
            "valid_until": valid_until,
            "valid_until_text": valid_until.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "cache_minutes": cache_minutes,
            "cache_seconds": cache_minutes * 60,
            "cache_duration": f"PT{cache_minutes}M",
        }

    def _certificate_sha256(self, purpose="signing"):
        cert_pem = (
            self.get_encryption_cert_pem()
            if purpose == "encryption" else self.get_cert_pem()
        )
        try:
            certificate = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
            digest = certificate.fingerprint(hashes.SHA256()).hex()
        except Exception:
            body = (
                self.get_encryption_cert_body()
                if purpose == "encryption" else self.get_cert_body()
            )
            digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        return digest.upper()

    def _certificate_info(self, purpose="signing"):
        cert_pem = (
            self.get_encryption_cert_pem()
            if purpose == "encryption" else self.get_cert_pem()
        )
        certificate = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        public_key = certificate.public_key()
        key_size = int(getattr(public_key, "key_size", 0) or 0)
        if hasattr(certificate, "not_valid_before_utc"):
            not_before = certificate.not_valid_before_utc
            not_after = certificate.not_valid_after_utc
        else:
            not_before = certificate.not_valid_before.replace(tzinfo=datetime.timezone.utc)
            not_after = certificate.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        return {
            "purpose": purpose,
            "sha256": self._certificate_sha256(purpose),
            "subject": certificate.subject.rfc4514_string(),
            "serial_number": format(certificate.serial_number, "X"),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "public_key_type": public_key.__class__.__name__,
            "key_size": key_size,
        }

    def normalize_federation_name(self, value):
        value = str(value or "").strip()
        if FEDERATION_PATTERN.fullmatch(value) is None:
            raise ValueError("Federation 이름은 영문 소문자, 숫자, 하이픈만 사용해 1~64자로 입력해야 합니다.")
        return value

    def _federation_path(self, name):
        return f"federation-group-{self.normalize_federation_name(name)}.json"

    def _federation_url(self, name=""):
        endpoint = f"{self._base_url()}/api/saml/federation-metadata"
        if name:
            endpoint = f"{endpoint}?{urllib.parse.urlencode({'federation': self.normalize_federation_name(name)})}"
        return endpoint

    def reviewops_profile(self, value=None):
        if value is None:
            value = wiz.request.query("reviewops_profile", "")
        return normalize_reviewops_profile(value)

    def _response_defaults_path(self, reviewops_profile):
        profile = self.reviewops_profile(reviewops_profile)
        if profile == "":
            raise ValueError("SAML response 기본값 설정에는 reviewops_profile이 필요합니다.")
        return f"reviewops-profile-{profile}.json"

    def normalize_omit_attributes(self, value):
        if value is None:
            return []
        if not isinstance(value, (list, tuple)):
            raise ValueError("omit_attributes는 SAML Attribute Name 문자열 배열이어야 합니다.")
        if len(value) > MAX_OMIT_ATTRIBUTES:
            raise ValueError(
                f"omit_attributes는 최대 {MAX_OMIT_ATTRIBUTES}개까지 설정할 수 있습니다."
            )
        normalized = []
        seen = set()
        for item in value:
            if not isinstance(item, str):
                raise ValueError("omit_attributes의 각 항목은 문자열이어야 합니다.")
            name = item.strip()
            if not name:
                raise ValueError("omit_attributes에 빈 Attribute Name을 사용할 수 없습니다.")
            if len(name) > MAX_ATTRIBUTE_NAME_LENGTH:
                raise ValueError(
                    "omit_attributes의 Attribute Name은 최대 "
                    f"{MAX_ATTRIBUTE_NAME_LENGTH}자입니다."
                )
            if any(ord(char) < 0x20 or ord(char) == 0x7F for char in name):
                raise ValueError("omit_attributes에 제어 문자를 사용할 수 없습니다.")
            if name not in seen:
                normalized.append(name)
                seen.add(name)
        return normalized

    def normalize_attribute_values(self, value):
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise ValueError("attribute_values는 SAML Attribute OID를 키로 사용하는 JSON 객체여야 합니다.")
        if len(value) > MAX_ATTRIBUTE_VALUES:
            raise ValueError(
                f"attribute_values는 최대 {MAX_ATTRIBUTE_VALUES}개 Attribute까지 설정할 수 있습니다."
            )

        normalized = {}
        for raw_name, raw_value in value.items():
            if not isinstance(raw_name, str):
                raise ValueError("attribute_values의 Attribute OID는 문자열이어야 합니다.")
            name = raw_name.strip()
            if len(name) > MAX_ATTRIBUTE_NAME_LENGTH:
                raise ValueError(
                    "attribute_values의 Attribute OID는 최대 "
                    f"{MAX_ATTRIBUTE_NAME_LENGTH}자입니다."
                )
            if SAML_ATTRIBUTE_OID_PATTERN.fullmatch(name) is None:
                raise ValueError(
                    "attribute_values의 키는 urn:oid:<숫자 OID> 형식이어야 합니다."
                )

            values = raw_value if isinstance(raw_value, list) else [raw_value]
            if not values:
                raise ValueError("attribute_values의 값 배열은 비어 있을 수 없습니다.")
            if len(values) > MAX_ATTRIBUTE_VALUE_COUNT:
                raise ValueError(
                    "attribute_values의 AttributeValue는 Attribute당 최대 "
                    f"{MAX_ATTRIBUTE_VALUE_COUNT}개까지 설정할 수 있습니다."
                )

            normalized_values = []
            for item in values:
                if not isinstance(item, str):
                    raise ValueError(
                        "attribute_values의 값은 문자열 또는 문자열 배열이어야 합니다."
                    )
                if item == "":
                    raise ValueError("attribute_values에 빈 AttributeValue를 사용할 수 없습니다.")
                if len(item) > MAX_ATTRIBUTE_VALUE_LENGTH:
                    raise ValueError(
                        "attribute_values의 AttributeValue는 최대 "
                        f"{MAX_ATTRIBUTE_VALUE_LENGTH}자입니다."
                    )
                if any(ord(char) < 0x20 or ord(char) == 0x7F for char in item):
                    raise ValueError("attribute_values에 제어 문자를 사용할 수 없습니다.")
                normalized_values.append(item)

            normalized[name] = (
                normalized_values
                if isinstance(raw_value, list)
                else normalized_values[0]
            )
        return normalized

    def response_defaults(self, reviewops_profile):
        profile = self.reviewops_profile(reviewops_profile)
        defaults = {
            "reviewops_profile": profile,
            "sign_response": True,
            "sign_assertion": True,
            "omit_attributes": [],
            "attribute_values": {},
            "configured": False,
        }
        if profile == "":
            defaults.update(self.response_standards(defaults))
            return defaults
        fs = self._cert_fs()
        path = self._response_defaults_path(profile)
        if not fs.exists(path):
            defaults.update(self.response_standards(defaults))
            return defaults
        data = fs.read.json(
            path,
            default={},
        )
        if not isinstance(data, dict):
            defaults.update(self.response_standards(defaults))
            return defaults
        if isinstance(data.get("sign_response"), bool):
            defaults["sign_response"] = data["sign_response"]
        if isinstance(data.get("sign_assertion"), bool):
            defaults["sign_assertion"] = data["sign_assertion"]
        try:
            defaults["omit_attributes"] = self.normalize_omit_attributes(
                data.get("omit_attributes", [])
            )
        except ValueError:
            defaults["omit_attributes"] = []
        try:
            defaults["attribute_values"] = self.normalize_attribute_values(
                data.get("attribute_values", {})
            )
        except ValueError:
            defaults["attribute_values"] = {}
        if isinstance(data.get("response_options"), dict):
            try:
                defaults.update(self.normalize_response_options(data["response_options"]))
            except ValueError:
                pass
        defaults["configured"] = True
        defaults.update(self.response_standards(defaults))
        return defaults

    def response_standards(self, settings):
        warnings = []
        if not settings.get("sign_response") and not settings.get("sign_assertion"):
            warnings.append("Response와 Assertion 서명이 모두 꺼져 있습니다.")
        if settings.get("response_variant", "standard") != "standard":
            warnings.append("표준과 다른 SAML 응답 변형이 활성화되었습니다.")
        content = settings.get("content_encryption_algorithm", "aes256-gcm")
        if settings.get("encrypt_assertion") and content in [
            "aes128-cbc", "aes192-cbc", "aes256-cbc", "tripledes-cbc"
        ]:
            warnings.append("이전 시스템 확인용 content encryption algorithm을 사용합니다.")
        transport = settings.get("key_transport_algorithm", "rsa-oaep-sha256")
        if settings.get("encrypt_assertion") and transport in ["rsa-oaep-sha1", "rsa-1_5"]:
            warnings.append("이전 시스템 확인용 key transport algorithm을 사용합니다.")
        if int(settings.get("time_offset_seconds", 0) or 0) != 0:
            warnings.append("응답 시간이 현재 시각에서 이동되어 있습니다.")
        return {
            "standards_status": "compatibility" if warnings else "standard",
            "standards_warnings": warnings,
        }

    def list_response_profiles(self):
        profiles = []
        prefix = "reviewops-profile-"
        suffix = ".json"
        fs = self._cert_fs()
        filenames = fs.files() if callable(getattr(fs, "files", None)) else []
        for filename in filenames:
            name = str(filename or "")
            if not name.startswith(prefix) or not name.endswith(suffix):
                continue
            profile = name[len(prefix):-len(suffix)]
            try:
                settings = self.response_defaults(profile)
            except ValueError:
                continue
            profiles.append({
                "name": profile,
                "standards_status": settings.get("standards_status", "standard"),
                "standards_warnings": settings.get("standards_warnings", []),
                "sign_response": settings.get("sign_response", True),
                "sign_assertion": settings.get("sign_assertion", True),
                "response_variant": settings.get("response_variant", "standard"),
            })
        return sorted(profiles, key=lambda item: item["name"])

    def get_federation(self, name):
        name = self.normalize_federation_name(name)
        path = self._federation_path(name)
        fs = self._cert_fs()
        if not fs.exists(path):
            return None
        value = fs.read.json(path, default={})
        if not isinstance(value, dict):
            return None
        profiles = []
        for item in value.get("profiles", []):
            profile = self.reviewops_profile(item)
            if profile and profile not in profiles:
                profiles.append(profile)
        return {
            "name": name,
            "profiles": profiles,
            "include_base": value.get("include_base") is not False,
            "preset": str(value.get("preset", "standard") or "standard"),
            "created": str(value.get("created", "") or ""),
            "metadata_url": self._federation_url(name),
            "entity_count": len(profiles) + (1 if value.get("include_base") is not False else 0),
        }

    def list_federations(self):
        fs = self._cert_fs()
        filenames = fs.files() if callable(getattr(fs, "files", None)) else []
        prefix = "federation-group-"
        suffix = ".json"
        result = []
        for filename in filenames:
            value = str(filename or "")
            if not value.startswith(prefix) or not value.endswith(suffix):
                continue
            name = value[len(prefix):-len(suffix)]
            try:
                federation = self.get_federation(name)
            except ValueError:
                continue
            if federation is not None:
                result.append(federation)
        return sorted(result, key=lambda item: item["name"])

    def create_federation(
        self,
        name,
        count=3,
        include_base=True,
        preset="standard",
        profiles=None,
    ):
        name = self.normalize_federation_name(name)
        preset = str(preset or "standard").strip()
        if preset not in ["standard", "encrypted", "mixed"]:
            raise ValueError("Federation preset은 standard, encrypted, mixed 중 하나여야 합니다.")
        quick_create = profiles is None
        if quick_create:
            if len(name) > MAX_QUICK_FEDERATION_NAME_LENGTH:
                raise ValueError(
                    f"빠른 생성 Federation 이름은 최대 {MAX_QUICK_FEDERATION_NAME_LENGTH}자여야 합니다."
                )
            try:
                count = int(count)
            except (TypeError, ValueError):
                raise ValueError("IdP 개수는 정수여야 합니다.")
            if count < 1 or count > MAX_QUICK_IDPS:
                raise ValueError(f"한 번에 만들 IdP는 1~{MAX_QUICK_IDPS}개여야 합니다.")
            profiles = [f"{name}-idp-{index}" for index in range(1, count + 1)]
        normalized_profiles = []
        for item in profiles:
            profile = self.reviewops_profile(item)
            if not profile:
                raise ValueError("Federation IdP 이름은 비어 있을 수 없습니다.")
            if profile not in normalized_profiles:
                normalized_profiles.append(profile)
        entity_count = len(normalized_profiles) + (1 if include_base else 0)
        if entity_count < 1 or entity_count > MAX_FEDERATION_ENTITIES:
            raise ValueError(f"Federation은 1~{MAX_FEDERATION_ENTITIES}개 entity를 포함해야 합니다.")

        existing_profiles = {
            item["name"] for item in self.list_response_profiles()
        }
        created_profiles = []
        reused_profiles = []
        reconfigured_profiles = []
        for index, profile in enumerate(normalized_profiles):
            exists = profile in existing_profiles
            if exists and not quick_create:
                reused_profiles.append(profile)
                continue
            selected = preset
            if preset == "mixed":
                selected = "encrypted" if index % 2 else "standard"
            response_options = {
                "encrypt_assertion": selected == "encrypted",
                "content_encryption_algorithm": "aes256-gcm",
                "key_transport_algorithm": "rsa-oaep-sha256",
                "response_variant": "standard",
                "time_offset_seconds": 0,
                "assertion_ttl_seconds": 300,
            }
            self.configure_response_defaults(
                profile,
                sign_response=True,
                sign_assertion=True,
                response_options=response_options,
            )
            if exists:
                reconfigured_profiles.append(profile)
            else:
                created_profiles.append(profile)

        created = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self._cert_fs().write.json(
            self._federation_path(name),
            {
                "name": name,
                "profiles": normalized_profiles,
                "include_base": bool(include_base),
                "preset": preset,
                "created": created,
            },
            indent=2,
        )
        result = self.federation_info(federation_name=name)
        result.update({
            "created_profiles": created_profiles,
            "reused_profiles": reused_profiles,
            "reconfigured_profiles": reconfigured_profiles,
            "preset": preset,
        })
        return result

    def delete_federation(self, name):
        name = self.normalize_federation_name(name)
        path = self._federation_path(name)
        fs = self._cert_fs()
        if not fs.exists(path):
            raise ValueError("Federation 구성을 찾을 수 없습니다.")
        fs.delete(path)
        return {"name": name, "deleted": True}

    def normalize_response_options(self, value):
        value = value or {}
        if not isinstance(value, dict):
            raise ValueError("SAML response 옵션은 JSON 객체여야 합니다.")
        content = str(value.get("content_encryption_algorithm", "aes256-gcm") or "aes256-gcm")
        if content not in ["aes128-gcm", "aes192-gcm", "aes256-gcm", "aes128-cbc", "aes192-cbc", "aes256-cbc", "tripledes-cbc"]:
            raise ValueError("지원하지 않는 content encryption algorithm입니다.")
        transport = str(value.get("key_transport_algorithm", "rsa-oaep-sha256") or "rsa-oaep-sha256")
        if transport not in ["rsa-oaep-sha256", "rsa-oaep-sha1", "rsa-1_5"]:
            raise ValueError("지원하지 않는 key transport algorithm입니다.")
        variant = str(value.get("response_variant", "standard") or "standard")
        if variant not in [
            "standard", "wrong_issuer", "wrong_audience", "expired", "future_not_before",
            "unsigned", "bad_ciphertext", "authn_failed", "no_authn_context",
            "request_denied", "responder",
        ]:
            raise ValueError("지원하지 않는 SAML response variant입니다.")
        offset = int(value.get("time_offset_seconds", 0) or 0)
        ttl = int(value.get("assertion_ttl_seconds", 300) or 300)
        if abs(offset) > 86400 or ttl < 1 or ttl > 86400:
            raise ValueError("SAML 시간 옵션이 허용 범위를 벗어났습니다.")
        return {
            "encrypt_assertion": value.get("encrypt_assertion") is True,
            "content_encryption_algorithm": content,
            "key_transport_algorithm": transport,
            "response_variant": variant,
            "time_offset_seconds": offset,
            "assertion_ttl_seconds": ttl,
        }

    def configure_response_defaults(
        self,
        reviewops_profile,
        sign_response=True,
        sign_assertion=True,
        omit_attributes=None,
        attribute_values=None,
        response_options=None,
    ):
        profile = self.reviewops_profile(reviewops_profile)
        if profile == "":
            raise ValueError("SAML response 기본값 설정에는 reviewops_profile이 필요합니다.")
        if not isinstance(sign_response, bool) or not isinstance(sign_assertion, bool):
            raise ValueError("sign_response와 sign_assertion은 boolean이어야 합니다.")
        data = {
            "reviewops_profile": profile,
            "sign_response": sign_response,
            "sign_assertion": sign_assertion,
            "omit_attributes": self.normalize_omit_attributes(omit_attributes),
            "attribute_values": self.normalize_attribute_values(attribute_values),
        }
        if response_options is not None:
            normalized_options = self.normalize_response_options(response_options)
            data["response_options"] = normalized_options
            data.update(normalized_options)
        data.update(self.response_standards(data))
        self._cert_fs().write.json(self._response_defaults_path(profile), data, indent=2)
        data["configured"] = True
        return data

    def clear_response_defaults(self, reviewops_profile):
        profile = self.reviewops_profile(reviewops_profile)
        path = self._response_defaults_path(profile)
        fs = self._cert_fs()
        if fs.exists(path):
            fs.delete(path)
        result = {
            "reviewops_profile": profile,
            "cleared": True,
            "configured": False,
            "sign_response": True,
            "sign_assertion": True,
            "omit_attributes": [],
            "attribute_values": {},
        }
        result.update(self.response_standards(result))
        return result

    def entity_id(self, reviewops_profile=None):
        base = self._base_url()
        profile = self.reviewops_profile(reviewops_profile)
        if profile:
            return f"{base}/reviewops/saml/{profile}"
        return f"{base}/api/saml/metadata"

    def info(self, reviewops_profile=None):
        self._ensure_keypair()
        base = self._base_url()
        profile = self.reviewops_profile(reviewops_profile)
        entity = self.entity_id(profile)
        cert_body = self.get_cert_body()
        encryption_cert_body = self.get_encryption_cert_body()
        lifetime = self._metadata_lifetime()
        federation_url = f"{base}/api/saml/federation-metadata"
        if profile:
            federation_url = append_reviewops_profile(federation_url, profile)

        return {
            "entity_id": entity,
            "metadata_url": append_reviewops_profile(
                f"{base}/api/saml/metadata",
                profile,
            ),
            "sso_post": append_reviewops_profile(f"{base}/api/saml/sso", profile),
            "sso_redirect": append_reviewops_profile(f"{base}/api/saml/sso", profile),
            "slo_post": append_reviewops_profile(f"{base}/api/saml/slo", profile),
            "slo_redirect": append_reviewops_profile(f"{base}/api/saml/slo", profile),
            "certificate": cert_body,
            "signing_certificate": cert_body,
            "encryption_certificate": encryption_cert_body,
            "sign_algorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "metadata_signed": True,
            "metadata_valid_until": lifetime["valid_until_text"],
            "metadata_cache_seconds": lifetime["cache_seconds"],
            "federation_metadata": federation_url,
            "federation_name": str(self._idp_config_value(
                "SAML_FEDERATION_NAME",
                "Debug IdP Federation",
            )),
            "certificate_sha256": self._certificate_sha256(),
            "signing_certificate_sha256": self._certificate_sha256("signing"),
            "encryption_certificate_sha256": self._certificate_sha256("encryption"),
            "signing_certificate_info": self._certificate_info("signing"),
            "encryption_certificate_info": self._certificate_info("encryption"),
            "inbound_encryption_support": [
                "LogoutRequest EncryptedID",
                "AES-GCM",
                "RSA-OAEP",
            ],
            "organization": "Debug IdP",
            "contacts": ["technical@nanoha.kr", "security@nanoha.kr"],
            "content_encryption_algorithms": [
                "aes256-gcm", "aes192-gcm", "aes128-gcm",
                "aes256-cbc", "aes192-cbc", "aes128-cbc", "tripledes-cbc",
            ],
            "key_transport_algorithms": ["rsa-oaep-sha256", "rsa-oaep-sha1", "rsa-1_5"],
            "nameid_formats": [
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
                "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            ],
        }

    def generate_xml(self, reviewops_profile=None, metadata_variant=None):
        info = self.info(reviewops_profile)
        if metadata_variant is None:
            try:
                metadata_variant = wiz.request.query("metadata_variant", "standard")
            except Exception:
                metadata_variant = "standard"
        metadata_variant = str(metadata_variant or "standard")
        if metadata_variant not in ["standard", "unsigned", "bad_signature"]:
            raise ValueError("지원하지 않는 metadata_variant입니다.")

        nsmap = {
            None: NS_MD,
            "ds": NS_DS,
            "alg": NS_ALG,
            "remd": NS_REMD,
        }

        ed = etree.Element(f"{{{NS_MD}}}EntityDescriptor", nsmap=nsmap)
        ed.set("entityID", info["entity_id"])
        ed.set("ID", f"_idp_{hashlib.sha256(info['entity_id'].encode()).hexdigest()[:20]}")
        lifetime = self._metadata_lifetime()
        ed.set("validUntil", lifetime["valid_until_text"])
        ed.set("cacheDuration", lifetime["cache_duration"])

        idp_sso = etree.SubElement(ed, f"{{{NS_MD}}}IDPSSODescriptor")
        idp_sso.set("protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol")
        idp_sso.set("WantAuthnRequestsSigned", "false")

        extensions = etree.SubElement(idp_sso, f"{{{NS_MD}}}Extensions")
        for algorithm in ["http://www.w3.org/2001/04/xmlenc#sha256"]:
            digest = etree.SubElement(extensions, f"{{{NS_ALG}}}DigestMethod")
            digest.set("Algorithm", algorithm)
        for algorithm in ["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"]:
            signing = etree.SubElement(extensions, f"{{{NS_ALG}}}SigningMethod")
            signing.set("Algorithm", algorithm)
            signing.set("MinKeySize", "2048")

        kd = etree.SubElement(idp_sso, f"{{{NS_MD}}}KeyDescriptor")
        kd.set("use", "signing")
        ki = etree.SubElement(kd, f"{{{NS_DS}}}KeyInfo")
        x509d = etree.SubElement(ki, f"{{{NS_DS}}}X509Data")
        x509c = etree.SubElement(x509d, f"{{{NS_DS}}}X509Certificate")
        x509c.text = info["certificate"]

        encryption_kd = etree.SubElement(idp_sso, f"{{{NS_MD}}}KeyDescriptor")
        encryption_kd.set("use", "encryption")
        encryption_ki = etree.SubElement(encryption_kd, f"{{{NS_DS}}}KeyInfo")
        encryption_x509d = etree.SubElement(encryption_ki, f"{{{NS_DS}}}X509Data")
        encryption_x509c = etree.SubElement(encryption_x509d, f"{{{NS_DS}}}X509Certificate")
        encryption_x509c.text = info["encryption_certificate"]
        for algorithm in (
            INBOUND_CONTENT_ENCRYPTION_ALGORITHMS
            + INBOUND_KEY_TRANSPORT_ALGORITHMS
        ):
            method = etree.SubElement(encryption_kd, f"{{{NS_MD}}}EncryptionMethod")
            method.set("Algorithm", algorithm)
            if algorithm == "http://www.w3.org/2009/xmlenc11#rsa-oaep":
                # XML Encryption 1.1 otherwise defaults both values to SHA-1.
                # Publish the parameters this IdP prefers and accepts for the
                # modern URI; the legacy rsa-oaep-mgf1p entry intentionally
                # represents its standard fixed-MGF1-SHA1 compatibility mode.
                digest = etree.SubElement(method, f"{{{NS_DS}}}DigestMethod")
                digest.set("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
                mgf = etree.SubElement(
                    method,
                    "{http://www.w3.org/2009/xmlenc11#}MGF",
                )
                mgf.set("Algorithm", "http://www.w3.org/2009/xmlenc11#mgf1sha256")

        for binding, url_key in [(BINDING_POST, "slo_post"), (BINDING_REDIRECT, "slo_redirect")]:
            slo = etree.SubElement(idp_sso, f"{{{NS_MD}}}SingleLogoutService")
            slo.set("Binding", binding)
            slo.set("Location", info[url_key])

        for fmt in info["nameid_formats"]:
            nf = etree.SubElement(idp_sso, f"{{{NS_MD}}}NameIDFormat")
            nf.text = fmt

        for binding, url_key in [(BINDING_POST, "sso_post"), (BINDING_REDIRECT, "sso_redirect")]:
            sso = etree.SubElement(idp_sso, f"{{{NS_MD}}}SingleSignOnService")
            sso.set("Binding", binding)
            sso.set("Location", info[url_key])

        organization = etree.SubElement(ed, f"{{{NS_MD}}}Organization")
        for tag, text in [
            ("OrganizationName", "Test IdP"),
            ("OrganizationDisplayName", "Debug IdP"),
            ("OrganizationURL", self._base_url()),
        ]:
            item = etree.SubElement(organization, f"{{{NS_MD}}}{tag}")
            item.set("{http://www.w3.org/XML/1998/namespace}lang", "ko")
            item.text = text
        for contact_type, company, email in [
            ("technical", "Debug IdP Technical", "mailto:technical@nanoha.kr"),
            ("support", "Debug IdP Support", "mailto:support@nanoha.kr"),
            ("administrative", "Debug IdP Administrative", "mailto:administrative@nanoha.kr"),
            ("billing", "Debug IdP Billing", "mailto:billing@nanoha.kr"),
            ("other", "Debug IdP Security", "mailto:security@nanoha.kr"),
        ]:
            contact = etree.SubElement(ed, f"{{{NS_MD}}}ContactPerson")
            contact.set("contactType", contact_type)
            if contact_type == "other":
                contact_extensions = etree.SubElement(contact, f"{{{NS_MD}}}Extensions")
                security_type = etree.SubElement(contact_extensions, f"{{{NS_REMD}}}ContactType")
                security_type.text = "http://refeds.org/metadata/contactType/security"
            company_node = etree.SubElement(contact, f"{{{NS_MD}}}Company")
            company_node.text = company
            email_node = etree.SubElement(contact, f"{{{NS_MD}}}EmailAddress")
            email_node.text = email

        try:
            if metadata_variant == "unsigned":
                raise LookupError("unsigned metadata variant")
            signed = XMLSigner(
                method=methods.enveloped,
                signature_algorithm="rsa-sha256",
                digest_algorithm="sha256",
                c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
            ).sign(ed, key=self.get_key_pem(), cert=self.get_cert_pem(), reference_uri=ed.get("ID"))
            signature = signed.find(f"{{{NS_DS}}}Signature")
            if signature is not None:
                signed.remove(signature)
                signed.insert(0, signature)
            ed = signed
            if metadata_variant == "bad_signature":
                signature_value = ed.find(f".//{{{NS_DS}}}SignatureValue")
                if signature_value is not None and signature_value.text:
                    raw = bytearray(base64.b64decode(signature_value.text))
                    raw[-1] ^= 1
                    signature_value.text = base64.b64encode(bytes(raw)).decode("ascii")
        except LookupError:
            pass
        except Exception:
            # key material이 없는 단위 fixture는 기존 unsigned 출력과 호환한다.
            try:
                fs = self._cert_fs()
            except Exception:
                fs = None
            if fs is not None and callable(getattr(fs, "read", None)):
                raise

        xml_str = etree.tostring(ed, pretty_print=False, xml_declaration=True, encoding="UTF-8").decode("utf-8")
        return xml_str

    def federation_profiles(self, reviewops_profile=None, federation_name=None):
        profile = self.reviewops_profile(reviewops_profile)
        if federation_name is None:
            try:
                federation_name = wiz.request.query("federation", "")
            except Exception:
                federation_name = ""
        federation_name = str(federation_name or "").strip()
        if profile and federation_name:
            raise ValueError("reviewops_profile과 federation은 동시에 지정할 수 없습니다.")
        if profile:
            return [profile]
        if federation_name:
            federation = self.get_federation(federation_name)
            if federation is None:
                raise ValueError("Federation 구성을 찾을 수 없습니다.")
            profiles = [""] if federation["include_base"] else []
            profiles.extend(federation["profiles"])
            return profiles
        profiles = [""]
        for item in self.list_response_profiles():
            name = self.reviewops_profile(item.get("name", ""))
            if name and name not in profiles:
                profiles.append(name)
        if len(profiles) > MAX_FEDERATION_ENTITIES:
            raise ValueError(
                f"federation metadata는 최대 {MAX_FEDERATION_ENTITIES}개 EntityDescriptor를 포함할 수 있습니다."
            )
        return profiles

    def federation_info(self, reviewops_profile=None, federation_name=None):
        profiles = self.federation_profiles(reviewops_profile, federation_name)
        lifetime = self._metadata_lifetime()
        base = self._base_url()
        selected_profile = self.reviewops_profile(reviewops_profile)
        endpoint = f"{base}/api/saml/federation-metadata"
        if selected_profile:
            endpoint = append_reviewops_profile(endpoint, selected_profile)
        selected_federation = str(federation_name or "").strip()
        if selected_federation:
            selected_federation = self.normalize_federation_name(selected_federation)
            endpoint = self._federation_url(selected_federation)
        return {
            "name": selected_federation or str(self._idp_config_value(
                "SAML_FEDERATION_NAME", "Debug IdP Federation",
            )),
            "federation": selected_federation,
            "endpoint": endpoint,
            "entity_count": len(profiles),
            "entities": [
                {
                    "reviewops_profile": profile,
                    "entity_id": self.entity_id(profile),
                }
                for profile in profiles
            ],
            "valid_until": lifetime["valid_until_text"],
            "cache_seconds": lifetime["cache_seconds"],
            "signature_algorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "signing_certificate_sha256": self._certificate_sha256(),
        }

    def generate_federation_xml(
        self,
        reviewops_profile=None,
        metadata_variant=None,
        federation_name=None,
    ):
        profiles = self.federation_profiles(reviewops_profile, federation_name)
        if metadata_variant is None:
            try:
                metadata_variant = wiz.request.query("metadata_variant", "standard")
            except Exception:
                metadata_variant = "standard"
        metadata_variant = str(metadata_variant or "standard")
        if metadata_variant not in ["standard", "unsigned", "bad_signature"]:
            raise ValueError("지원하지 않는 metadata_variant입니다.")
        parser = etree.XMLParser(
            resolve_entities=False,
            no_network=True,
            load_dtd=False,
            huge_tree=False,
        )
        entities = etree.Element(
            f"{{{NS_MD}}}EntitiesDescriptor",
            nsmap={None: NS_MD, "ds": NS_DS},
        )
        selected_federation = str(federation_name or "").strip()
        federation_name = (
            self.normalize_federation_name(selected_federation)
            if selected_federation else str(self._idp_config_value(
                "SAML_FEDERATION_NAME", "Debug IdP Federation",
            ))
        )
        lifetime = self._metadata_lifetime()
        entities.set("Name", federation_name)
        entities.set("ID", f"_federation_{hashlib.sha256(federation_name.encode()).hexdigest()[:20]}")
        entities.set("validUntil", lifetime["valid_until_text"])
        entities.set("cacheDuration", lifetime["cache_duration"])
        for profile in profiles:
            entity = etree.fromstring(
                self.generate_xml(profile, metadata_variant="unsigned").encode("utf-8"),
                parser=parser,
            )
            entities.append(entity)
        try:
            if metadata_variant == "unsigned":
                raise LookupError("unsigned metadata variant")
            entities = XMLSigner(
                method=methods.enveloped,
                signature_algorithm="rsa-sha256",
                digest_algorithm="sha256",
                c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
            ).sign(
                entities,
                key=self.get_key_pem(),
                cert=self.get_cert_pem(),
                reference_uri=entities.get("ID"),
            )
            signature = entities.find(f"{{{NS_DS}}}Signature")
            if signature is not None:
                entities.remove(signature)
                entities.insert(0, signature)
            if metadata_variant == "bad_signature":
                signature_value = entities.find(f".//{{{NS_DS}}}SignatureValue")
                if signature_value is not None and signature_value.text:
                    raw = bytearray(base64.b64decode(signature_value.text))
                    raw[-1] ^= 1
                    signature_value.text = base64.b64encode(bytes(raw)).decode("ascii")
        except LookupError:
            pass
        except Exception:
            try:
                fs = self._cert_fs()
            except Exception:
                fs = None
            if fs is not None and callable(getattr(fs, "read", None)):
                raise
        return etree.tostring(
            entities,
            pretty_print=False,
            xml_declaration=True,
            encoding="UTF-8",
        ).decode("utf-8")


Model = Metadata
