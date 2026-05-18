import datetime
import hashlib
import importlib
import json
import re


SAML_PRIVATE_OID_BASE = "1.3.6.1.4.1.55555.100"
SAML_URI_NAME_FORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
PYSAML2_ATTRIBUTE_MAP_MODULES = [
    "saml2.attributemaps.saml_uri",
    "saml2.attributemaps.basic",
    "saml2.attributemaps.shibboleth_uri",
    "saml2.attributemaps.adfs_v20",
    "saml2.attributemaps.adfs_v1x",
]
OIDC_CLAIM_ALIASES = {
    "uid": "preferred_username",
    "userid": "preferred_username",
    "username": "preferred_username",
    "mail": "email",
    "email": "email",
    "emailaddress": "email",
    "displayname": "name",
    "cn": "name",
    "commonname": "name",
    "givenname": "given_name",
    "firstname": "given_name",
    "sn": "family_name",
    "surname": "family_name",
    "familyname": "family_name",
    "lastname": "family_name",
    "departmentnumber": "department",
    "department": "department",
    "memberof": "groups",
    "group": "groups",
    "groups": "groups",
    "testidpprofile": "profile",
}
SAML_ATTRIBUTE_SPECS = [
    {
        "friendly_name": "uid",
        "oid": "0.9.2342.19200300.100.1.1",
        "aliases": ["uid", "user_id", "userid", "username"],
        "description": "User identifier",
        "example": "alice",
    },
    {
        "friendly_name": "mail",
        "oid": "0.9.2342.19200300.100.1.3",
        "aliases": ["mail", "email", "emailaddress"],
        "description": "Email address",
        "example": "alice@test-idp.local",
    },
    {
        "friendly_name": "displayName",
        "oid": "2.16.840.1.113730.3.1.241",
        "aliases": ["displayname", "display_name"],
        "description": "Display name",
        "example": "Alice Example",
    },
    {
        "friendly_name": "givenName",
        "oid": "2.5.4.42",
        "aliases": ["givenname", "given_name", "firstname", "first_name"],
        "description": "Given name",
        "example": "Alice",
    },
    {
        "friendly_name": "sn",
        "oid": "2.5.4.4",
        "aliases": ["sn", "surname", "familyname", "family_name", "lastname", "last_name"],
        "description": "Surname",
        "example": "Example",
    },
    {
        "friendly_name": "cn",
        "oid": "2.5.4.3",
        "aliases": ["cn", "commonname", "common_name"],
        "description": "Common name",
        "example": "Alice Example",
    },
    {
        "friendly_name": "eduPersonPrincipalName",
        "oid": "1.3.6.1.4.1.5923.1.1.1.6",
        "aliases": ["edupersonprincipalname", "eppn"],
        "description": "eduPerson principal name",
        "example": "alice@test-idp.local",
    },
    {
        "friendly_name": "eduPersonAffiliation",
        "oid": "1.3.6.1.4.1.5923.1.1.1.1",
        "aliases": ["edupersonaffiliation"],
        "description": "eduPerson affiliation",
        "example": ["member"],
    },
    {
        "friendly_name": "eduPersonScopedAffiliation",
        "oid": "1.3.6.1.4.1.5923.1.1.1.9",
        "aliases": ["edupersonscopedaffiliation"],
        "description": "eduPerson scoped affiliation",
        "example": ["member@test-idp.local"],
    },
    {
        "friendly_name": "eduPersonEntitlement",
        "oid": "1.3.6.1.4.1.5923.1.1.1.7",
        "aliases": ["edupersonentitlement"],
        "description": "eduPerson entitlement",
        "example": ["urn:test-idp:entitlement:full-access"],
    },
    {
        "friendly_name": "departmentNumber",
        "oid": "2.16.840.1.113730.3.1.2",
        "aliases": ["departmentnumber", "department_number", "department"],
        "description": "Department number or code",
        "example": "engineering",
    },
    {
        "friendly_name": "memberOf",
        "oid": "1.2.840.113556.1.2.102",
        "aliases": ["memberof", "groups", "group"],
        "description": "Group memberships",
        "example": ["developers", "testers"],
    },
    {
        "friendly_name": "testIdpProfile",
        "oid": f"{SAML_PRIVATE_OID_BASE}.1",
        "aliases": ["profile", "testidpprofile"],
        "description": "test-idp custom profile payload",
        "example": {"department": "engineering", "groups": ["developers"]},
        "custom": True,
    },
]


class Struct:
    def __init__(self):
        self.package = "idpcore"
        self.orm = wiz.model("portal/season/orm")
        self.session = wiz.model("portal/season/session").use()

        self._User = wiz.model("portal/idpcore/struct/user")
        self._AttributePreset = wiz.model("portal/idpcore/struct/attribute_preset")
        self._DebugPayload = wiz.model("portal/idpcore/struct/debug_payload")
        self._Audit = wiz.model("portal/idpcore/struct/audit")

        self._init_tables()
        try:
            self.seed(force=False)
        except Exception:
            pass

    def _init_tables(self):
        for name in [
            "idp_user",
            "idp_attribute_preset",
            "idp_debug_payload",
            "idp_audit_log",
        ]:
            try:
                db = self.orm.use(name, module="idpcore")
                db.orm.create_table(safe=True)
            except Exception:
                pass
        self._migrate_columns()
        self._normalize_existing_saml_data()

    def _migrate_columns(self):
        try:
            db = self.orm.use("idp_user", module="idpcore")
            database = db.orm._meta.database
            cursor = database.execute_sql("PRAGMA table_info('idp_user')")
            existing = [row[1] for row in cursor.fetchall()]
            if "created_by_ip" not in existing:
                database.execute_sql('ALTER TABLE "idp_user" ADD COLUMN "created_by_ip" VARCHAR(45) DEFAULT ""')
        except Exception:
            pass

    def db(self, name):
        return self.orm.use(name, module="idpcore")

    def now(self):
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def hash_password(self, password):
        return hashlib.sha256(str(password).encode("utf-8")).hexdigest()

    def normalize_json(self, value, default=None):
        if value is None:
            return default
        if isinstance(value, (dict, list)):
            return value
        if value == "":
            return default
        try:
            return json.loads(value)
        except Exception:
            return default

    def normalize_object(self, value, default=None):
        if default is None:
            default = {}
        value = self.normalize_json(value, default)
        if isinstance(value, dict):
            return value
        return default

    def normalize_array(self, value, default=None):
        if default is None:
            default = []
        value = self.normalize_json(value, default)
        if isinstance(value, list):
            return value
        return default

    def _saml_attribute_catalog_index(self):
        oid_map = {}
        alias_map = {}
        for spec in SAML_ATTRIBUTE_SPECS:
            item = dict(spec)
            item["urn"] = f"urn:oid:{item['oid']}"
            item["name"] = item["urn"]
            item["name_format"] = SAML_URI_NAME_FORMAT
            item["oidc_claim_key"] = self.oidc_claim_key_for_saml_attribute(item)
            aliases = []
            for alias in [item.get("friendly_name", "")] + list(item.get("aliases", [])):
                alias = str(alias or "").strip()
                if alias == "":
                    continue
                aliases.append(alias)
                alias_map[alias.lower()] = item
            item["aliases"] = aliases
            oid_map[item["oid"]] = item
        return oid_map, alias_map

    def saml_attribute_catalog(self):
        oid_map, _ = self._saml_attribute_catalog_index()
        return [dict(oid_map[key]) for key in oid_map]

    def _normalize_attribute_alias(self, value):
        return re.sub(r"[^A-Za-z0-9]+", "", str(value or "").strip()).lower()

    def oidc_claim_key_for_saml_attribute(self, attr):
        aliases = list(attr.get("aliases", []) or [])
        names = [attr.get("friendly_name", "")] + aliases
        for name in names:
            normalized = self._normalize_attribute_alias(name)
            if normalized in OIDC_CLAIM_ALIASES:
                return OIDC_CLAIM_ALIASES[normalized]

        friendly_name = str(attr.get("friendly_name", "") or "").strip()
        if friendly_name:
            return friendly_name
        return str(attr.get("name", attr.get("urn", "")) or "").strip()

    def _attribute_example(self, attr):
        key = self.oidc_claim_key_for_saml_attribute(attr)
        examples = {
            "preferred_username": "alice",
            "email": "alice@test-idp.local",
            "name": "Alice Example",
            "given_name": "Alice",
            "family_name": "Example",
            "department": "engineering",
            "groups": ["developers", "testers"],
            "profile": {"department": "engineering", "groups": ["developers"]},
        }
        if key in examples:
            return examples[key]
        friendly_name = str(attr.get("friendly_name", "") or "").lower()
        if "affiliation" in friendly_name:
            return ["member"]
        if "entitlement" in friendly_name:
            return ["urn:test-idp:entitlement:full-access"]
        if "date" in friendly_name:
            return "2000-01-01"
        return "example-value"

    def pysaml2_attribute_catalog(self, strict=True):
        catalog = {}
        errors = []
        for module_name in PYSAML2_ATTRIBUTE_MAP_MODULES:
            try:
                module = importlib.import_module(module_name)
            except Exception as e:
                errors.append(str(e))
                continue

            attribute_map = getattr(module, "MAP", {}) or {}
            name_format = str(attribute_map.get("identifier", "") or SAML_URI_NAME_FORMAT)
            to_map = attribute_map.get("to", {}) or {}
            fro_map = attribute_map.get("fro", {}) or {}
            source = module_name.rsplit(".", 1)[-1]

            for friendly_name, saml_name in to_map.items():
                friendly_name = str(friendly_name or "").strip()
                saml_name = str(saml_name or "").strip()
                if saml_name == "":
                    continue
                key = f"{name_format}|{saml_name}"
                if key not in catalog:
                    catalog[key] = {
                        "friendly_name": friendly_name or fro_map.get(saml_name, ""),
                        "name": saml_name,
                        "urn": saml_name,
                        "oid": saml_name[8:] if saml_name.lower().startswith("urn:oid:") else "",
                        "name_format": name_format,
                        "aliases": [],
                        "source": source,
                        "sources": [],
                        "description": "pysaml2 attribute map",
                    }
                item = catalog[key]
                if source not in item["sources"]:
                    item["sources"].append(source)
                if friendly_name and friendly_name not in item["aliases"]:
                    item["aliases"].append(friendly_name)

            for saml_name, friendly_name in fro_map.items():
                saml_name = str(saml_name or "").strip()
                friendly_name = str(friendly_name or "").strip()
                if saml_name == "":
                    continue
                key = f"{name_format}|{saml_name}"
                if key not in catalog:
                    catalog[key] = {
                        "friendly_name": friendly_name,
                        "name": saml_name,
                        "urn": saml_name,
                        "oid": saml_name[8:] if saml_name.lower().startswith("urn:oid:") else "",
                        "name_format": name_format,
                        "aliases": [],
                        "source": source,
                        "sources": [],
                        "description": "pysaml2 attribute map",
                    }
                item = catalog[key]
                if source not in item["sources"]:
                    item["sources"].append(source)
                if friendly_name and friendly_name not in item["aliases"]:
                    item["aliases"].append(friendly_name)

        if not catalog and strict:
            raise Exception("pysaml2 attribute map을 불러올 수 없습니다: " + "; ".join(errors))

        items = []
        for item in catalog.values():
            aliases = []
            for alias in [item.get("friendly_name", "")] + list(item.get("aliases", [])):
                alias = str(alias or "").strip()
                if alias and alias not in aliases:
                    aliases.append(alias)
            item["aliases"] = aliases
            item["oidc_claim_key"] = self.oidc_claim_key_for_saml_attribute(item)
            item["example"] = self._attribute_example(item)
            items.append(item)

        return sorted(items, key=lambda x: (
            str(x.get("friendly_name", "") or "").lower(),
            str(x.get("name", "") or "").lower(),
        ))

    def _pysaml2_attribute_catalog_index(self):
        name_map = {}
        alias_map = {}
        for item in self.pysaml2_attribute_catalog(strict=False):
            name = str(item.get("name", "") or "").strip()
            if name:
                name_map[name] = item
            for alias in item.get("aliases", []) or []:
                alias = str(alias or "").strip()
                if alias:
                    alias_map[alias.lower()] = item
        return name_map, alias_map

    def _sanitize_saml_friendly_name(self, value):
        friendly_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or "").strip())
        friendly_name = friendly_name.strip("_")
        if friendly_name == "":
            friendly_name = "customAttribute"
        if re.match(r"^[0-9]", friendly_name):
            friendly_name = f"attr_{friendly_name}"
        return friendly_name

    def _private_saml_attribute_spec(self, name):
        friendly_name = self._sanitize_saml_friendly_name(name)
        digest = hashlib.sha1(friendly_name.lower().encode("utf-8")).hexdigest()
        oid = f"{SAML_PRIVATE_OID_BASE}.{int(digest[:12], 16)}"
        return {
            "friendly_name": friendly_name,
            "oid": oid,
            "urn": f"urn:oid:{oid}",
            "name": f"urn:oid:{oid}",
            "name_format": SAML_URI_NAME_FORMAT,
            "aliases": [friendly_name],
            "description": "test-idp custom attribute",
            "example": "custom-value",
            "custom": True,
        }

    def saml_attribute_spec(self, name, allow_custom=True):
        value = str(name or "").strip()
        if value == "":
            return None

        oid_map, alias_map = self._saml_attribute_catalog_index()
        pysaml2_name_map, pysaml2_alias_map = self._pysaml2_attribute_catalog_index()
        lowered = value.lower()

        if lowered.startswith("urn:oid:"):
            oid = value[8:].strip()
            if oid in oid_map:
                return dict(oid_map[oid])
            if value in pysaml2_name_map:
                return dict(pysaml2_name_map[value])
            return {
                "friendly_name": "",
                "oid": oid,
                "urn": f"urn:oid:{oid}",
                "name": f"urn:oid:{oid}",
                "name_format": SAML_URI_NAME_FORMAT,
                "aliases": [value],
                "description": "OID attribute",
            }

        if re.fullmatch(r"\d+(?:\.\d+)+", value):
            if value in oid_map:
                return dict(oid_map[value])
            return {
                "friendly_name": "",
                "oid": value,
                "urn": f"urn:oid:{value}",
                "name": f"urn:oid:{value}",
                "name_format": SAML_URI_NAME_FORMAT,
                "aliases": [value],
                "description": "OID attribute",
            }

        if lowered in alias_map:
            return dict(alias_map[lowered])

        if value in pysaml2_name_map:
            return dict(pysaml2_name_map[value])

        if lowered in pysaml2_alias_map:
            return dict(pysaml2_alias_map[lowered])

        if allow_custom is False:
            return None

        return self._private_saml_attribute_spec(value)

    def normalize_saml_attributes(self, value, default=None, allow_custom=True):
        if default is None:
            default = {}
        attrs = self.normalize_object(value, default)
        normalized = {}
        for raw_name, raw_value in attrs.items():
            spec = self.saml_attribute_spec(raw_name, allow_custom=allow_custom)
            if spec is None:
                continue
            normalized[spec["urn"]] = raw_value
        return normalized

    def normalize_saml_preset_payload(self, value):
        payload = self.normalize_object(value, {})
        attributes = self.normalize_object(payload.get("attributes"), {})
        if attributes:
            payload["attributes"] = self.normalize_saml_attributes(attributes)
        return payload

    def default_temporary_profile(self, data):
        profile = self.normalize_object(data.get("profile"), {})
        if not profile.get("department"):
            profile["department"] = "testing"
        if not profile.get("groups"):
            profile["groups"] = ["testers"]
        if not profile.get("organization"):
            profile["organization"] = "Test IDP"
        return profile

    def _split_display_name(self, display_name, username):
        parts = [p for p in str(display_name or "").strip().split(" ") if p]
        if not parts and username:
            parts = [username]
        given_name = parts[0] if parts else "Test"
        family_name = parts[-1] if len(parts) > 1 else "Tester"
        return given_name, family_name

    def default_saml_attribute_value(self, spec, data):
        username = str(data.get("username", "") or "").strip()
        email = str(data.get("email", "") or "").strip() or (f"{username}@test-idp.local" if username else "")
        display_name = str(data.get("display_name", "") or "").strip() or username
        profile = self.default_temporary_profile(data)
        given_name, family_name = self._split_display_name(display_name, username)
        friendly_name = str(spec.get("friendly_name", "") or "")
        normalized = self._normalize_attribute_alias(friendly_name)

        if normalized == "uid":
            return username
        if normalized == "mail":
            return email
        if normalized in ["displayname", "cn"]:
            return display_name
        if normalized == "givenname":
            return profile.get("given_name") or given_name
        if normalized == "sn":
            return profile.get("family_name") or family_name
        if normalized == "edupersonprincipalname":
            return email or (f"{username}@test-idp.local" if username else "")
        if normalized == "edupersonaffiliation":
            return profile.get("affiliation") or ["member"]
        if normalized == "edupersonscopedaffiliation":
            return profile.get("scoped_affiliation") or ["member@test-idp.local"]
        if normalized == "edupersonentitlement":
            return profile.get("entitlements") or ["urn:test-idp:entitlement:full-access"]
        if normalized == "departmentnumber":
            return profile.get("department", "testing")
        if normalized == "memberof":
            return profile.get("groups", ["testers"])
        if normalized == "testidpprofile":
            return profile
        return spec.get("example", "example-value")

    def default_temporary_saml_attributes(self, data):
        attrs = {}
        for spec in self.saml_attribute_catalog():
            attrs[spec["urn"]] = self.default_saml_attribute_value(spec, data)
        return attrs

    def default_temporary_oidc_claims(self, data):
        claims = {}
        for spec in self.saml_attribute_catalog():
            claim_key = self.oidc_claim_key_for_saml_attribute(spec)
            if claim_key:
                claims[claim_key] = self.default_saml_attribute_value(spec, data)
        return claims

    def _normalize_existing_saml_data(self):
        try:
            db = self.db("idp_user")
            rows = db.rows()
            for row in rows:
                current = self.normalize_object(row.get("saml_attributes"), {})
                normalized = self.normalize_saml_attributes(current)
                if normalized == current:
                    continue
                db.update({
                    "saml_attributes": normalized,
                    "updated": self.now(),
                }, id=row["id"])
        except Exception:
            pass

        try:
            db = self.db("idp_attribute_preset")
            rows = db.rows(protocol="saml")
            for row in rows:
                payload = self.normalize_object(row.get("payload"), {})
                normalized = self.normalize_saml_preset_payload(payload)
                if normalized == payload:
                    continue
                db.update({
                    "payload": normalized,
                    "updated": self.now(),
                }, id=row["id"])
        except Exception:
            pass

    def current_actor_id(self):
        return self.session.get("id", "")

    def seed(self, force=False):
        return {
            "users": self.user.seed_samples(force=force),
            "attribute_presets": self.attribute_preset.seed_defaults(force=force),
        }

    def info(self):
        return {
            "package": self.package,
            "ready": True,
            "counts": {
                "user": self.db("idp_user").count() or 0,
                "attribute_preset": self.db("idp_attribute_preset").count() or 0,
                "debug_payload": self.db("idp_debug_payload").count() or 0,
                "audit": self.db("idp_audit_log").count() or 0,
            },
        }

    @property
    def user(self):
        return self._User(self)

    @property
    def attribute_preset(self):
        return self._AttributePreset(self)

    @property
    def debug_payload(self):
        return self._DebugPayload(self)

    @property
    def audit(self):
        return self._Audit(self)


Model = Struct()
