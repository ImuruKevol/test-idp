import datetime
import hashlib
import json
import re


SAML_PRIVATE_OID_BASE = "1.3.6.1.4.1.55555.100"
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
        lowered = value.lower()

        if lowered.startswith("urn:oid:"):
            oid = value[8:].strip()
            if oid in oid_map:
                return dict(oid_map[oid])
            return {
                "friendly_name": "",
                "oid": oid,
                "urn": f"urn:oid:{oid}",
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
                "aliases": [value],
                "description": "OID attribute",
            }

        if lowered in alias_map:
            return dict(alias_map[lowered])

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