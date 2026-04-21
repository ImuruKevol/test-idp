class AttributePreset:
    def __init__(self, core):
        self.core = core
        self.db = core.db("idp_attribute_preset")

    def list(self, protocol=""):
        kwargs = dict(orderby="created", order="ASC")
        if protocol:
            kwargs["protocol"] = protocol
        return self.db.rows(**kwargs)

    def get(self, id=None, protocol="", name=""):
        if id:
            return self.db.get(id=id)
        if protocol and name:
            return self.db.get(protocol=protocol, name=name)
        return None

    def create(self, data):
        item = dict(data)
        protocol = str(item.get("protocol", "")).strip()
        name = str(item.get("name", "")).strip()
        if protocol == "" or name == "":
            raise Exception("protocol and name are required")

        now = self.core.now()
        item["protocol"] = protocol
        item["name"] = name
        item["payload"] = self.core.normalize_json(item.get("payload"), {})
        if protocol == "saml":
            item["payload"] = self.core.normalize_saml_preset_payload(item["payload"])
        item["created"] = now
        item["updated"] = now
        return self.db.insert(item)

    def update(self, data, id=None, protocol="", name=""):
        item = dict(data)
        if "payload" in item:
            item["payload"] = self.core.normalize_json(item.get("payload"), {})
            preset = self.get(id=id, protocol=protocol, name=name)
            target_protocol = protocol or (preset.get("protocol", "") if preset else "")
            if target_protocol == "saml":
                item["payload"] = self.core.normalize_saml_preset_payload(item["payload"])
        item["updated"] = self.core.now()
        self.db.update(item, **self._where(id=id, protocol=protocol, name=name))

    def delete(self, id=None, protocol="", name=""):
        self.db.delete(**self._where(id=id, protocol=protocol, name=name))

    def seed_defaults(self, force=False):
        results = []
        for preset in self.default_presets():
            current = self.get(protocol=preset["protocol"], name=preset["name"])
            if current is None:
                preset_id = self.create(preset)
                results.append({
                    "protocol": preset["protocol"],
                    "name": preset["name"],
                    "id": preset_id,
                    "action": "created",
                })
                continue

            if force is False:
                results.append({
                    "protocol": preset["protocol"],
                    "name": preset["name"],
                    "id": current["id"],
                    "action": "skipped",
                })
                continue

            self.update({"payload": preset["payload"]}, protocol=preset["protocol"], name=preset["name"])
            current = self.get(protocol=preset["protocol"], name=preset["name"])
            results.append({
                "protocol": preset["protocol"],
                "name": preset["name"],
                "id": current["id"],
                "action": "updated",
            })
        return results

    def default_presets(self):
        return [
            {
                "protocol": "saml",
                "name": "minimal",
                "payload": {
                    "attributes": {
                        "urn:oid:0.9.2342.19200300.100.1.1": "{{username}}",
                        "urn:oid:0.9.2342.19200300.100.1.3": "{{email}}",
                        "urn:oid:2.16.840.1.113730.3.1.241": "{{display_name}}",
                    }
                },
            },
            {
                "protocol": "saml",
                "name": "eduPerson-basic",
                "payload": {
                    "attributes": {
                        "urn:oid:1.3.6.1.4.1.5923.1.1.1.6": "{{username}}@test-idp.local",
                        "urn:oid:1.3.6.1.4.1.5923.1.1.1.1": ["member"],
                        "urn:oid:2.5.4.42": "{{profile.given_name}}",
                        "urn:oid:2.5.4.4": "{{profile.family_name}}",
                        "urn:oid:0.9.2342.19200300.100.1.3": "{{email}}",
                    }
                },
            },
            {
                "protocol": "saml",
                "name": "eduPerson-full",
                "payload": {
                    "attributes": {
                        "urn:oid:1.3.6.1.4.1.5923.1.1.1.6": "{{username}}@test-idp.local",
                        "urn:oid:1.3.6.1.4.1.5923.1.1.1.9": ["member@test-idp.local", "employee@test-idp.local"],
                        "urn:oid:1.3.6.1.4.1.5923.1.1.1.7": ["urn:test-idp:entitlement:full-access"],
                        "urn:oid:2.16.840.1.113730.3.1.241": "{{display_name}}",
                        "urn:oid:0.9.2342.19200300.100.1.3": "{{email}}",
                        "urn:oid:2.16.840.1.113730.3.1.2": "{{profile.department}}",
                    }
                },
            },
            {
                "protocol": "saml",
                "name": "custom-json",
                "payload": {
                    "attributes": {
                        "urn:oid:1.3.6.1.4.1.55555.100.1": "{{profile}}",
                        "urn:oid:1.2.840.113556.1.2.102": "{{profile.groups}}",
                    }
                },
            },
            {
                "protocol": "oidc",
                "name": "openid-basic",
                "payload": {
                    "claims": {
                        "sub": "{{id}}",
                        "preferred_username": "{{username}}",
                    }
                },
            },
            {
                "protocol": "oidc",
                "name": "profile",
                "payload": {
                    "claims": {
                        "sub": "{{id}}",
                        "name": "{{display_name}}",
                        "preferred_username": "{{username}}",
                        "profile": "{{profile}}",
                    }
                },
            },
            {
                "protocol": "oidc",
                "name": "email",
                "payload": {
                    "claims": {
                        "sub": "{{id}}",
                        "email": "{{email}}",
                        "email_verified": True,
                    }
                },
            },
            {
                "protocol": "oidc",
                "name": "groups",
                "payload": {
                    "claims": {
                        "sub": "{{id}}",
                        "groups": "{{profile.groups}}",
                    }
                },
            },
            {
                "protocol": "oidc",
                "name": "academic-profile",
                "payload": {
                    "claims": {
                        "sub": "{{id}}",
                        "name": "{{display_name}}",
                        "email": "{{email}}",
                        "zoneinfo": "Asia/Seoul",
                        "organization": "{{profile.organization}}",
                        "department": "{{profile.department}}",
                    }
                },
            },
        ]

    def _where(self, id=None, protocol="", name=""):
        if id:
            return {"id": id}
        if protocol and name:
            return {"protocol": protocol, "name": name}
        raise Exception("id or protocol/name is required")


Model = AttributePreset