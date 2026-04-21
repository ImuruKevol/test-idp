class DebugPayload:
    def __init__(self, core):
        self.core = core
        self.db = core.db("idp_debug_payload")

    def list(self, protocol="", category="", target_type="", target_id=""):
        kwargs = dict(orderby="created", order="DESC")
        if protocol:
            kwargs["protocol"] = protocol
        if category:
            kwargs["category"] = category
        if target_type:
            kwargs["target_type"] = target_type
        if target_id:
            kwargs["target_id"] = target_id
        return self.db.rows(**kwargs)

    def get(self, id=None, key=None):
        if id:
            return self.db.get(id=id)
        if key:
            return self.db.get(key=key)
        return None

    def create(self, data):
        item = dict(data)
        item["key"] = str(item.get("key", self._generate_key())).strip()
        if item["key"] == "":
            raise Exception("key is required")

        item["protocol"] = str(item.get("protocol", "common")).strip() or "common"
        item["category"] = str(item.get("category", "general")).strip() or "general"
        item["target_type"] = str(item.get("target_type", "")).strip()
        item["target_id"] = str(item.get("target_id", "")).strip()
        item["payload_format"] = str(item.get("payload_format", "json")).strip() or "json"
        item["summary"] = self.core.normalize_object(item.get("summary"), {})
        item["raw_path"] = str(item.get("raw_path", "")).strip()
        item["created"] = self.core.now()

        expires = item.get("expires")
        if expires in ["", None]:
            item["expires"] = None

        return self.db.insert(item)

    def update(self, data, id=None, key=None):
        item = dict(data)
        if "summary" in item:
            item["summary"] = self.core.normalize_object(item.get("summary"), {})
        if "raw_path" in item:
            item["raw_path"] = str(item.get("raw_path", "")).strip()
        if "payload_format" in item:
            item["payload_format"] = str(item.get("payload_format", "json")).strip() or "json"
        self.db.update(item, **self._where(id=id, key=key))

    def delete(self, id=None, key=None):
        self.db.delete(**self._where(id=id, key=key))

    def _generate_key(self):
        return f"dbg-{self.db.random(24)}"

    def _where(self, id=None, key=None):
        if id:
            return {"id": id}
        if key:
            return {"key": key}
        raise Exception("id or key is required")


Model = DebugPayload