class Audit:
    def __init__(self, core):
        self.core = core
        self.db = core.db("idp_audit_log")

    def list(self, protocol="", action="", status="", actor_id="", target_type="", target_id=""):
        kwargs = dict(orderby="created", order="DESC")
        if protocol:
            kwargs["protocol"] = protocol
        if action:
            kwargs["action"] = action
        if status:
            kwargs["status"] = status
        if actor_id:
            kwargs["actor_id"] = actor_id
        if target_type:
            kwargs["target_type"] = target_type
        if target_id:
            kwargs["target_id"] = target_id
        return self.db.rows(**kwargs)

    def get(self, id):
        return self.db.get(id=id)

    def create(self, data):
        item = dict(data)
        action = str(item.get("action", "")).strip()
        if action == "":
            raise Exception("action is required")

        item["protocol"] = str(item.get("protocol", "common")).strip() or "common"
        item["action"] = action
        item["actor_id"] = str(item.get("actor_id", self.core.current_actor_id())).strip()
        item["target_type"] = str(item.get("target_type", "")).strip()
        item["target_id"] = str(item.get("target_id", "")).strip()
        item["status"] = str(item.get("status", "success")).strip() or "success"
        item["message"] = str(item.get("message", "")).strip()
        item["payload"] = self.core.normalize_object(item.get("payload"), {})
        item["created"] = self.core.now()
        return self.db.insert(item)

    def log(self, action, **kwargs):
        payload = dict(kwargs)
        payload["action"] = action
        return self.create(payload)

    def delete(self, id):
        self.db.delete(id=id)


Model = Audit