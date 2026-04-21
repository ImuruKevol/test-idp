import peewee as pw

orm = wiz.model("portal/season/orm")
base = orm.base("idpcore")


class Model(base):
    class Meta:
        db_table = "idp_audit_log"

    id = pw.CharField(max_length=32, primary_key=True)
    protocol = pw.CharField(max_length=16, default="common", index=True)
    action = pw.CharField(max_length=64, index=True)
    actor_id = pw.CharField(max_length=64, default="", index=True)
    target_type = pw.CharField(max_length=64, default="", index=True)
    target_id = pw.CharField(max_length=64, default="", index=True)
    status = pw.CharField(max_length=32, default="success", index=True)
    message = base.TextField(default="")
    payload = base.JSONObject(default=dict)
    created = pw.DateTimeField(index=True)