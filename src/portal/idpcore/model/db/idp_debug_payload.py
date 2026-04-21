import peewee as pw

orm = wiz.model("portal/season/orm")
base = orm.base("idpcore")


class Model(base):
    class Meta:
        db_table = "idp_debug_payload"

    id = pw.CharField(max_length=32, primary_key=True)
    key = pw.CharField(max_length=64, unique=True, index=True)
    protocol = pw.CharField(max_length=16, default="common", index=True)
    category = pw.CharField(max_length=64, default="general", index=True)
    target_type = pw.CharField(max_length=64, default="", index=True)
    target_id = pw.CharField(max_length=64, default="", index=True)
    payload_format = pw.CharField(max_length=32, default="json")
    summary = base.JSONObject(default=dict)
    raw_path = pw.CharField(max_length=255, default="")
    expires = pw.DateTimeField(null=True, index=True)
    created = pw.DateTimeField(index=True)