import peewee as pw

orm = wiz.model("portal/season/orm")
base = orm.base("idpcore")


class Model(base):
    class Meta:
        db_table = "idp_attribute_preset"
        indexes = (
            (("protocol", "name"), True),
        )

    id = pw.CharField(max_length=32, primary_key=True)
    protocol = pw.CharField(max_length=16, index=True)
    name = pw.CharField(max_length=64)
    payload = base.JSONObject(default=dict)
    created = pw.DateTimeField(index=True)
    updated = pw.DateTimeField(index=True)