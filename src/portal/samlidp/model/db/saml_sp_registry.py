import peewee as pw

orm = wiz.model("portal/season/orm")
base = orm.base("samlidp")


class Model(base):
    class Meta:
        db_table = "saml_sp_registry"

    id = pw.CharField(max_length=32, primary_key=True)
    entity_id = pw.CharField(max_length=512, unique=True, index=True)
    acs_url = base.JSONObject(default=list)
    slo_url = base.JSONObject(default=list)
    nameid_formats = base.JSONObject(default=list)
    certificates = base.JSONObject(default=dict)
    requested_attributes = base.JSONObject(default=list)
    raw_metadata_path = pw.CharField(max_length=255, default="")
    flags = base.JSONObject(default=dict)
    created_by_ip = pw.CharField(max_length=45, default="")
    expires = pw.DateTimeField(null=True, index=True)
    created = pw.DateTimeField(index=True)
    updated = pw.DateTimeField(index=True)
