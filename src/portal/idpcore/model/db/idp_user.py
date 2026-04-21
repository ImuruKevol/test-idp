import peewee as pw

orm = wiz.model("portal/season/orm")
base = orm.base("idpcore")


class Model(base):
    class Meta:
        db_table = "idp_user"

    id = pw.CharField(max_length=32, primary_key=True)
    username = pw.CharField(max_length=64, unique=True, index=True)
    password_hash = pw.CharField(max_length=255)
    email = pw.CharField(max_length=255, default="", index=True)
    display_name = pw.CharField(max_length=255, default="")
    role = pw.CharField(max_length=32, default="tester", index=True)
    profile = base.JSONObject(default=dict)
    is_temporary = pw.BooleanField(default=False, index=True)
    expires = pw.DateTimeField(null=True, index=True)
    created_by = pw.CharField(max_length=64, default="")
    created_by_ip = pw.CharField(max_length=45, default="")
    saml_attributes = base.JSONObject(default=dict)
    oidc_claims = base.JSONObject(default=dict)
    created = pw.DateTimeField(index=True)
    updated = pw.DateTimeField(index=True)
