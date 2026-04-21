import peewee as pw

orm = wiz.model("portal/season/orm")
base = orm.base("oidcidp")


class Model(base):
    class Meta:
        db_table = "oidc_authorization_code"

    id = pw.CharField(max_length=32, primary_key=True)
    code = pw.CharField(max_length=255, unique=True, index=True)
    client_id = pw.CharField(max_length=255, index=True)
    user_id = pw.CharField(max_length=32, index=True)
    redirect_uri = pw.TextField(default="")
    scope = pw.TextField(default="")
    nonce = pw.CharField(max_length=255, default="")
    code_challenge = pw.CharField(max_length=255, default="")
    code_challenge_method = pw.CharField(max_length=32, default="")
    claims = base.JSONObject(default=dict)
    released_claims = base.JSONObject(default=dict)
    extra = base.JSONObject(default=dict)
    debug_key = pw.CharField(max_length=64, default="", index=True)
    auth_time = pw.DateTimeField(index=True)
    expires = pw.DateTimeField(index=True)
    consumed = pw.DateTimeField(null=True, index=True)
    created = pw.DateTimeField(index=True)