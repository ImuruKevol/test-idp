import peewee as pw

orm = wiz.model("portal/season/orm")
base = orm.base("oidcidp")


class Model(base):
    class Meta:
        db_table = "oidc_token_log"

    id = pw.CharField(max_length=32, primary_key=True)
    client_id = pw.CharField(max_length=255, index=True)
    user_id = pw.CharField(max_length=32, index=True)
    grant_type = pw.CharField(max_length=64, index=True)
    access_token_jti = pw.CharField(max_length=255, default="", index=True)
    id_token_jti = pw.CharField(max_length=255, default="", index=True)
    refresh_token_jti = pw.CharField(max_length=255, default="", index=True)
    refresh_token_parent_jti = pw.CharField(max_length=255, default="", index=True)
    refresh_token_expires = pw.DateTimeField(null=True, index=True)
    refresh_token_consumed = pw.DateTimeField(null=True, index=True)
    debug_key = pw.CharField(max_length=64, default="", index=True)
    raw_request = base.JSONObject(default=dict)
    raw_response = base.JSONObject(default=dict)
    created = pw.DateTimeField(index=True)
