import peewee as pw

orm = wiz.model("portal/season/orm")
base = orm.base("oidcidp")


class Model(base):
    class Meta:
        db_table = "oidc_rp_client"

    id = pw.CharField(max_length=32, primary_key=True)
    client_id = pw.CharField(max_length=255, unique=True, index=True)
    client_secret = pw.CharField(max_length=255, default="")
    client_name = pw.CharField(max_length=255, index=True)
    redirect_uris = base.JSONObject(default=list)
    post_logout_redirect_uris = base.JSONObject(default=list)
    grant_types = base.JSONObject(default=list)
    response_types = base.JSONObject(default=list)
    scope_policy = base.JSONObject(default=list)
    claims_policy = base.JSONObject(default=list)
    token_endpoint_auth_method = pw.CharField(max_length=64, default="client_secret_basic")
    jwks = base.JSONObject(null=True)
    extra = base.JSONObject(default=dict)
    expires = pw.DateTimeField(null=True, index=True)
    created = pw.DateTimeField(index=True)
    updated = pw.DateTimeField(index=True)