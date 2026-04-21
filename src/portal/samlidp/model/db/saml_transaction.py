import peewee as pw

orm = wiz.model("portal/season/orm")
base = orm.base("samlidp")


class Model(base):
    class Meta:
        db_table = "saml_transaction"

    id = pw.CharField(max_length=32, primary_key=True)
    request_id = pw.CharField(max_length=255, default="", index=True)
    sp_entity_id = pw.CharField(max_length=512, default="", index=True)
    relay_state = pw.CharField(max_length=512, default="")
    binding = pw.CharField(max_length=32, default="")
    nameid_format_requested = pw.CharField(max_length=255, default="")
    authn_context_requested = base.JSONObject(default=list)
    raw_request_path = pw.CharField(max_length=255, default="")
    raw_response_path = pw.CharField(max_length=255, default="")
    session_index = pw.CharField(max_length=255, default="")
    status = pw.CharField(max_length=32, default="pending", index=True)
    user_id = pw.CharField(max_length=32, default="")
    created = pw.DateTimeField(index=True)
