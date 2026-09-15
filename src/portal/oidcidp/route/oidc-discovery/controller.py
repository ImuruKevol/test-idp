import json

struct = wiz.model("portal/oidcidp/struct")

try:
	payload = struct.provider.discovery()
except ValueError as e:
	wiz.response.status(400, message=str(e))
except Exception as e:
	wiz.response.status(500, message=str(e))

flask = wiz.response._flask
resp = flask.Response(
	json.dumps(payload, ensure_ascii=False),
	mimetype="application/json",
)
resp.headers["Cache-Control"] = "no-store"
resp.headers["Pragma"] = "no-cache"
wiz.response.response(resp)
