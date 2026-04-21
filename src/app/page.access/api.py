session = wiz.model("portal/season/session").use()
core = wiz.model("portal/idpcore/struct")
rate_limiter = wiz.model("portal/idpcore/struct/rate_limiter")


def _client_ip():
    try:
        return wiz.request.ip()
    except Exception:
        return "unknown"


def login():
    ip = _client_ip()
    if not rate_limiter.check(f"login:{ip}", max_requests=10, window_seconds=300):
        wiz.response.status(429, message="로그인 시도가 너무 많습니다. 잠시 후 다시 시도해주세요.")

    username = wiz.request.query("username", "")
    password = wiz.request.query("password", "")

    if not username or not password:
        wiz.response.status(400, message="사용자명과 비밀번호를 입력해주세요.")

    if str(username).strip() != "admin":
        wiz.response.status(403, message="admin 계정만 로그인할 수 있습니다.")

    try:
        user = core.user.authenticate(username, password)
    except Exception as e:
        wiz.response.status(500, message=str(e))

    if user is None:
        wiz.response.status(401, message="사용자명 또는 비밀번호가 올바르지 않습니다.")

    session.set(
        id=user["id"],
        username=user["username"],
        email=user.get("email", ""),
        name=user.get("display_name", user["username"]),
        role=user.get("role", "tester"),
    )
    wiz.response.status(200)
