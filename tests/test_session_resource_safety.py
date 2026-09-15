import datetime
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]


def load(relative, name, globals=None):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    for key, value in (globals or {}).items():
        setattr(module, key, value)
    spec.loader.exec_module(module)
    return module


class MemorySession:
    def __init__(self, values=None):
        self.values = dict(values or {})
        self.cleared = False

    def get(self, key, default=""):
        return self.values.get(key, default)

    def clear(self):
        self.values.clear()
        self.cleared = True


def test_signed_cookie_session_age_and_invalid_timestamp_are_bounded():
    flask = SimpleNamespace(session={
        "oidc_auth_time": "2026-09-15T00:00:00+00:00",
        "broken_auth_time": "not-a-time",
    })
    module = load(
        "src/portal/season/model/session.py",
        "resource_session_model",
        {
            "wiz": SimpleNamespace(server=SimpleNamespace(package=SimpleNamespace(flask=flask))),
            "season": SimpleNamespace(util=SimpleNamespace(stdClass=dict)),
        },
    )
    session = module.Session()
    now = datetime.datetime(2026, 9, 15, 0, 1, tzinfo=datetime.timezone.utc)

    assert session.age_seconds("oidc_auth_time", now=now) == 60
    assert session.is_expired("oidc_auth_time", 60, now=now) is True
    assert session.is_expired("broken_auth_time", 60, now=now) is True
    assert session.is_expired("missing_auth_time", 60, now=now) is False


def test_rate_limiter_prunes_stale_keys_and_caps_unique_buckets(monkeypatch):
    module = load(
        "src/portal/idpcore/model/struct/rate_limiter.py",
        "resource_rate_limiter",
    )
    limiter = module.RateLimiter
    limiter.reset()
    clock = {"now": 10_000.0}
    monkeypatch.setattr(module.time, "time", lambda: clock["now"])

    assert limiter.check("old:client") is True
    clock["now"] += module.STALE_BUCKET_SECONDS + 1
    assert limiter.check("new:client") is True
    assert "old:client" not in limiter._buckets()

    for index in range(module.MAX_BUCKETS + 64):
        clock["now"] += 0.001
        assert limiter.check(f"client:{index}") is True
    assert len(limiter._buckets()) <= module.MAX_BUCKETS
    limiter.reset()


class RecordingDb:
    def __init__(self):
        self.calls = []

    def rows(self, **kwargs):
        self.calls.append(kwargs)
        return []


def test_debug_and_audit_queries_have_hard_result_limits():
    debug_module = load(
        "src/portal/idpcore/model/struct/debug_payload.py",
        "resource_debug_payload",
    )
    audit_module = load(
        "src/portal/idpcore/model/struct/audit.py",
        "resource_audit",
    )
    debug_db = RecordingDb()
    audit_db = RecordingDb()
    core = SimpleNamespace(db=lambda name: debug_db if name == "idp_debug_payload" else audit_db)

    debug_module.DebugPayload(core).list(protocol="oidc", limit=1000)
    audit_module.Audit(core).list(protocol="saml", limit=1000)

    assert debug_db.calls[0]["page"] == 1
    assert debug_db.calls[0]["dump"] == debug_module.DebugPayload.MAX_LIST_LIMIT
    assert audit_db.calls[0]["page"] == 1
    assert audit_db.calls[0]["dump"] == audit_module.Audit.MAX_LIST_LIMIT


def oidc_flow(auth_time, ttl_seconds=60):
    module = load(
        "src/portal/oidcidp/model/struct/flow.py",
        f"resource_oidc_flow_{id(auth_time)}",
    )
    user = {"id": "user-1", "username": "tester", "email": "tester@example.test"}
    session = MemorySession({"id": user["id"], "oidc_auth_time": auth_time})
    core_user = SimpleNamespace(
        get=lambda **kwargs: user,
        is_expired=lambda value: False,
    )
    provider = SimpleNamespace(
        reviewops_profile=lambda value=None: "",
        profile_settings=lambda profile: {"session_ttl_seconds": ttl_seconds},
    )
    struct = SimpleNamespace(
        session=session,
        core=SimpleNamespace(user=core_user),
        provider=provider,
    )
    flow = module.Flow(struct)
    flow._now = lambda: datetime.datetime(2026, 9, 15, 0, 2)
    return flow, session, user


def test_oidc_session_profile_ttl_ends_stale_login():
    flow, session, _ = oidc_flow("2026-09-15T00:00:00+00:00", ttl_seconds=60)

    assert flow._current_user() is None
    assert session.cleared is True


def test_oidc_session_profile_ttl_keeps_fresh_login():
    flow, session, user = oidc_flow("2026-09-15T00:01:30+00:00", ttl_seconds=60)

    assert flow._current_user() == user
    assert session.cleared is False


def test_protocol_routes_apply_session_expiry_without_loading_all_users():
    oidc_route = (ROOT / "src/portal/oidcidp/route/oidc/controller.py").read_text()
    saml_route = (ROOT / "src/portal/samlidp/route/saml/controller.py").read_text()

    assert 'session.is_expired("oidc_auth_time", _session_ttl_seconds())' in oidc_route
    assert 'struct.session.is_expired("saml_auth_time", SAML_SSO_SESSION_TTL_SECONDS)' in saml_route
    assert "struct.core.user.get(" in oidc_route
    assert "struct.core.user.get(" in saml_route
    assert "rows = struct.core.user.list_active()" not in oidc_route
    assert "rows = struct.core.user.list_active()" not in saml_route


def teardown_module():
    for key in [
        "_wiz_rate_limit_store",
        "_wiz_rate_limit_lock",
        "_wiz_rate_limit_last_cleanup",
    ]:
        if hasattr(sys, key):
            delattr(sys, key)
