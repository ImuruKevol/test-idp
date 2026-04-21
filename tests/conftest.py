"""Test helpers for test-idp integration tests.

Provides session cookie generation and a base HTTP client
for testing WIZ framework API endpoints.
"""
import base64
import datetime
import hashlib
import json
import pytest
import requests
import sqlite3
from pathlib import Path


WIZ_BASE = "http://localhost:3034"
WIZ_PROJECT = "main"
SECRET_KEY = "season-wiz-secret"
IDPCORE_DB = Path(__file__).resolve().parents[1] / "data" / "idpcore.db"


def hash_password(password: str) -> str:
    return hashlib.sha256(str(password).encode("utf-8")).hexdigest()


def get_admin_password_hash() -> str | None:
    with sqlite3.connect(IDPCORE_DB) as conn:
        row = conn.execute(
            "SELECT password_hash FROM idp_user WHERE username = ? LIMIT 1",
            ("admin",),
        ).fetchone()
    if row is None:
        return None
    return row[0]


def set_admin_password_hash(password_hash: str) -> None:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(IDPCORE_DB) as conn:
        conn.execute(
            "UPDATE idp_user SET password_hash = ?, updated = ? WHERE username = ?",
            (password_hash, now, "admin"),
        )
        conn.commit()


def make_session_cookie(user_data: dict) -> str:
    """Generate a Flask signed session cookie.

    Args:
        user_data: dict with keys like id, username, email, name, role
    """
    from flask import Flask
    from flask.sessions import SecureCookieSessionInterface

    app = Flask(__name__)
    app.secret_key = SECRET_KEY
    with app.test_request_context():
        from flask import session as sess
        for k, v in user_data.items():
            sess[k] = v
        si = SecureCookieSessionInterface()
        s = si.get_signing_serializer(app)
        return s.dumps(dict(sess))


def get_cookies(session_data: dict = None) -> dict:
    """Return cookie dict for WIZ API requests."""
    cookies = {
        "season-wiz-project": WIZ_PROJECT,
        "season-wiz-devmode": "true",
    }
    if session_data:
        cookies["session"] = make_session_cookie(session_data)
    return cookies


ADMIN_SESSION = {
    "id": "test-admin-id",
    "username": "admin",
    "email": "admin@test-idp.local",
    "name": "Admin Tester",
    "role": "admin",
}


class WizClient:
    """HTTP client for WIZ API testing."""

    def __init__(self, base_url=WIZ_BASE, session_data=None):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.cookies.update(get_cookies(session_data))

    def reset_rate_limits(self):
        """Reset all rate limiter buckets (test helper)."""
        url = f"{self.base_url}/api/idpcore/rate-limit-reset"
        self.session.get(url)

    def app_api(self, app_id: str, function: str, data: dict = None, method="POST"):
        """Call an app api.py function."""
        url = f"{self.base_url}/wiz/api/{app_id}/{function}"
        if method == "GET":
            return self.session.get(url, params=data or {})
        return self.session.post(url, data=data or {})

    def route(self, path: str, data: dict = None, method="GET"):
        """Call a route endpoint."""
        url = f"{self.base_url}{path}"
        if method == "POST":
            return self.session.post(url, data=data or {})
        return self.session.get(url, params=data or {})

    def assert_ok(self, resp, expected_code=200):
        """Assert WIZ JSON response is successful."""
        assert resp.status_code == 200, f"HTTP {resp.status_code}: {resp.text[:200]}"
        body = resp.json()
        assert body.get("code") == expected_code, f"WIZ code={body.get('code')}: {json.dumps(body.get('data', {}), ensure_ascii=False)[:300]}"
        return body

    def assert_error(self, resp, expected_code):
        """Assert WIZ JSON response is an error."""
        body = resp.json()
        assert body.get("code") == expected_code, f"Expected {expected_code}, got {body.get('code')}"
        return body


@pytest.fixture(autouse=True, scope="class")
def reset_rate_limits():
    """Reset rate limiter state before each test class."""
    client = WizClient(session_data=ADMIN_SESSION)
    client.reset_rate_limits()
    client.route("/api/idpcore/seed")
    yield
    client.reset_rate_limits()


@pytest.fixture
def known_admin_password():
    client = WizClient(session_data=ADMIN_SESSION)
    client.route("/api/idpcore/seed")
    original_hash = get_admin_password_hash()
    password = "admin1234"
    set_admin_password_hash(hash_password(password))
    try:
        yield password
    finally:
        if original_hash is not None:
            set_admin_password_hash(original_hash)
