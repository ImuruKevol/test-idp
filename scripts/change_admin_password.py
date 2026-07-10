#!/usr/bin/env python3
"""관리자(admin) 계정 패스워드 변경 스크립트."""

import hashlib
import getpass
from pathlib import Path
import sqlite3
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
WIZ_ROOT = PROJECT_ROOT.parents[1]
PROJECT_NAME = PROJECT_ROOT.name
DB_PATH = PROJECT_ROOT / "data" / "idpcore.db"


def hash_password(password):
    return hashlib.sha256(str(password).encode("utf-8")).hexdigest()


def database_has_admin(db_path):
    db_path = Path(db_path)
    if not db_path.is_file():
        return False

    try:
        with sqlite3.connect(db_path) as conn:
            table = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'idp_user'"
            ).fetchone()
            if table is None:
                return False
            admin = conn.execute(
                "SELECT 1 FROM idp_user WHERE username = ? LIMIT 1",
                ("admin",),
            ).fetchone()
            return admin is not None
    except sqlite3.Error:
        return False


def initialize_project_database():
    """WIZ 모델을 로드해 DB 테이블과 기본 admin 계정을 생성한다."""
    import season

    app = season.server(str(WIZ_ROOT))
    wiz = app.wiz()
    wiz.project(PROJECT_NAME)
    wiz.model("portal/idpcore/struct")


def ensure_database(db_path):
    db_path = Path(db_path)
    if database_has_admin(db_path):
        return True

    print("[INFO] idpcore DB 또는 admin 계정이 없어 WIZ 모델을 초기화합니다.")
    try:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        initialize_project_database()
    except Exception as exc:
        print(f"[ERROR] WIZ 모델 초기화에 실패했습니다: {exc}")
        print("[ERROR] project/main/config/database.py와 Python 의존성을 확인하세요.")
        return False

    if not database_has_admin(db_path):
        print(f"[ERROR] 초기화 후에도 admin 계정을 찾을 수 없습니다: {db_path}")
        return False

    print(f"[OK] idpcore DB와 admin 계정을 초기화했습니다: {db_path}")
    return True


def main(db_path=None):
    db_path = Path(db_path or DB_PATH).resolve()

    new_password = getpass.getpass("새 패스워드 입력: ")
    if not new_password:
        print("[ERROR] 패스워드가 비어있습니다.")
        return 1

    confirm = getpass.getpass("패스워드 확인: ")
    if new_password != confirm:
        print("[ERROR] 패스워드가 일치하지 않습니다.")
        return 1

    if not ensure_database(db_path):
        return 1

    try:
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()

            cur.execute("SELECT id, username FROM idp_user WHERE username = ?", ("admin",))
            row = cur.fetchone()
            if row is None:
                print("[ERROR] admin 계정이 존재하지 않습니다.")
                return 1

            new_hash = hash_password(new_password)
            cur.execute(
                "UPDATE idp_user SET password_hash = ? WHERE username = ?",
                (new_hash, "admin"),
            )
            conn.commit()
    except sqlite3.Error as exc:
        print(f"[ERROR] admin 패스워드 변경에 실패했습니다: {exc}")
        return 1

    print("[OK] admin 패스워드가 변경되었습니다.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
