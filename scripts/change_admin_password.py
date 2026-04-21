#!/usr/bin/env python3
"""관리자(admin) 계정 패스워드 변경 스크립트"""

import hashlib
import getpass
import sqlite3
import os
import sys

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "idpcore.db")


def hash_password(password):
    return hashlib.sha256(str(password).encode("utf-8")).hexdigest()


def main():
    db_path = os.path.abspath(DB_PATH)
    if not os.path.exists(db_path):
        print(f"[ERROR] DB 파일을 찾을 수 없습니다: {db_path}")
        sys.exit(1)

    new_password = getpass.getpass("새 패스워드 입력: ")
    if not new_password:
        print("[ERROR] 패스워드가 비어있습니다.")
        sys.exit(1)

    confirm = getpass.getpass("패스워드 확인: ")
    if new_password != confirm:
        print("[ERROR] 패스워드가 일치하지 않습니다.")
        sys.exit(1)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("SELECT id, username FROM idp_user WHERE username = ?", ("admin",))
    row = cur.fetchone()
    if row is None:
        print("[ERROR] admin 계정이 존재하지 않습니다.")
        conn.close()
        sys.exit(1)

    new_hash = hash_password(new_password)
    cur.execute("UPDATE idp_user SET password_hash = ? WHERE username = ?", (new_hash, "admin"))
    conn.commit()
    conn.close()

    print("[OK] admin 패스워드가 변경되었습니다.")


if __name__ == "__main__":
    main()
