import datetime
import os
import secrets


class User:
    def __init__(self, core):
        self.core = core
        self.db = core.db("idp_user")

    def _get_ttl_hours(self):
        try:
            config = wiz.config("idp")
            return int(getattr(config, "TEMPORARY_ACCOUNT_TTL_HOURS", 24) or 24)
        except Exception:
            return 24

    def _parse_expires(self, expires):
        if expires in [None, ""]:
            return None
        if isinstance(expires, str):
            try:
                return datetime.datetime.strptime(expires, "%Y-%m-%d %H:%M:%S")
            except Exception:
                return None
        return expires

    def __call__(self, id):
        inst = User(self.core)
        inst.id = id
        inst.data = self.get(id=id)
        return inst

    def list(self, role="", orderby="created", order="ASC", include_expired=False):
        kwargs = dict(orderby=orderby, order=order)
        if role:
            kwargs["role"] = role
        rows = self.db.rows(**kwargs)
        if include_expired:
            return rows
        return [r for r in rows if not self._is_expired(r)]

    def list_permanent(self, orderby="created", order="ASC"):
        rows = self.db.rows(is_temporary=False, orderby=orderby, order=order)
        return rows

    def list_temporary(self, orderby="created", order="DESC", include_expired=False):
        rows = self.db.rows(is_temporary=True, orderby=orderby, order=order)
        if include_expired:
            return rows
        return [r for r in rows if not self._is_expired(r)]

    def list_active(self, orderby="created", order="ASC"):
        rows = self.db.rows(orderby=orderby, order=order)
        return [r for r in rows if not self._is_expired(r)]

    def get(self, id=None, username=None):
        if id:
            return self.db.get(id=id)
        if username:
            return self.db.get(username=username)
        return None

    def create(self, data):
        item = dict(data)
        username = str(item.get("username", "")).strip()
        if username == "":
            raise Exception("username is required")

        password = item.pop("password", None)
        password_hash = item.get("password_hash", "")
        if password is None and password_hash == "":
            raise Exception("password is required")

        now = self.core.now()
        item["username"] = username
        item["display_name"] = str(item.get("display_name", username)).strip()
        item["email"] = str(item.get("email", "")).strip()
        item["role"] = str(item.get("role", "tester")).strip() or "tester"
        item["profile"] = self.core.normalize_object(item.get("profile"), {})
        item["is_temporary"] = bool(item.get("is_temporary", False))
        item["expires"] = item.get("expires", None)
        item["created_by"] = str(item.get("created_by", "")).strip()
        item["created_by_ip"] = str(item.get("created_by_ip", "")).strip()
        item["saml_attributes"] = self.core.normalize_saml_attributes(item.get("saml_attributes"), {})
        item["oidc_claims"] = self.core.normalize_object(item.get("oidc_claims"), {})
        item["created"] = now
        item["updated"] = now

        if password is not None:
            item["password_hash"] = self.core.hash_password(password)

        return self.db.insert(item)

    def create_temporary(self, data, created_by_ip=""):
        item = dict(data)
        item["is_temporary"] = True
        item["profile"] = self.core.default_temporary_profile(item)
        default_saml_attributes = self.core.default_temporary_saml_attributes(item)
        default_oidc_claims = self.core.default_temporary_oidc_claims(item)
        provided_saml_attributes = self.core.normalize_object(item.get("saml_attributes"), {})
        provided_oidc_claims = self.core.normalize_object(item.get("oidc_claims"), {})
        item["saml_attributes"] = {**default_saml_attributes, **provided_saml_attributes}
        item["oidc_claims"] = {**default_oidc_claims, **provided_oidc_claims}
        ttl_hours = self._get_ttl_hours()
        now_dt = datetime.datetime.now()
        expires_dt = now_dt + datetime.timedelta(hours=ttl_hours)
        item["expires"] = expires_dt.strftime("%Y-%m-%d %H:%M:%S")
        item["created_by"] = str(item.get("created_by", self.core.current_actor_id())).strip()
        item["created_by_ip"] = str(created_by_ip)
        return self.create(item)

    def update(self, data, id=None, username=None):
        item = dict(data)
        password = item.pop("password", None)

        if "profile" in item:
            item["profile"] = self.core.normalize_object(item.get("profile"), {})
        if "display_name" in item:
            item["display_name"] = str(item.get("display_name", "")).strip()
        if "email" in item:
            item["email"] = str(item.get("email", "")).strip()
        if "role" in item:
            item["role"] = str(item.get("role", "tester")).strip() or "tester"
        if "saml_attributes" in item:
            item["saml_attributes"] = self.core.normalize_saml_attributes(item.get("saml_attributes"), {})
        if "oidc_claims" in item:
            item["oidc_claims"] = self.core.normalize_object(item.get("oidc_claims"), {})
        if password is not None:
            item["password_hash"] = self.core.hash_password(password)

        item["updated"] = self.core.now()

        where = self._where(id=id, username=username)
        self.db.update(item, **where)

    def delete(self, id=None, username=None):
        where = self._where(id=id, username=username)
        self.db.delete(**where)

    def extend_validity(self, id=None, username=None, ttl_hours=None):
        user = self.get(id=id, username=username)
        if user is None:
            raise Exception("user not found")
        if not user.get("is_temporary", False):
            raise Exception("임시 테스트 계정만 연장할 수 있습니다.")

        if ttl_hours is None:
            ttl_hours = self._get_ttl_hours()
        ttl_hours = int(ttl_hours)
        if ttl_hours <= 0:
            raise Exception("ttl_hours는 1 이상이어야 합니다.")

        now_dt = datetime.datetime.now()
        current_expires = self._parse_expires(user.get("expires"))
        baseline = current_expires if current_expires and current_expires > now_dt else now_dt
        expires_dt = baseline + datetime.timedelta(hours=ttl_hours)
        self.update({"expires": expires_dt.strftime("%Y-%m-%d %H:%M:%S")}, id=user["id"])
        return self.get(id=user["id"])

    def set_unlimited(self, id=None, username=None):
        user = self.get(id=id, username=username)
        if user is None:
            raise Exception("user not found")
        if not user.get("is_temporary", False):
            raise Exception("임시 테스트 계정만 무기한으로 전환할 수 있습니다.")

        self.update({"expires": None}, id=user["id"])
        return self.get(id=user["id"])

    def can_delete(self, user, client_ip="", is_admin=False):
        """Check whether the given client is allowed to delete this user."""
        if is_admin:
            return True
        created_ip = user.get("created_by_ip", "")
        if created_ip and client_ip and created_ip == client_ip:
            return True
        return False

    def authenticate(self, username, password):
        user = self.get(username=username)
        if user is None:
            return None
        if self._is_expired(user):
            return None
        if user["password_hash"] != self.core.hash_password(password):
            return None
        return user

    def cleanup_expired(self):
        now = self.core.now()
        rows = self.db.rows(is_temporary=True)
        deleted = []
        for row in rows:
            if self._is_expired(row):
                self.db.delete(id=row["id"])
                deleted.append({"id": row["id"], "username": row["username"]})
        return deleted

    def seed_samples(self, force=False):
        results = []
        for sample in self.sample_accounts():
            current = self.get(username=sample["username"])
            payload = dict(sample)
            if current is None:
                user_id = self.create(payload)
                results.append({"username": sample["username"], "id": user_id, "action": "created"})
                continue

            if force is False:
                results.append({"username": sample["username"], "id": current["id"], "action": "skipped"})
                continue

            if current.get("password_hash"):
                payload.pop("password", None)
                payload["password_hash"] = current.get("password_hash")

            self.update(payload, username=sample["username"])
            current = self.get(username=sample["username"])
            results.append({"username": sample["username"], "id": current["id"], "action": "updated"})

        results.extend(self._remove_legacy_sample_accounts())
        return results

    def legacy_sample_accounts(self):
        return ["alice", "bob", "carol", "mfauser"]

    def _remove_legacy_sample_accounts(self):
        removed = []
        for username in self.legacy_sample_accounts():
            current = self.get(username=username)
            if current is None:
                continue
            if current.get("is_temporary", False):
                continue
            self.delete(id=current["id"])
            removed.append({"username": username, "id": current["id"], "action": "deleted"})
        return removed

    def is_expired(self, user):
        return self._is_expired(user)

    def sample_accounts(self):
        return [
            {
                "username": "admin",
                "password": self._admin_seed_password(),
                "email": "admin@test-idp.local",
                "display_name": "Admin Tester",
                "role": "admin",
                "profile": {
                    "department": "platform",
                    "groups": ["admins", "qa"],
                    "organization": "Test IDP",
                },
            },
        ]

    def _admin_seed_password(self):
        password = os.environ.get("TEST_IDP_ADMIN_PASSWORD", "").strip()
        if password:
            return password
        return secrets.token_urlsafe(32)

    def _is_expired(self, user):
        if not user.get("is_temporary", False):
            return False
        expires = self._parse_expires(user.get("expires"))
        if expires is None:
            return False
        now = datetime.datetime.now()
        return now > expires

    def _where(self, id=None, username=None):
        if id:
            return {"id": id}
        if username:
            return {"username": username}
        raise Exception("id or username is required")


Model = User
