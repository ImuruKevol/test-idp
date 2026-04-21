class Struct:
    def __init__(self):
        self.package = "oidcidp"
        self.orm = wiz.model("portal/season/orm")
        self.session = wiz.model("portal/season/session").use()
        self.core = wiz.model("portal/idpcore/struct")

        self._Registry = wiz.model("portal/oidcidp/struct/registry")
        self._Provider = wiz.model("portal/oidcidp/struct/provider")
        self._Preview = wiz.model("portal/oidcidp/struct/preview")
        self._Flow = wiz.model("portal/oidcidp/struct/flow")

        self._init_tables()

        try:
            self.core.seed(force=False)
        except Exception:
            pass

    def _init_tables(self):
        try:
            db = self.orm.use("oidc_rp_client", module="oidcidp")
            db.orm.create_table(safe=True)
        except Exception:
            pass
        try:
            db = self.orm.use("oidc_authorization_code", module="oidcidp")
            db.orm.create_table(safe=True)
        except Exception:
            pass
        try:
            db = self.orm.use("oidc_token_log", module="oidcidp")
            db.orm.create_table(safe=True)
        except Exception:
            pass
        self._migrate_columns()

    def _migrate_columns(self):
        try:
            db = self.orm.use("oidc_rp_client", module="oidcidp")
            database = db.orm._meta.database
            cursor = database.execute_sql("PRAGMA table_info('oidc_rp_client')")
            existing = [row[1] for row in cursor.fetchall()]
            if "expires" not in existing:
                database.execute_sql('ALTER TABLE "oidc_rp_client" ADD COLUMN "expires" DATETIME')
        except Exception:
            pass

    def should_repair_storage(self, error):
        message = str(error or "").lower()
        return "database disk image is malformed" in message or "missing from index" in message

    def repair_storage(self):
        try:
            db = self.orm.use("oidc_rp_client", module="oidcidp")
            database = db.orm._meta.database
            database.execute_sql("REINDEX")
            cursor = database.execute_sql("PRAGMA integrity_check")
            rows = [str(row[0]) for row in cursor.fetchall()]
            return len(rows) == 1 and rows[0] == "ok"
        except Exception:
            return False

    def db(self, name):
        return self.orm.use(name, module="oidcidp")

    @property
    def registry(self):
        return self._Registry(self)

    @property
    def provider(self):
        return self._Provider(self)

    @property
    def preview(self):
        return self._Preview(self)

    @property
    def flow(self):
        return self._Flow(self)

    def info(self):
        provider = self.provider.info()
        return {
            "package": self.package,
            "ready": True,
            "client_count": self.db("oidc_rp_client").count(),
            "issuer": provider["issuer"],
            "discovery_endpoint": provider["discovery_endpoint"],
        }


Model = Struct()
