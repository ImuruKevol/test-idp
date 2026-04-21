class Struct:
    def __init__(self):
        self.package = "samlidp"
        self.orm = wiz.model("portal/season/orm")
        self.session = wiz.model("portal/season/session").use()
        self.core = wiz.model("portal/idpcore/struct")
        self._Registry = wiz.model("portal/samlidp/struct/registry")
        self._Metadata = wiz.model("portal/samlidp/struct/metadata")
        self._Process = wiz.model("portal/samlidp/struct/process")

        self._init_tables()

    def _init_tables(self):
        for name in ["saml_sp_registry", "saml_transaction"]:
            try:
                db = self.orm.use(name, module="samlidp")
                db.create()
            except Exception:
                pass
        self._migrate_columns()

    def _migrate_columns(self):
        try:
            db = self.orm.use("saml_sp_registry", module="samlidp")
            database = db.orm._meta.database
            cursor = database.execute_sql("PRAGMA table_info('saml_sp_registry')")
            existing = [row[1] for row in cursor.fetchall()]
            if "created_by_ip" not in existing:
                database.execute_sql('ALTER TABLE "saml_sp_registry" ADD COLUMN "created_by_ip" VARCHAR(45) DEFAULT ""')
        except Exception:
            pass

    def db(self, name):
        return self.orm.use(name, module="samlidp")

    @property
    def registry(self):
        return self._Registry(self)

    @property
    def metadata(self):
        return self._Metadata(self)

    @property
    def process(self):
        return self._Process(self)

    def info(self):
        db = self.db("saml_sp_registry")
        sp_count = db.count()
        idp_info = self.metadata.info()
        return {
            "package": self.package,
            "ready": True,
            "sp_count": sp_count,
            "idp_entity_id": idp_info["entity_id"],
        }


Model = Struct()
