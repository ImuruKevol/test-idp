class Struct:
    def __init__(self):
        self.orm = wiz.model("portal/season/orm")
        self.session = wiz.model("portal/season/session").use()

        # 패키지 Struct 캐시
        self._packages = {}

    def db(self, name):
        """ORM Wrapper 반환 (src/model/db/{name}.py)"""
        return self.orm.use(name)

    def __getattr__(self, name):
        """알 수 없는 속성 → 패키지 Struct 동적 로드"""
        if name.startswith('_'):
            raise AttributeError(name)
        if name not in self._packages:
            try:
                self._packages[name] = wiz.model(f"portal/{name}/struct")
            except Exception:
                raise AttributeError(f"Package '{name}' not found")
        return self._packages[name]

Model = Struct()
