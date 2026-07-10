from season.util import stdClass

# WIZ는 워크스페이스 루트에서 실행되므로 DB 경로에 project/main을 포함한다.
# 각 변수명은 portal 패키지가 orm.base(namespace)로 조회하는 namespace와 같다.
base = stdClass(
    type="sqlite",
    path="project/main/data/base.db",
)

idpcore = stdClass(
    type="sqlite",
    path="project/main/data/idpcore.db",
)

samlidp = stdClass(
    type="sqlite",
    path="project/main/data/samlidp.db",
)

oidcidp = stdClass(
    type="sqlite",
    path="project/main/data/oidcidp.db",
)
