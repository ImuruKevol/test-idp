struct = wiz.model("portal/oidcidp/struct")


def info():
    clients = struct.registry.list()
    wiz.response.status(200, data={
        "provider": struct.provider.info(),
        "discovery": struct.provider.discovery(),
        "jwks": struct.provider.jwks_public(),
        "clients": clients[:6],
        "client_count": len(clients),
    })