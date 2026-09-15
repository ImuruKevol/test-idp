struct = wiz.model("portal/oidcidp/struct")


def info():
    clients = struct.registry.list()
    wiz.response.status(200, data={
        "provider": struct.provider.info(),
        "discovery": struct.provider.discovery(
            discovery_variant=wiz.request.query("discovery_variant", "standard")
        ),
        "jwks": struct.provider.jwks_public(),
        "clients": [struct.registry.public_view(item) for item in clients[:6]],
        "client_count": len(clients),
        "profiles": struct.provider.list_profiles(),
    })


def profile():
    try:
        result = struct.provider.profile_settings(
            wiz.request.query("reviewops_profile", "")
        )
    except ValueError as error:
        wiz.response.status(400, message=str(error))
    wiz.response.status(200, data=result)
