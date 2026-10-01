struct = wiz.model("portal/samlidp/struct")


def info():
    metadata = struct.metadata
    info = metadata.info(wiz.request.query("reviewops_profile", ""))
    profiles = []
    try:
        list_profiles = getattr(metadata, "list_response_profiles", None)
        if callable(list_profiles):
            profiles = list_profiles()
        else:
            prefix = "reviewops-profile-"
            suffix = ".json"
            for filename in metadata._cert_fs().files():
                name = str(filename or "")
                if not name.startswith(prefix) or not name.endswith(suffix):
                    continue
                profile = name[len(prefix):-len(suffix)]
                settings = metadata.response_defaults(profile)
                profiles.append({
                    "name": profile,
                    "standards_status": settings.get("standards_status", "standard"),
                    "standards_warnings": settings.get("standards_warnings", []),
                    "sign_response": settings.get("sign_response", True),
                    "sign_assertion": settings.get("sign_assertion", True),
                    "response_variant": settings.get("response_variant", "standard"),
                })
            profiles = sorted(profiles, key=lambda item: item["name"])
    except Exception:
        profiles = []
    info["profiles"] = profiles
    try:
        info["federations"] = metadata.list_federations()
    except Exception:
        info["federations"] = []
    wiz.response.status(200, data=info)


def metadata_xml():
    xml = struct.metadata.generate_xml(
        reviewops_profile=wiz.request.query("reviewops_profile", ""),
        metadata_variant=wiz.request.query("metadata_variant", "standard")
    )
    wiz.response.status(200, data=xml)


def profile():
    try:
        result = struct.metadata.response_defaults(
            wiz.request.query("reviewops_profile", "")
        )
    except ValueError as error:
        wiz.response.status(400, message=str(error))
    wiz.response.status(200, data=result)


def federation_create():
    try:
        result = struct.metadata.create_federation(
            wiz.request.query("name", True),
            count=wiz.request.query("count", 3),
            include_base=str(wiz.request.query("include_base", "true")).lower() == "true",
            preset=wiz.request.query("preset", "standard"),
        )
    except ValueError as error:
        wiz.response.status(400, message=str(error))
    wiz.response.status(200, data=result)


def federation_delete():
    try:
        result = struct.metadata.delete_federation(
            wiz.request.query("name", True)
        )
    except ValueError as error:
        wiz.response.status(400, message=str(error))
    wiz.response.status(200, data=result)
