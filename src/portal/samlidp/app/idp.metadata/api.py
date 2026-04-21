struct = wiz.model("portal/samlidp/struct")


def info():
    info = struct.metadata.info()
    wiz.response.status(200, data=info)


def metadata_xml():
    xml = struct.metadata.generate_xml()
    wiz.response.status(200, data=xml)
