"""Template/source checks for temporary account attribute catalog behavior."""
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]


def read(relative_path: str) -> str:
    return (PROJECT / relative_path).read_text(encoding="utf-8")


def test_temp_account_form_uses_two_column_attribute_catalog_layout():
    template = read("src/portal/idpcore/app/temp.account.form/view.pug")

    assert "lg:grid-cols-[minmax(0,1fr)_minmax(320px,380px)]" in template
    assert "aside(class=\"rounded-lg border border-sky-200 bg-sky-50 p-3 lg:sticky lg:top-4\")" in template
    assert "pysaml2 지원 속성" in template
    assert "SAML Attributes (JSON)" in template
    assert "OIDC Claims (JSON)" in template


def test_attribute_catalog_uses_pysaml2_route_and_adds_to_both_editors():
    source = read("src/portal/idpcore/app/temp.account.form/view.ts")
    template = read("src/portal/idpcore/app/temp.account.form/view.pug")

    assert "/api/idpcore/pysaml2-attribute-catalog" in source
    assert "(click)=\"addCatalogAttribute(attr)\"" in template
    assert "const parsedAttributes = this.parseObjectEditor(this.form.saml_attributes);" in source
    assert "const parsedClaims = this.parseObjectEditor(this.form.oidc_claims);" in source
    assert "parsedAttributes[samlName] = attr.example;" in source
    assert "parsedClaims[claimKey] = attr.example;" in source
    assert "this.form.oidc_claims = JSON.stringify(parsedClaims, null, 2);" in source


def test_attribute_catalog_shows_saml_and_oidc_badges():
    template = read("src/portal/idpcore/app/temp.account.form/view.pug")

    for expected in (
        "SAML 있음",
        "SAML 없음",
        "OIDC 있음",
        "OIDC 없음",
        "attr.has_saml",
        "attr.has_oidc",
    ):
        assert expected in template


def test_attribute_catalog_refreshes_badges_when_json_editors_change():
    source = read("src/portal/idpcore/app/temp.account.form/view.ts")
    template = read("src/portal/idpcore/app/temp.account.form/view.pug")

    assert "(ngModelChange)=\"onEditorChange()\"" in template
    assert "item.has_saml = this.samlKeysForAttribute(item).some" in source
    assert "item.has_oidc = this.hasOwn(oidc, claimKey);" in source
