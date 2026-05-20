"""Template checks for the compact Test IdP UI refresh."""
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]


def read(relative_path: str) -> str:
    return (PROJECT / relative_path).read_text(encoding="utf-8")


def test_landing_keeps_primary_flows_and_uses_compact_shell():
    template = read("src/app/page.landing/view.pug")

    assert 'wiz-portal-idpcore-temp-account-list' in template
    assert 'routerLink="/saml/register"' in template
    assert 'routerLink="/oidc/register"' in template
    assert 'openPasswordModal()' in template
    assert 'rounded-lg border border-zinc-200 bg-white' in template
    assert 'rounded-[2rem]' not in template
    assert 'bg-[linear-gradient' not in template


def test_topnav_and_protocol_tabs_share_compact_navigation_classes():
    topnav_ts = read("src/app/layout.topnav/view.ts")
    saml_ts = read("src/app/page.saml/view.ts")
    oidc_ts = read("src/app/page.oidc/view.ts")

    for source in (topnav_ts, saml_ts, oidc_ts):
        assert "h-8 items-center rounded-md bg-zinc-950" in source
        assert "rounded-full" not in source


def test_temporary_account_list_preserves_actions():
    template = read("src/portal/idpcore/app/temp.account.list/view.pug")

    for action in (
        "quickCreate()",
        "selectQuickPreset(preset.id)",
        "openCreate()",
        "cleanupExpired()",
        "extendValidity(item)",
        "setUnlimited(item)",
        "openEdit(item)",
        "deleteItem(item)",
    ):
        assert action in template

    assert 'wiz-portal-idpcore-temp-account-form' in template
    assert "Quick Create" in template
    assert "rounded-xl" not in template


def test_quick_create_offers_edu_person_presets():
    source = read("src/portal/idpcore/app/temp.account.list/view.ts")
    template = read("src/portal/idpcore/app/temp.account.list/view.pug")

    for expected in ("일반", "연구소", "학교", "기관"):
        assert expected in source

    for expected in (
        "quickCreatePresets",
        "selectedQuickPreset",
        "selectQuickPreset(preset.id)",
        "selectedQuickPresetLabel()",
    ):
        assert expected in template

    for expected in (
        "eduPersonPrincipalName",
        "eduPersonAffiliation",
        "eduPersonScopedAffiliation",
        "eduPersonEntitlement",
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.7",
    ):
        assert expected in source


def test_access_login_has_loading_state_and_render_updates():
    template = read("src/app/page.access/view.pug")
    source = read("src/app/page.access/view.ts")

    assert "loggingIn" in source
    assert "[disabled]=\"loggingIn\"" in template
    assert "(ngModelChange)=\"service.render()\"" in template
