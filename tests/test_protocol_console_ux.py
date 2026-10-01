from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def source(relative_path):
    return (ROOT / relative_path).read_text(encoding="utf-8")


def assert_in_order(content, labels):
    positions = [content.index(label) for label in labels]
    assert positions == sorted(positions)


def test_protocol_pages_present_a_numbered_task_menu_in_recommended_order():
    oidc = source("src/app/page.oidc/view.pug")
    saml = source("src/app/page.saml/view.pug")

    assert 'max-w-[1440px]' in oidc
    assert 'aria-label="OIDC 작업 메뉴"' in oidc
    assert_in_order(oidc, [
        'routerLink="/oidc/register"',
        'routerLink="/oidc/publish"',
        'routerLink="/oidc/authorizecheck"',
        'routerLink="/oidc/logoutcheck"',
    ])
    for label in ["RP 관리", "Provider 정보", "로그인 확인", "로그아웃 확인"]:
        assert label in oidc
    assert "실행 설정은 특정 시험에서 응답을 바꿀 때만 사용합니다." in oidc

    assert 'max-w-[1440px]' in saml
    assert 'aria-label="SAML 작업 메뉴"' in saml
    assert_in_order(saml, [
        'routerLink="/saml/register"',
        'routerLink="/saml/publish"',
        'routerLink="/saml/logincheck"',
        'routerLink="/saml/logoutcheck"',
    ])
    for label in ["SP 관리", "IdP 정보", "로그인 확인", "로그아웃 확인"]:
        assert label in saml
    assert "실행 설정은 특정 시험에서 응답을 바꿀 때만 사용합니다." in saml


def test_execution_settings_are_guided_and_explain_when_they_apply():
    oidc_view = source("src/portal/oidcidp/app/provider.publish/view.html")
    oidc_code = source("src/portal/oidcidp/app/provider.publish/view.ts")
    saml_view = source("src/portal/samlidp/app/idp.metadata/view.pug")
    saml_code = source("src/portal/samlidp/app/idp.metadata/view.ts")

    for view in [oidc_view, saml_view]:
        assert "선택 기능" in view
        assert "일반" in view and "만들 필요가 없습니다" in view
        assert "설정 이름" in view
        assert "확인할 상황 선택" in view
        assert "주요 값 확인" in view
        assert "표준 설정" in view
        assert "호환 시험 설정" in view
        assert "고급" in view

    assert "loadProfile()" in oidc_code
    assert "applyPreset(name: string)" in oidc_code
    assert "저장된 실행 설정" in oidc_view
    assert "selectProfile(item: any)" in oidc_code
    assert "deleteProfile()" in oidc_code
    assert "실행 설정 삭제" in oidc_view
    assert "복구할 수 없습니다" in oidc_code
    assert "Session 만료(초)" in oidc_view
    assert "loadProfile()" in saml_code
    assert "applyPreset(name: string)" in saml_code
    assert "저장된 실행 설정" in saml_view
    assert "selectProfile(item: any)" in saml_code
    assert "deleteProfile()" in saml_code
    assert "실행 설정 삭제" in saml_view
    assert "복구할 수 없습니다" in saml_code


def test_saml_publish_prioritizes_metadata_and_federation_and_collapses_expert_tools():
    view = source("src/portal/samlidp/app/idp.metadata/view.pug")
    metadata = source("src/portal/samlidp/model/struct/metadata.py")

    assert_in_order(view, [
        "기본 IdP Metadata",
        "Quick Federation",
        "고급 테스트 실행 설정",
        "Metadata XML·호환 시험",
    ])
    assert view.count("details(") >= 5
    assert "수동 연결 정보" in view
    assert "Signing·Encryption 인증서" in view
    assert "저장된 Federation · {{federationOptions.length}}개" in view
    assert "{{idpInfo.metadata_url}}" in view
    assert '"metadata_url": append_reviewops_profile(' in metadata


def test_registration_details_use_summary_rails_and_task_tabs():
    oidc_view = source("src/portal/oidcidp/app/rp.register/view.html")
    oidc_code = source("src/portal/oidcidp/app/rp.register/view.ts")
    saml_view = source("src/portal/samlidp/app/sp.register/view.pug")
    saml_code = source("src/portal/samlidp/app/sp.register/view.ts")

    assert "선택한 RP" in oidc_view
    assert "RP 상세 메뉴" in oidc_view
    assert_in_order(oidc_view, [">요약</button>", ">Callback</button>", ">Claim·메모</button>"])
    assert "detailTabClass" in oidc_code

    assert "선택한 SP" in saml_view
    assert "SP 상세 메뉴" in saml_view
    assert_in_order(saml_view, [") 요약", ") Endpoint", ") Attribute·보안"])
    assert "detailTabClass" in saml_code


def test_login_and_logout_pages_prioritize_primary_flows_and_hide_advanced_fields():
    oidc_login = source("src/portal/oidcidp/app/authorize.check/view.html")
    oidc_logout = source("src/portal/oidcidp/app/logout.check/view.html")
    saml_login = source("src/portal/samlidp/app/login.check/view.pug")
    saml_logout = source("src/portal/samlidp/app/logout.check/view.pug")

    assert "대상 선택" in oidc_login
    assert "PKCE" in oidc_login
    assert "<details" in oidc_login and "추가 요청값" in oidc_login
    assert "복귀 위치" in oidc_logout
    assert "<details" in oidc_logout and "id_token_hint 직접 입력" in oidc_logout

    assert "SP에서 시작" in saml_login
    assert "IdP 시작 SSO" in saml_login
    assert "details(" in saml_login and "고급 응답 설정" in saml_login
    assert_in_order(saml_logout, ["활성 세션", "SP 요청 받기", "IdP 요청 보내기"])
    assert "allowUnsignedLogout" in saml_logout
    assert "호환 시험" in saml_logout


def test_saml_console_limits_session_history_and_loads_secondary_data_later():
    login_view = source("src/portal/samlidp/app/login.check/view.pug")
    login_code = source("src/portal/samlidp/app/login.check/view.ts")
    logout_view = source("src/portal/samlidp/app/logout.check/view.pug")
    logout_code = source("src/portal/samlidp/app/logout.check/view.ts")

    essential_block = login_code.split("public async loadSupplementalData", 1)[0]
    assert 'wiz.call("tx_list", {})' not in essential_block
    assert "loadSupplementalData" in login_code
    assert "최근 요청을 불러오는 중" in login_view
    assert "activeSessionWindowHours" in logout_code
    assert "activeSessionTotal" in logout_code
    assert "최근 {{activeSessionWindowHours}}시간" in logout_view


def test_reworked_protocol_surfaces_use_expanded_spacing():
    for path in ["src/app/page.oidc/view.pug", "src/app/page.saml/view.pug"]:
        content = source(path)
        assert "lg:px-10" in content
        assert "lg:py-9" in content
        assert "lg:p-8" in content

    template_paths = [
        "src/portal/oidcidp/app/rp.register/view.html",
        "src/portal/oidcidp/app/provider.publish/view.html",
        "src/portal/oidcidp/app/authorize.check/view.html",
        "src/portal/oidcidp/app/logout.check/view.html",
        "src/portal/samlidp/app/sp.register/view.pug",
        "src/portal/samlidp/app/idp.metadata/view.pug",
        "src/portal/samlidp/app/login.check/view.pug",
        "src/portal/samlidp/app/logout.check/view.pug",
    ]
    for path in template_paths:
        assert "space-y-8" in source(path), path


def test_reworked_templates_have_explicit_render_updates_and_plain_labels():
    template_paths = [
        "src/portal/oidcidp/app/rp.register/view.html",
        "src/portal/oidcidp/app/provider.publish/view.html",
        "src/portal/oidcidp/app/authorize.check/view.html",
        "src/portal/oidcidp/app/logout.check/view.html",
        "src/portal/samlidp/app/sp.register/view.pug",
        "src/portal/samlidp/app/idp.metadata/view.pug",
        "src/portal/samlidp/app/login.check/view.pug",
        "src/portal/samlidp/app/logout.check/view.pug",
    ]

    for path in template_paths:
        content = source(path)
        assert "계약" not in content
        assert "게이트" not in content
        assert "실행 프로필" not in content
        for line in content.splitlines():
            if "[(ngModel)]" in line:
                assert "(ngModelChange)" in line, f"render update missing: {path}: {line}"
