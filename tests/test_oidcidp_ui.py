"""Tests for oidcidp portal app APIs and UI-facing simulation flows."""
import base64
import datetime
import hashlib
import json
import os
import sys
import urllib.parse

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from conftest import WizClient, ADMIN_SESSION


@pytest.fixture
def client():
    return WizClient(session_data=ADMIN_SESSION)


def _register_rp(client, name='Pytest OIDC RP'):
    resp = client.app_api('portal.oidcidp.rp.register', 'register', {
        'client_name': name,
        'redirect_uris': json.dumps(['https://pytest-rp.example.com/callback']),
        'post_logout_redirect_uris': json.dumps(['https://pytest-rp.example.com/logout/callback']),
        'grant_types': json.dumps(['authorization_code', 'refresh_token']),
        'response_types': json.dumps(['code']),
        'scope_policy': json.dumps(['openid', 'profile', 'email', 'groups']),
        'claims_policy': json.dumps(['sub', 'preferred_username', 'email', 'name', 'department']),
        'token_endpoint_auth_method': 'client_secret_basic',
        'public_client': 'false',
        'jwks': '',
        'jwks_uri': '',
        'extra': json.dumps({'notes': 'pytest registration'}),
    })
    body = client.assert_ok(resp)
    return body['data']['data']


def _create_temp_user(client, username='oidc_pytest_user'):
    resp = client.route('/api/idpcore/user-create-temporary', data={
        'username': username,
        'password': 'test1234',
        'display_name': 'OIDC Pytest User',
        'email': f'{username}@debug-idp.nanoha.kr',
        'profile': json.dumps({'department': 'qa', 'groups': ['oidc-testers']}),
        'oidc_claims': json.dumps({
            'preferred_username': username,
            'email': f'{username}@debug-idp.nanoha.kr',
            'name': 'OIDC Pytest User',
            'department': 'qa',
            'groups': ['oidc-testers'],
        }),
    }, method='POST')
    body = client.assert_ok(resp)
    return body['data']['data']


def _get_oidc_preset_id(client, name='academic-profile'):
    resp = client.route('/api/idpcore/presets', data={'protocol': 'oidc'})
    body = client.assert_ok(resp)
    preset = next(item for item in body['data']['data'] if item['name'] == name)
    return preset['id']


def _pkce_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')


def _basic_auth_header(client_id: str, client_secret: str) -> str:
    token = f'{client_id}:{client_secret}'.encode('utf-8')
    return f'Basic {base64.b64encode(token).decode("utf-8")}'


class TestOIDCRPRegister:
    def test_register_rp_and_bootstrap_list(self, client):
        rp = _register_rp(client, name='Pytest RP Register')

        try:
            assert rp['client_id'].startswith('rp_')
            assert rp['client_secret'].startswith('secret_')
            assert rp['redirect_uris'][0] == 'https://pytest-rp.example.com/callback'
            assert rp['expires'] is not None

            resp = client.app_api('portal.oidcidp.rp.register', 'bootstrap')
            body = client.assert_ok(resp)
            rows = body['data']['data']['clients']
            assert any(item['client_id'] == rp['client_id'] for item in rows)
            assert body['data']['data']['provider']['issuer'] == 'https://debug-idp.nanoha.kr'
        finally:
            client.assert_ok(client.app_api('portal.oidcidp.rp.register', 'delete', {'id': rp['id']}))

    def test_delete_registered_rp_removes_row(self, client):
        rp = _register_rp(client, name='Pytest RP Delete')

        resp = client.app_api('portal.oidcidp.rp.register', 'delete', {'id': rp['id']})
        body = client.assert_ok(resp)
        assert body['data']['message'] == 'deleted'

        resp = client.app_api('portal.oidcidp.rp.register', 'bootstrap')
        body = client.assert_ok(resp)
        rows = body['data']['data']['clients']
        assert all(item['id'] != rp['id'] for item in rows)

    def test_update_registered_rp_persists_changes(self, client):
        rp = _register_rp(client, name='Pytest RP Update')

        try:
            resp = client.app_api('portal.oidcidp.rp.register', 'update', {
                'id': rp['id'],
                'client_name': 'Pytest RP Updated',
                'redirect_uris': json.dumps(['https://pytest-rp.example.com/updated/callback']),
                'post_logout_redirect_uris': json.dumps([]),
                'grant_types': json.dumps(['authorization_code']),
                'response_types': json.dumps(['code']),
                'scope_policy': json.dumps(['openid', 'profile']),
                'claims_policy': json.dumps(['sub', 'email']),
                'token_endpoint_auth_method': 'none',
                'public_client': 'true',
                'jwks': '',
                'jwks_uri': '',
                'extra': json.dumps({'notes': 'updated note'}),
            })
            body = client.assert_ok(resp)
            updated = body['data']['data']

            assert updated['client_name'] == 'Pytest RP Updated'
            assert updated['redirect_uris'] == ['https://pytest-rp.example.com/updated/callback']
            assert updated['post_logout_redirect_uris'] == []
            assert updated['grant_types'] == ['authorization_code']
            assert updated['scope_policy'] == ['openid', 'profile']
            assert updated['claims_policy'] == ['sub', 'email']
            assert updated['public_client'] is True
            assert updated['token_endpoint_auth_method'] == 'none'
            assert updated['client_secret'] == ''
            assert updated['extra']['notes'] == 'updated note'

            resp = client.app_api('portal.oidcidp.rp.register', 'get', {'id': rp['id']})
            persisted = client.assert_ok(resp)['data']['data']
            assert persisted['client_name'] == 'Pytest RP Updated'
            assert persisted['client_secret'] == ''
        finally:
            client.assert_ok(client.app_api('portal.oidcidp.rp.register', 'delete', {'id': rp['id']}))

    def test_rp_extend_validity_and_set_unlimited(self, client):
        rp = _register_rp(client, name='Pytest RP Validity')
        original_expires = datetime.datetime.fromisoformat(rp['expires'])

        try:
            resp = client.app_api('portal.oidcidp.rp.register', 'extend_validity', {
                'id': rp['id'],
                'ttl_hours': '24',
            })
            body = client.assert_ok(resp)
            extended = body['data']['data']
            extended_expires = datetime.datetime.fromisoformat(extended['expires'])
            assert extended_expires > original_expires

            resp = client.app_api('portal.oidcidp.rp.register', 'set_unlimited', {'id': rp['id']})
            body = client.assert_ok(resp)
            unlimited = body['data']['data']
            assert unlimited['expires'] is None
        finally:
            client.assert_ok(client.app_api('portal.oidcidp.rp.register', 'delete', {'id': rp['id']}))


class TestOIDCPublishAndSimulations:
    def test_discovery_route_returns_openid_configuration_document(self, client):
        resp = client.route('/.well-known/openid-configuration')
        assert resp.status_code == 200
        data = resp.json()
        assert data['issuer'] == 'https://debug-idp.nanoha.kr'
        assert data['jwks_uri'] == 'https://debug-idp.nanoha.kr/api/oidc/jwks'
        assert data['authorization_endpoint'] == 'https://debug-idp.nanoha.kr/api/oidc/authorize'

    def test_jwks_route_returns_public_keys(self, client):
        resp = client.route('/api/oidc/jwks')
        assert resp.status_code == 200
        data = resp.json()
        assert 'keys' in data
        assert len(data['keys']) == 1
        assert data['keys'][0]['kid'].startswith('oidc-')

    def test_publish_info_returns_discovery_and_jwks(self, client):
        resp = client.app_api('portal.oidcidp.provider.publish', 'info')
        body = client.assert_ok(resp)
        data = body['data']['data']

        assert data['provider']['issuer'] == 'https://debug-idp.nanoha.kr'
        assert data['discovery']['jwks_uri'] == 'https://debug-idp.nanoha.kr/api/oidc/jwks'
        assert len(data['jwks']['keys']) == 1
        assert data['jwks']['keys'][0]['kid'].startswith('oidc-')

    def test_authorize_simulation_returns_code_and_token_preview(self, client):
        rp = _register_rp(client, name='Pytest Authorize RP')
        user = _create_temp_user(client, username='oidc_auth_pytest')
        preset_id = _get_oidc_preset_id(client)
        code_verifier = 'pytest-code-verifier-0123456789abcdef'

        try:
            resp = client.app_api('portal.oidcidp.authorize.check', 'simulate', {
                'client_id': rp['client_id'],
                'user_id': user['id'],
                'redirect_uri': rp['redirect_uris'][0],
                'response_type': 'code',
                'response_mode': 'query',
                'scope': 'openid profile email groups',
                'claims': json.dumps({'userinfo': {'department': {'essential': True}}}),
                'preset_id': preset_id,
                'state': 'pytest_state',
                'nonce': 'pytest_nonce',
                'code_challenge': _pkce_challenge(code_verifier),
                'code_challenge_method': 'S256',
                'code_verifier': code_verifier,
            })
            body = client.assert_ok(resp)
            data = body['data']['data']

            assert data['status'] == 'success'
            assert data['authorization_code'].startswith('code_')
            assert data['token_response']['access_token'].count('.') == 2
            assert data['id_token'].count('.') == 2
            assert data['userinfo']['sub'] == user['id']
            assert data['id_token_payload']['aud'] == rp['client_id']
            assert data['redirect_target'].startswith(rp['redirect_uris'][0])
            assert data['debug_raw_url'].endswith(data['history_key'])

            raw_resp = client.route(f'/api/oidc/debug/raw/{data["history_key"]}')
            assert raw_resp.status_code == 200
            raw_data = raw_resp.json()
            assert raw_data['authorize_request']['client_id'] == rp['client_id']
            assert raw_data['token_response']['scope'] == 'openid profile email groups'
            assert raw_data['userinfo']['department'] == 'qa'

            history = client.assert_ok(client.app_api('portal.oidcidp.authorize.check', 'history'))['data']['data']
            assert any(item['summary']['client_id'] == rp['client_id'] for item in history)
        finally:
            client.assert_ok(client.route('/api/idpcore/user-delete', data={'id': user['id']}, method='POST'))
            client.assert_ok(client.app_api('portal.oidcidp.rp.register', 'delete', {'id': rp['id']}))

    def test_public_authorize_token_userinfo_code_flow(self, client):
        rp = _register_rp(client, name='Pytest Public Flow RP')
        user = _create_temp_user(client, username='oidc_public_flow')
        code_verifier = 'pytest-public-code-verifier-0123456789abcdef'
        code_challenge = _pkce_challenge(code_verifier)

        try:
            authorize_resp = client.session.get(
                f'{client.base_url}/api/oidc/authorize',
                params={
                    'client_id': rp['client_id'],
                    'user_id': user['id'],
                    'redirect_uri': rp['redirect_uris'][0],
                    'response_type': 'code',
                    'scope': 'openid profile email groups',
                    'state': 'public_state',
                    'nonce': 'public_nonce',
                    'code_challenge': code_challenge,
                    'code_challenge_method': 'S256',
                },
                allow_redirects=False,
            )
            assert authorize_resp.status_code == 302

            location = authorize_resp.headers['Location']
            parsed = urllib.parse.urlparse(location)
            query = urllib.parse.parse_qs(parsed.query)
            assert query['state'][0] == 'public_state'
            code = query['code'][0]

            token_resp = client.session.post(
                f'{client.base_url}/api/oidc/token',
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': rp['redirect_uris'][0],
                    'code_verifier': code_verifier,
                },
                headers={'Authorization': _basic_auth_header(rp['client_id'], rp['client_secret'])},
            )
            assert token_resp.status_code == 200
            token_data = token_resp.json()
            assert token_data['access_token'].count('.') == 2
            assert token_data['id_token'].count('.') == 2
            assert token_data['scope'] == 'openid profile email groups'

            userinfo_resp = client.session.get(
                f'{client.base_url}/api/oidc/userinfo',
                headers={'Authorization': f'Bearer {token_data["access_token"]}'},
            )
            assert userinfo_resp.status_code == 200
            userinfo = userinfo_resp.json()
            assert userinfo['sub'] == user['id']
            assert userinfo['department'] == 'qa'
            assert userinfo['preferred_username'] == user['username']

            invalid_resp = client.session.post(
                f'{client.base_url}/api/oidc/token',
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': rp['redirect_uris'][0],
                    'code_verifier': code_verifier,
                },
                headers={'Authorization': _basic_auth_header(rp['client_id'], rp['client_secret'])},
            )
            assert invalid_resp.status_code == 400
            invalid_data = invalid_resp.json()
            assert invalid_data['error'] == 'invalid_grant'
        finally:
            client.assert_ok(client.route('/api/idpcore/user-delete', data={'id': user['id']}, method='POST'))
            client.assert_ok(client.app_api('portal.oidcidp.rp.register', 'delete', {'id': rp['id']}))

    def test_public_authorize_without_session_renders_login_prompt(self, client):
        rp = _register_rp(client, name='Pytest Authorize Prompt RP')
        user = _create_temp_user(client, username='oidc_authorize_prompt')
        anonymous = WizClient()

        try:
            authorize_resp = anonymous.session.get(
                f'{anonymous.base_url}/api/oidc/authorize',
                params={
                    'client_id': rp['client_id'],
                    'redirect_uri': rp['redirect_uris'][0],
                    'response_type': 'code',
                    'scope': 'openid profile email',
                    'state': 'prompt_state',
                    'nonce': 'prompt_nonce',
                },
                allow_redirects=False,
            )
            assert authorize_resp.status_code == 200
            assert 'text/html' in authorize_resp.headers.get('Content-Type', '')
            assert 'Test IdP Sign In' in authorize_resp.text
            assert rp['client_id'] in authorize_resp.text
            assert user['email'] in authorize_resp.text
            assert 'admin@test-idp.local' not in authorize_resp.text

            login_resp = anonymous.session.get(
                f'{anonymous.base_url}/api/oidc/authorize',
                params={
                    'client_id': rp['client_id'],
                    'redirect_uri': rp['redirect_uris'][0],
                    'response_type': 'code',
                    'scope': 'openid profile email',
                    'state': 'prompt_state',
                    'nonce': 'prompt_nonce',
                    'selected_user_id': user['id'],
                },
                allow_redirects=False,
            )
            assert login_resp.status_code == 302

            location = login_resp.headers['Location']
            parsed = urllib.parse.urlparse(location)
            query = urllib.parse.parse_qs(parsed.query)
            assert query['state'][0] == 'prompt_state'
            assert query['code'][0].startswith('code_')
        finally:
            client.assert_ok(client.route('/api/idpcore/user-delete', data={'id': user['id']}, method='POST'))
            client.assert_ok(client.app_api('portal.oidcidp.rp.register', 'delete', {'id': rp['id']}))

    def test_logout_simulation_validates_redirect_and_hint(self, client):
        rp = _register_rp(client, name='Pytest Logout RP')
        user = _create_temp_user(client, username='oidc_logout_pytest')

        try:
            resp = client.app_api('portal.oidcidp.logout.check', 'simulate', {
                'client_id': rp['client_id'],
                'user_id': user['id'],
                'post_logout_redirect_uri': rp['post_logout_redirect_uris'][0],
                'state': 'logout_state',
                'local_session_clear': 'true',
            })
            body = client.assert_ok(resp)
            data = body['data']['data']

            assert data['redirect_target'] == rp['post_logout_redirect_uris'][0]
            assert data['session_match']['matched'] is True
            assert data['id_token_hint'].count('.') == 2
            assert data['end_session_url'].startswith('https://debug-idp.nanoha.kr/api/oidc/logout')
            assert 'post_logout_redirect_uri=' in data['end_session_url']

            history = client.assert_ok(client.app_api('portal.oidcidp.logout.check', 'history'))['data']['data']
            assert any(item['summary']['client_id'] == rp['client_id'] for item in history)
        finally:
            client.assert_ok(client.route('/api/idpcore/user-delete', data={'id': user['id']}, method='POST'))
            client.assert_ok(client.app_api('portal.oidcidp.rp.register', 'delete', {'id': rp['id']}))