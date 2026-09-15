import { OnInit } from '@angular/core';
import { Service } from '@wiz/libs/portal/season/service';

export class Component implements OnInit {
    public loading: boolean = true;
    public submitting: boolean = false;
    public quickCreating: boolean = false;
    public mode: string = 'compose';
    public clients: any[] = [];
    public users: any[] = [];
    public presets: any[] = [];
    public history: any[] = [];
    public provider: any = null;
    public options: any = {
        response_types: [],
        response_modes: [],
        code_challenge_methods: [],
        error_modes: [],
    };
    public result: any = null;
    public showSecrets: boolean = false;
    public form: any = this.defaultForm();

    constructor(public service: Service) { }

    public async ngOnInit() {
        await this.service.init();
        await this.loadBootstrap();
    }

    public defaultForm() {
        return {
            client_id: '',
            user_id: '',
            redirect_uri: '',
            response_type: 'code',
            response_mode: '',
            scope: 'openid profile email',
            claims: '{}',
            preset_id: '',
            state: 'state_demo',
            nonce: 'nonce_demo',
            prompt: '',
            max_age: '',
            acr_values: '',
            code_challenge: '',
            code_challenge_method: 'S256',
            code_verifier: '',
            error_mode: '',
        };
    }

    private encodeBase64Url(bytes: Uint8Array) {
        let binary = '';
        bytes.forEach((value) => {
            binary += String.fromCharCode(value);
        });
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    }

    private async sha256Base64Url(value: string) {
        const encoded = new TextEncoder().encode(value);
        const digest = await crypto.subtle.digest('SHA-256', encoded);
        return this.encodeBase64Url(new Uint8Array(digest));
    }

    public async syncPkceFromVerifier() {
        if (!this.form.code_verifier) {
            this.form.code_challenge = '';
            await this.service.render();
            return;
        }

        if (this.form.code_challenge_method === 'plain') {
            this.form.code_challenge = this.form.code_verifier;
        } else {
            this.form.code_challenge = await this.sha256Base64Url(this.form.code_verifier);
        }
        await this.service.render();
    }

    public async generatePkce() {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
        const buffer = new Uint8Array(64);
        crypto.getRandomValues(buffer);
        this.form.code_verifier = Array.from(buffer)
            .map((value) => chars.charAt(value % chars.length))
            .join('');
        await this.syncPkceFromVerifier();
    }

    public async loadBootstrap() {
        this.loading = true;
        await this.service.render();

        try {
            const res = await wiz.call('bootstrap', {});
            if (res.code === 200) {
                const data = res.data.data || res.data;
                this.clients = data.clients || [];
                this.users = data.users || [];
                this.presets = data.presets || [];
                this.history = data.history || [];
                this.provider = data.provider || null;
                this.options = data.options || this.options;

                if (!this.form.client_id && this.clients.length > 0) {
                    this.form.client_id = this.clients[0].client_id;
                }
                if (!this.form.user_id && this.users.length > 0) {
                    this.form.user_id = this.users[0].id;
                }
                await this.onClientChange(false);
            }
        } catch (e) {
            this.clients = [];
            this.users = [];
            this.presets = [];
            this.history = [];
            this.provider = null;
        }

        this.loading = false;
        await this.service.render();
    }

    public async loadHistory() {
        try {
            const res = await wiz.call('history', {});
            if (res.code === 200) {
                this.history = res.data.data || res.data || [];
            }
        } catch (e) {
            this.history = [];
        }
        await this.service.render();
    }

    public selectedClient() {
        return this.clients.find((item) => item.client_id === this.form.client_id) || null;
    }

    public async onClientChange(shouldRender: boolean = true) {
        const client = this.selectedClient();
        if (client && (!this.form.redirect_uri || !(client.redirect_uris || []).includes(this.form.redirect_uri))) {
            this.form.redirect_uri = (client.redirect_uris || [])[0] || '';
        }
        if (shouldRender) {
            await this.service.render();
        }
    }

    public isScopeSelected(scope: string) {
        return String(this.form.scope || '').split(' ').includes(scope);
    }

    public async toggleScope(scope: string) {
        const scopes = String(this.form.scope || '')
            .split(' ')
            .map((item) => item.trim())
            .filter((item) => item !== '');
        const index = scopes.indexOf(scope);
        if (index >= 0) {
            scopes.splice(index, 1);
        } else {
            scopes.push(scope);
        }
        this.form.scope = scopes.join(' ');
        await this.service.render();
    }

    public async simulate() {
        if (!this.form.client_id || !this.form.user_id) {
            await this.service.modal.error('대상 RP와 사용자를 선택해주세요.');
            return;
        }

        this.submitting = true;
        await this.service.render();

        try {
            const res = await wiz.call('simulate', {
                client_id: this.form.client_id,
                user_id: this.form.user_id,
                redirect_uri: this.form.redirect_uri,
                response_type: this.form.response_type,
                response_mode: this.form.response_mode,
                scope: this.form.scope,
                claims: this.form.claims,
                preset_id: this.form.preset_id,
                state: this.form.state,
                nonce: this.form.nonce,
                prompt: this.form.prompt,
                max_age: this.form.max_age,
                acr_values: this.form.acr_values,
                code_challenge: this.form.code_challenge,
                code_challenge_method: this.form.code_challenge_method,
                code_verifier: this.form.code_verifier,
                error_mode: this.form.error_mode,
            });
            if (res.code === 200) {
                this.result = res.data.data || res.data;
                this.mode = 'result';
                await this.loadHistory();
            } else {
                await this.service.modal.error(res.data?.message || 'authorize 시뮬레이션에 실패했습니다.');
            }
        } catch (e: any) {
            await this.service.modal.error(e.message || 'authorize 시뮬레이션 중 오류가 발생했습니다.');
        }

        this.submitting = false;
        await this.service.render();
    }

    public async showCompose() {
        this.mode = 'compose';
        this.result = null;
        await this.loadHistory();
    }

    public stringify(value: any) {
        if (value === null || value === undefined) return '';
        if (typeof value === 'string') return value;
        return JSON.stringify(value, null, 2);
    }

    public tokenPreview(value: any) {
        if (this.showSecrets || !value || typeof value !== 'object') return value;
        const masked = { ...value };
        ['access_token', 'id_token', 'refresh_token'].forEach((key) => {
            if (masked[key]) masked[key] = '••••••••••••';
        });
        return masked;
    }

    public async toggleSecrets() {
        this.showSecrets = !this.showSecrets;
        await this.service.render();
    }

    public async copyText(text: string) {
        try {
            await navigator.clipboard.writeText(String(text || ''));
        } catch (e) { }
    }

    private generateSuffix(): string {
        const letters = 'abcdefghijklmnopqrstuvwxyz';
        const digits = '0123456789';
        let result = '';
        for (let i = 0; i < 2; i += 1) result += letters.charAt(Math.floor(Math.random() * letters.length));
        for (let i = 0; i < 2; i += 1) result += digits.charAt(Math.floor(Math.random() * digits.length));
        return result;
    }

    private generatePassword(): string {
        return `test-${this.generateSuffix()}-${this.generateSuffix()}`;
    }

    public async quickCreateUser() {
        this.quickCreating = true;
        await this.service.render();

        const suffix = this.generateSuffix();
        const password = this.generatePassword();
        const username = `oidc_${suffix}`;
        const data: any = {
            username: username,
            password: password,
            display_name: `OIDC Tester ${suffix.toUpperCase()}`,
            email: `${username}@debug-idp.nanoha.kr`,
            profile: JSON.stringify({ department: 'qa', groups: ['oidc-testers'] }),
            oidc_claims: JSON.stringify({
                preferred_username: username,
                email: `${username}@debug-idp.nanoha.kr`,
                name: `OIDC Tester ${suffix.toUpperCase()}`,
                groups: ['oidc-testers'],
                department: 'qa',
            }),
        };

        try {
            const res = await this.service.request.post('/api/idpcore/user-create-temporary', data);
            if (res.code === 200) {
                const created = res.data.data || res.data;
                await this.loadBootstrap();
                this.form.user_id = created.id;
                await this.service.render();
            } else {
                await this.service.modal.error(res.data?.message || '임시 계정 생성에 실패했습니다.');
            }
        } catch (e: any) {
            await this.service.modal.error(e.message || '임시 계정 생성 중 오류가 발생했습니다.');
        }

        this.quickCreating = false;
        await this.service.render();
    }
}
