import { OnInit } from '@angular/core';
import { Service } from '@wiz/libs/portal/season/service';

export class Component implements OnInit {
    public loading: boolean = true;
    public submitting: boolean = false;
    public mode: string = 'compose';
    public clients: any[] = [];
    public users: any[] = [];
    public history: any[] = [];
    public provider: any = null;
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
            post_logout_redirect_uri: '',
            id_token_hint: '',
            logout_hint: '',
            state: 'logout_state',
            ui_locales: 'ko en',
            local_session_clear: true,
        };
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
                this.history = data.history || [];
                this.provider = data.provider || null;
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
        const redirects = client?.post_logout_redirect_uris || [];
        if (!this.form.post_logout_redirect_uri || !redirects.includes(this.form.post_logout_redirect_uri)) {
            this.form.post_logout_redirect_uri = redirects[0] || '';
        }
        if (shouldRender) {
            await this.service.render();
        }
    }

    public async simulate() {
        if (!this.form.client_id) {
            await this.service.modal.error('대상 RP를 선택해주세요.');
            return;
        }

        this.submitting = true;
        await this.service.render();

        try {
            const res = await wiz.call('simulate', {
                client_id: this.form.client_id,
                user_id: this.form.user_id,
                post_logout_redirect_uri: this.form.post_logout_redirect_uri,
                id_token_hint: this.form.id_token_hint,
                logout_hint: this.form.logout_hint,
                state: this.form.state,
                ui_locales: this.form.ui_locales,
                local_session_clear: this.form.local_session_clear ? 'true' : 'false',
            });
            if (res.code === 200) {
                this.result = res.data.data || res.data;
                this.mode = 'result';
                await this.loadHistory();
            } else {
                await this.service.modal.error(res.data?.message || 'logout 시뮬레이션에 실패했습니다.');
            }
        } catch (e: any) {
            await this.service.modal.error(e.message || 'logout 시뮬레이션 중 오류가 발생했습니다.');
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

    public async copyText(text: string) {
        try {
            await navigator.clipboard.writeText(String(text || ''));
        } catch (e) { }
    }

    public openEndSession() {
        const url = String(this.result?.end_session_url || '');
        if (url) window.open(url, '_blank', 'noopener,noreferrer');
    }

    public maskedLogoutUrl(value: string) {
        if (this.showSecrets) return value;
        try {
            const url = new URL(value);
            if (url.searchParams.has('id_token_hint')) url.searchParams.set('id_token_hint', '••••••••••••');
            return url.toString();
        } catch (e) {
            return '민감한 값 숨김';
        }
    }

    public async toggleSecrets() {
        this.showSecrets = !this.showSecrets;
        await this.service.render();
    }
}
