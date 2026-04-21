import { OnInit } from '@angular/core';
import { Service } from '@wiz/libs/portal/season/service';

export class Component implements OnInit {
    public loading: boolean = true;
    public submitting: boolean = false;
    public mode: string = 'list';
    public items: any[] = [];
    public provider: any = null;
    public selectedItem: any = null;
    public registerResult: any = null;
    public copied: string = '';
    public options: any = {
        auth_methods: [],
        grant_types: [],
        response_types: [],
        scope_options: [],
    };
    public form: any = this.defaultForm();

    constructor(public service: Service) { }

    public async ngOnInit() {
        await this.service.init();
        await this.load();
    }

    public defaultForm() {
        return {
            client_name: '',
            redirect_uris_text: 'https://rp.example.com/callback',
            post_logout_redirect_uris_text: 'https://rp.example.com/logout/callback',
            grant_types: ['authorization_code', 'refresh_token'],
            response_types: ['code'],
            scope_policy: ['openid', 'profile', 'email'],
            claims_policy_text: 'sub\npreferred_username\nemail\nname',
            token_endpoint_auth_method: 'client_secret_basic',
            public_client: false,
            jwks_uri: '',
            jwks_text: '',
            extra_notes: '',
        };
    }

    public async load() {
        this.loading = true;
        await this.service.render();

        try {
            const res = await wiz.call('bootstrap', {});
            if (res.code === 200) {
                const data = res.data.data || res.data;
                this.items = data.clients || [];
                this.provider = data.provider || null;
                this.options = data.options || this.options;
            }
        } catch (e) {
            this.items = [];
            this.provider = null;
        }

        this.loading = false;
        await this.service.render();
    }

    public async openCreate() {
        this.form = this.defaultForm();
        this.registerResult = null;
        this.selectedItem = null;
        this.mode = 'create';
        await this.service.render();
    }

    public formFromItem(item: any) {
        return {
            client_name: item.client_name || '',
            redirect_uris_text: (item.redirect_uris || []).join('\n'),
            post_logout_redirect_uris_text: (item.post_logout_redirect_uris || []).join('\n'),
            grant_types: [...(item.grant_types || [])],
            response_types: [...(item.response_types || [])],
            scope_policy: [...(item.scope_policy || [])],
            claims_policy_text: (item.claims_policy || []).join('\n'),
            token_endpoint_auth_method: item.token_endpoint_auth_method || 'client_secret_basic',
            public_client: !!item.public_client,
            jwks_uri: item.extra?.jwks_uri || '',
            jwks_text: this.stringify(item.jwks),
            extra_notes: item.extra?.notes || '',
        };
    }

    public async openEdit(item: any) {
        this.selectedItem = item;
        this.form = this.formFromItem(item);
        this.registerResult = null;
        this.mode = 'edit';
        await this.service.render();
    }

    public async showList() {
        this.mode = 'list';
        this.registerResult = null;
        this.selectedItem = null;
        await this.load();
    }

    public async cancelForm() {
        if (this.mode === 'edit' && this.selectedItem) {
            this.mode = 'detail';
            await this.service.render();
            return;
        }
        await this.showList();
    }

    public async showDetail(item: any) {
        this.selectedItem = item;
        this.mode = 'detail';
        await this.service.render();
    }

    public async toggleListValue(key: string, value: string) {
        const current = Array.isArray(this.form[key]) ? [...this.form[key]] : [];
        const index = current.indexOf(value);
        if (index >= 0) {
            current.splice(index, 1);
        } else {
            current.push(value);
        }
        this.form[key] = current;
        await this.service.render();
    }

    public isSelected(value: string, items: any[]) {
        return Array.isArray(items) && items.includes(value);
    }

    public chipClass(active: boolean) {
        if (active) {
            return 'inline-flex items-center rounded-full bg-sky-600 px-3 py-1.5 text-xs font-semibold text-white';
        }
        return 'inline-flex items-center rounded-full bg-white px-3 py-1.5 text-xs font-semibold text-zinc-600 ring-1 ring-inset ring-zinc-200 transition hover:bg-zinc-50';
    }

    public async onAuthMethodChange() {
        if (this.form.token_endpoint_auth_method === 'none') {
            this.form.public_client = true;
        }
        await this.service.render();
    }

    public async onPublicClientChange() {
        if (this.form.public_client) {
            this.form.token_endpoint_auth_method = 'none';
        } else if (this.form.token_endpoint_auth_method === 'none') {
            this.form.token_endpoint_auth_method = 'client_secret_basic';
        }
        await this.service.render();
    }

    public parseLines(text: string) {
        return String(text || '')
            .replace(/\r/g, '\n')
            .split('\n')
            .map((item) => item.trim())
            .filter((item, index, array) => item !== '' && array.indexOf(item) === index);
    }

    public stringify(value: any) {
        if (value === null || value === undefined) return '';
        if (typeof value === 'string') return value;
        return JSON.stringify(value, null, 2);
    }

    public buildPayload() {
        return {
            client_name: String(this.form.client_name || '').trim(),
            redirect_uris: JSON.stringify(this.parseLines(this.form.redirect_uris_text)),
            post_logout_redirect_uris: JSON.stringify(this.parseLines(this.form.post_logout_redirect_uris_text)),
            grant_types: JSON.stringify(this.form.grant_types || []),
            response_types: JSON.stringify(this.form.response_types || []),
            scope_policy: JSON.stringify(this.form.scope_policy || []),
            claims_policy: JSON.stringify(this.parseLines(this.form.claims_policy_text)),
            token_endpoint_auth_method: this.form.token_endpoint_auth_method,
            public_client: this.form.public_client ? 'true' : 'false',
            jwks_uri: String(this.form.jwks_uri || '').trim(),
            jwks: String(this.form.jwks_text || '').trim(),
            extra: JSON.stringify({ notes: String(this.form.extra_notes || '').trim() }),
        };
    }

    public async submitForm() {
        if (this.mode === 'edit') {
            await this.update();
            return;
        }
        await this.register();
    }

    public async register() {
        if (!String(this.form.client_name || '').trim()) {
            await this.service.modal.error('RP 이름을 입력해주세요.');
            return;
        }

        const redirectUris = this.parseLines(this.form.redirect_uris_text);
        if (redirectUris.length === 0) {
            await this.service.modal.error('redirect_uri를 하나 이상 입력해주세요.');
            return;
        }

        this.submitting = true;
        await this.service.render();

        try {
            const payload = this.buildPayload();
            const res = await wiz.call('register', payload);
            if (res.code === 200) {
                this.registerResult = res.data.data || res.data;
                this.mode = 'result';
            } else {
                await this.service.modal.error(res.data?.message || 'RP 등록에 실패했습니다.');
            }
        } catch (e: any) {
            await this.service.modal.error(e.message || 'RP 등록 중 오류가 발생했습니다.');
        }

        this.submitting = false;
        await this.service.render();
    }

    public async update() {
        if (!this.selectedItem?.id) {
            await this.service.modal.error('수정할 RP를 찾을 수 없습니다.');
            return;
        }

        if (!String(this.form.client_name || '').trim()) {
            await this.service.modal.error('RP 이름을 입력해주세요.');
            return;
        }

        const redirectUris = this.parseLines(this.form.redirect_uris_text);
        if (redirectUris.length === 0) {
            await this.service.modal.error('redirect_uri를 하나 이상 입력해주세요.');
            return;
        }

        const previousSecret = this.selectedItem.client_secret || '';
        this.submitting = true;
        await this.service.render();

        try {
            const payload = this.buildPayload();
            payload.id = this.selectedItem.id;

            const res = await wiz.call('update', payload);
            if (res.code === 200) {
                const updated = res.data.data || res.data;
                await this.load();
                this.selectedItem = this.items.find((item) => item.id === updated.id) || updated;
                this.mode = 'detail';

                if (!previousSecret && this.selectedItem.client_secret) {
                    await this.service.modal.success('RP 정보를 수정했고 새 client_secret이 발급되었습니다. 상세 화면에서 복사할 수 있습니다.');
                } else {
                    await this.service.modal.success('RP 정보를 수정했습니다.');
                }
            } else {
                await this.service.modal.error(res.data?.message || 'RP 수정에 실패했습니다.');
            }
        } catch (e: any) {
            await this.service.modal.error(e.message || 'RP 수정 중 오류가 발생했습니다.');
        }

        this.submitting = false;
        await this.service.render();
    }

    public async deleteClient(item: any) {
        const confirmed = await this.service.modal.show({
            title: 'RP 삭제',
            message: `'${item.client_name}' RP를 삭제하시겠습니까?`,
            action: '삭제',
            cancel: '취소',
            status: 'error',
            actionBtn: 'error',
        });
        if (!confirmed) {
            return;
        }

        try {
            const res = await wiz.call('delete', { id: item.id });
            if (res.code === 200) {
                if (this.selectedItem && this.selectedItem.id === item.id) {
                    this.selectedItem = null;
                    this.mode = 'list';
                }
                await this.load();
                return;
            }
            await this.service.modal.error(res.data?.message || 'RP 삭제에 실패했습니다.');
        } catch (e: any) {
            await this.service.modal.error(e.message || 'RP 삭제 중 오류가 발생했습니다.');
        }
    }

    public isAdmin(): boolean {
        return this.service.auth.check.role && this.service.auth.check.role('admin');
    }

    public isExpired(expires: string | null): boolean {
        if (!expires) return false;
        return new Date(expires).getTime() <= new Date().getTime();
    }

    public isExpiringSoon(expires: string | null): boolean {
        if (!expires) return false;
        const diff = new Date(expires).getTime() - new Date().getTime();
        return diff > 0 && diff < 2 * 60 * 60 * 1000;
    }

    public getTimeRemaining(expires: string | null): string {
        if (!expires) return '영구';
        const diff = new Date(expires).getTime() - new Date().getTime();
        if (diff <= 0) return '만료됨';
        const hours = Math.floor(diff / (1000 * 60 * 60));
        const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
        if (hours > 0) return `${hours}시간 ${minutes}분 남음`;
        return `${minutes}분 남음`;
    }

    public async extendClient(item: any) {
        if (!this.isAdmin() || !item.expires) return;

        try {
            const res = await wiz.call('extend_validity', { id: item.id, ttl_hours: '24' });
            if (res.code === 200) {
                const updated = res.data.data || res.data;
                this.selectedItem = this.selectedItem && this.selectedItem.id === updated.id ? updated : this.selectedItem;
                this.registerResult = this.registerResult && this.registerResult.id === updated.id ? updated : this.registerResult;
                await this.load();
                if (this.selectedItem && this.selectedItem.id === updated.id) {
                    this.selectedItem = updated;
                }
                return;
            }
            await this.service.modal.error(res.data?.message || 'RP 유효 시간 연장에 실패했습니다.');
        } catch (e: any) {
            await this.service.modal.error(e.message || 'RP 유효 시간 연장 중 오류가 발생했습니다.');
        }
    }

    public async setUnlimited(item: any) {
        if (!this.isAdmin() || !item.expires) return;

        const confirmed = await this.service.modal.show({
            title: '영구 보관 전환',
            message: `'${item.client_name}' RP를 무기한 보관으로 전환하시겠습니까?`,
            action: '영구 보관',
            cancel: '취소',
            status: 'warning',
            actionBtn: 'warning',
        });
        if (!confirmed) {
            return;
        }

        try {
            const res = await wiz.call('set_unlimited', { id: item.id });
            if (res.code === 200) {
                const updated = res.data.data || res.data;
                this.selectedItem = this.selectedItem && this.selectedItem.id === updated.id ? updated : this.selectedItem;
                this.registerResult = this.registerResult && this.registerResult.id === updated.id ? updated : this.registerResult;
                await this.load();
                if (this.selectedItem && this.selectedItem.id === updated.id) {
                    this.selectedItem = updated;
                }
                return;
            }
            await this.service.modal.error(res.data?.message || 'RP 영구 보관 전환에 실패했습니다.');
        } catch (e: any) {
            await this.service.modal.error(e.message || 'RP 영구 보관 전환 중 오류가 발생했습니다.');
        }
    }

    public async copyText(text: string, label: string = '') {
        try {
            await navigator.clipboard.writeText(String(text || ''));
            this.copied = label;
            await this.service.render();
            setTimeout(async () => {
                this.copied = '';
                await this.service.render();
            }, 1500);
        } catch (e) { }
    }
}