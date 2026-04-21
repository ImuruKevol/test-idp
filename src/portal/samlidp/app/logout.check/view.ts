import { OnInit } from '@angular/core';
import { Service } from '@wiz/libs/portal/season/service';

export class Component implements OnInit {
    public mode: string = 'overview';
    public loading: boolean = false;
    public spList: any[] = [];
    public users: any[] = [];
    public activeSessions: any[] = [];

    // SP-initiated SLO parse
    public samlRequestInput: string = '';
    public relayStateInput: string = '';
    public bindingInput: string = 'POST';
    public parsedLogoutRequest: any = null;

    // LogoutResponse params
    public signLogoutResponse: boolean = true;
    public logoutStatusCode: string = 'urn:oasis:names:tc:SAML:2.0:status:Success';

    // IdP-initiated SLO
    public selectedSpId: string = '';
    public selectedUserId: string = '';
    public nameidValue: string = '';
    public nameidFormat: string = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
    public signLogoutRequest: boolean = true;

    // Result
    public result: any = null;

    constructor(public service: Service) { }

    public async ngOnInit() {
        await this.service.init();
        await this.loadData();
    }

    public async loadData() {
        this.loading = true;
        await this.service.render();
        try {
            const [spRes, userRes, sessRes] = await Promise.all([
                wiz.call("sp_list", {}),
                wiz.call("user_list", {}),
                wiz.call("active_sessions", {}),
            ]);
            this.spList = spRes.code === 200 ? (spRes.data.data || spRes.data || []) : [];
            this.users = userRes.code === 200 ? (userRes.data.data || userRes.data || []) : [];
            this.activeSessions = sessRes.code === 200 ? (sessRes.data.data || sessRes.data || []) : [];
        } catch (e) { }
        this.loading = false;
        await this.service.render();
    }

    public async parseLogoutRequest() {
        if (!this.samlRequestInput.trim()) {
            await this.service.modal.error('LogoutRequest를 입력해 주세요.');
            return;
        }
        this.loading = true;
        await this.service.render();
        try {
            const res = await wiz.call("parse_logout_request", {
                SAMLRequest: this.samlRequestInput,
                RelayState: this.relayStateInput,
                binding: this.bindingInput,
            });
            if (res.code === 200) {
                this.parsedLogoutRequest = res.data.data || res.data;
                this.mode = 'respond';
            } else {
                await this.service.modal.error(res.data?.message || 'LogoutRequest 파싱 실패');
            }
        } catch (e: any) {
            await this.service.modal.error(e.message || '파싱 오류');
        }
        this.loading = false;
        await this.service.render();
    }

    public async buildLogoutResponse() {
        this.loading = true;
        await this.service.render();

        const matched = this.parsedLogoutRequest?.matched_sessions || [];
        const invalidateIds = matched.map((s: any) => s.id).filter(Boolean);

        const params: any = {
            request_id: this.parsedLogoutRequest?.request_id || '',
            sp_entity_id: this.parsedLogoutRequest?.issuer || '',
            destination: this.getSpSloUrl(this.parsedLogoutRequest?.issuer || ''),
            relay_state: this.parsedLogoutRequest?.relay_state || '',
            status_code: this.logoutStatusCode,
            sign: this.signLogoutResponse ? 'true' : 'false',
            invalidate_ids: JSON.stringify(invalidateIds),
        };

        try {
            const res = await wiz.call("build_logout_response", params);
            if (res.code === 200) {
                this.result = res.data.data || res.data;
                this.mode = 'result';
            } else {
                await this.service.modal.error(res.data?.message || 'LogoutResponse 생성 실패');
            }
        } catch (e: any) {
            await this.service.modal.error(e.message || 'LogoutResponse 생성 오류');
        }
        this.loading = false;
        await this.service.render();
    }

    public async buildIdpLogoutRequest() {
        if (!this.selectedSpId) {
            await this.service.modal.error('SP를 선택해 주세요.');
            return;
        }
        if (!this.nameidValue) {
            await this.service.modal.error('NameID를 입력해 주세요.');
            return;
        }
        this.loading = true;
        await this.service.render();

        const sp = this.spList.find((s: any) => s.id === this.selectedSpId);
        const spEntityId = sp?.entity_id || '';

        const sessionIndexes = this.activeSessions
            .filter((s: any) => s.sp_entity_id === spEntityId && s.session_index)
            .map((s: any) => s.session_index);

        const params: any = {
            sp_entity_id: spEntityId,
            nameid_value: this.nameidValue,
            nameid_format: this.nameidFormat,
            sign: this.signLogoutRequest ? 'true' : 'false',
            session_indexes: JSON.stringify(sessionIndexes),
        };

        try {
            const res = await wiz.call("build_logout_request", params);
            if (res.code === 200) {
                this.result = res.data.data || res.data;
                this.mode = 'idp-result';
            } else {
                await this.service.modal.error(res.data?.message || 'LogoutRequest 생성 실패');
            }
        } catch (e: any) {
            await this.service.modal.error(e.message || 'LogoutRequest 생성 오류');
        }
        this.loading = false;
        await this.service.render();
    }

    public async invalidateSession(sessionId: string) {
        this.loading = true;
        await this.service.render();
        try {
            const res = await wiz.call("invalidate_sessions", { session_ids: JSON.stringify([sessionId]) });
            if (res.code === 200) {
                await this.loadData();
            } else {
                await this.service.modal.error('세션 무효화 실패');
            }
        } catch (e) { }
        this.loading = false;
        await this.service.render();
    }

    public async showOverview() {
        this.mode = 'overview';
        this.parsedLogoutRequest = null;
        this.result = null;
        await this.loadData();
    }

    public getSpSloUrl(entityId: string): string {
        const sp = this.spList.find((s: any) => s.entity_id === entityId);
        if (!sp) return '';
        const sloUrls = sp.slo_url || [];
        for (const ep of sloUrls) {
            if (ep.location) return ep.location;
        }
        return '';
    }

    public onSpChange() {
        const sp = this.spList.find((s: any) => s.id === this.selectedSpId);
        if (sp) {
            const filtered = this.activeSessions.filter((s: any) => s.sp_entity_id === sp.entity_id);
            if (filtered.length > 0 && filtered[0].user_id) {
                const user = this.users.find((u: any) => u.id === filtered[0].user_id);
                if (user) {
                    this.nameidValue = user.email || user.username || '';
                    this.selectedUserId = user.id;
                }
            }
        }
        this.service.render();
    }

    public async copyText(text: string) {
        try {
            await navigator.clipboard.writeText(text);
        } catch (e) { }
    }

    public objectKeys(obj: any): string[] {
        if (!obj || typeof obj !== 'object') return [];
        return Object.keys(obj);
    }

    public stringify(val: any): string {
        if (val === null || val === undefined) return '';
        if (typeof val === 'object') return JSON.stringify(val);
        return String(val);
    }
}
