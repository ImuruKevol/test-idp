import { OnInit } from '@angular/core';
import { Service } from '@wiz/libs/portal/season/service';

export class Component implements OnInit {
    public loading: boolean = true;
    public provider: any = null;
    public discovery: any = {};
    public jwks: any = {};
    public clients: any[] = [];
    public clientCount: number = 0;
    public profileOptions: any[] = [];
    public copied: string = '';
    public profileName: string = '';
    public profilePreset: string = 'standard';
    public profileSettings: any = this.defaultProfileSettings();
    public amrText: string = 'pwd';
    public claimOverridesText: string = '{}';
    public idTokenClaimOverridesText: string = '{}';
    public userinfoClaimOverridesText: string = '{}';
    public distributedClaimsText: string = '{}';
    public omitClaimsText: string = '';
    public idTokenOnlyClaimsText: string = '';
    public userinfoOnlyClaimsText: string = '';
    public profileResult: any = null;
    public profileBusy: boolean = false;
    public discoveryVariant: string = 'standard';

    constructor(public service: Service) { }

    public defaultProfileSettings() {
        return {
            subject_source: 'sub',
            id_token_signing_alg: 'RS256',
            response_variant: 'standard',
            time_offset_seconds: 0,
            token_ttl_seconds: 600,
            session_ttl_seconds: 28800,
            acr: '',
        };
    }

    public async ngOnInit() {
        await this.service.init();
        await this.loadInfo();
    }

    public async loadInfo() {
        this.loading = true;
        await this.service.render();

        try {
            const res = await wiz.call('info', {
                discovery_variant: this.discoveryVariant,
                reviewops_profile: String(this.profileName || '').trim(),
            });
            if (res.code === 200) {
                const data = res.data.data || res.data;
                this.provider = data.provider || null;
                this.discovery = data.discovery || {};
                this.jwks = data.jwks || {};
                this.clients = data.clients || [];
                this.clientCount = data.client_count || 0;
                this.profileOptions = data.profiles || [];
            }
        } catch (e) {
            this.provider = null;
            this.discovery = {};
            this.jwks = {};
            this.clients = [];
            this.clientCount = 0;
            this.profileOptions = [];
        }

        this.loading = false;
        await this.service.render();
    }

    public stringify(value: any) {
        return JSON.stringify(value || {}, null, 2);
    }

    public parseLines(text: string) {
        return String(text || '')
            .replace(/\r/g, '\n')
            .split('\n')
            .map((item) => item.trim())
            .filter((item, index, values) => item !== '' && values.indexOf(item) === index);
    }

    public presetClass(name: string) {
        return this.profilePreset === name
            ? 'rounded-xl border border-sky-300 bg-sky-50 px-3 py-3 text-left text-sky-950 ring-1 ring-sky-200'
            : 'rounded-xl border border-slate-200 bg-white px-3 py-3 text-left text-slate-700 transition hover:border-sky-200 hover:bg-slate-50';
    }

    public async profileChanged() {
        this.profileResult = null;
        await this.service.render();
    }

    public profileOptionClass(name: string) {
        return this.profileName === name
            ? 'border-sky-300 bg-sky-50 text-sky-950 ring-1 ring-sky-200'
            : 'border-slate-200 bg-white text-slate-700 hover:border-sky-200 hover:bg-slate-50';
    }

    public async selectProfile(item: any) {
        this.profileName = item.name;
        await this.service.render();
        await this.loadProfile();
    }

    public async startNewProfile() {
        this.profileName = '';
        this.profilePreset = 'standard';
        await this.applyPreset('standard');
    }

    public hasSavedProfile() {
        const name = String(this.profileName || '').trim();
        return this.profileOptions.some((item: any) => item.name === name);
    }

    public async applyPreset(name: string) {
        this.profilePreset = name;
        this.profileSettings = this.defaultProfileSettings();
        this.amrText = 'pwd';
        this.claimOverridesText = '{}';
        this.idTokenClaimOverridesText = '{}';
        this.userinfoClaimOverridesText = '{}';
        this.distributedClaimsText = '{}';
        this.omitClaimsText = '';
        this.idTokenOnlyClaimsText = '';
        this.userinfoOnlyClaimsText = '';
        if (name === 'mfa') {
            this.profileSettings.acr = 'https://refeds.org/profile/mfa';
            this.amrText = 'pwd\notp';
        } else if (name === 'claims') {
            this.profileSettings.subject_source = 'preferred_username';
            this.claimOverridesText = JSON.stringify({ groups: ['engineering', 'qa'] }, null, 2);
        } else if (name === 'error') {
            this.profileSettings.response_variant = 'expired';
        }
        this.profileResult = null;
        await this.service.render();
    }

    public applyProfile(data: any) {
        this.profileSettings = {
            subject_source: data.subject_source || 'sub',
            id_token_signing_alg: data.id_token_signing_alg || 'RS256',
            response_variant: data.response_variant || 'standard',
            time_offset_seconds: Number(data.time_offset_seconds || 0),
            token_ttl_seconds: Number(data.token_ttl_seconds || 600),
            session_ttl_seconds: Number(data.session_ttl_seconds || 28800),
            acr: data.acr || '',
        };
        this.amrText = (data.amr || ['pwd']).join('\n');
        this.claimOverridesText = JSON.stringify(data.claim_overrides || {}, null, 2);
        this.idTokenClaimOverridesText = JSON.stringify(data.id_token_claim_overrides || {}, null, 2);
        this.userinfoClaimOverridesText = JSON.stringify(data.userinfo_claim_overrides || {}, null, 2);
        this.distributedClaimsText = JSON.stringify(data.distributed_claims || {}, null, 2);
        this.omitClaimsText = (data.omit_claims || []).join('\n');
        this.idTokenOnlyClaimsText = (data.id_token_only_claims || []).join('\n');
        this.userinfoOnlyClaimsText = (data.userinfo_only_claims || []).join('\n');
        this.profileResult = data;
    }

    public async loadProfile() {
        const name = String(this.profileName || '').trim();
        if (!name) {
            await this.service.modal.error('실행 설정 이름을 입력해주세요.');
            return;
        }
        this.profileBusy = true;
        await this.service.render();
        try {
            const res = await wiz.call('profile', { reviewops_profile: name });
            if (res.code !== 200) {
                await this.service.modal.error(res.data?.message || '실행 설정을 불러오지 못했습니다.');
            } else {
                this.applyProfile(res.data.data || res.data);
                await this.loadInfo();
            }
        } catch (e: any) {
            await this.service.modal.error(e.message || '실행 설정을 불러오지 못했습니다.');
        }
        this.profileBusy = false;
        await this.service.render();
    }

    public async copyText(text: string, label: string) {
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

    public downloadText(filename: string, content: string, type: string = 'application/json') {
        const blob = new Blob([content], { type: type });
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = filename;
        anchor.click();
        URL.revokeObjectURL(url);
    }

    public async saveProfile() {
        const name = String(this.profileName || '').trim();
        if (!name) {
            await this.service.modal.error('실행 설정 이름을 입력해주세요.');
            return;
        }
        this.profileBusy = true;
        await this.service.render();
        try {
            const parsed = {
                ...this.profileSettings,
                amr: this.parseLines(this.amrText),
                claim_overrides: JSON.parse(this.claimOverridesText || '{}'),
                id_token_claim_overrides: JSON.parse(this.idTokenClaimOverridesText || '{}'),
                userinfo_claim_overrides: JSON.parse(this.userinfoClaimOverridesText || '{}'),
                distributed_claims: JSON.parse(this.distributedClaimsText || '{}'),
                omit_claims: this.parseLines(this.omitClaimsText),
                id_token_only_claims: this.parseLines(this.idTokenOnlyClaimsText),
                userinfo_only_claims: this.parseLines(this.userinfoOnlyClaimsText),
            };
            const res = await this.service.request.post('/api/oidc/reviewops-profile-config', {
                reviewops_profile: name,
                settings: JSON.stringify(parsed),
            });
            if (res.code !== 200) {
                await this.service.modal.error(res.data?.error_description || res.data?.message || '실행 설정 저장에 실패했습니다.');
                this.profileBusy = false;
                await this.service.render();
                return;
            }
            this.applyProfile(res.data?.data || res.data);
            await this.loadInfo();
            await this.service.render();
        } catch (e: any) {
            await this.service.modal.error(e.message || '고급 Claim 입력값을 확인해주세요.');
        }
        this.profileBusy = false;
        await this.service.render();
    }

    public async deleteProfile() {
        const name = String(this.profileName || '').trim();
        if (!name || !this.hasSavedProfile()) {
            await this.service.modal.error('삭제할 실행 설정을 목록에서 선택해주세요.');
            return;
        }
        const confirmed = await this.service.modal.error(
            `'${name}' 실행 설정을 삭제할까요? 삭제한 설정은 복구할 수 없습니다.`,
            '취소',
            '삭제',
        );
        if (!confirmed) return;
        this.profileBusy = true;
        await this.service.render();
        try {
            const res = await this.service.request.post('/api/oidc/reviewops-profile-clear', { reviewops_profile: name });
            if (res.code !== 200) {
                await this.service.modal.error(res.data?.error_description || res.data?.message || '실행 설정을 삭제하지 못했습니다.');
            } else {
                this.profileName = '';
                this.profileBusy = false;
                await this.applyPreset('standard');
                await this.loadInfo();
                await this.service.modal.success('실행 설정을 삭제했습니다.');
                return;
            }
        } catch (e: any) {
            await this.service.modal.error(e.message || '실행 설정을 삭제하지 못했습니다.');
        }
        this.profileBusy = false;
        await this.service.render();
    }

}
