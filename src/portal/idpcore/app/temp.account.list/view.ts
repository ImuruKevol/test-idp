import { OnInit } from '@angular/core';
import { Service } from '@wiz/libs/portal/season/service';

export class Component implements OnInit {
    public items: any[] = [];
    public loading: boolean = true;
    public showForm: boolean = false;
    public editItem: any = null;
    public formMode: string = 'create';
    public lastCreated: any = null;
    public creating: boolean = false;
    public selectedQuickPreset: string = 'general';
    public quickCreatePresets: any[] = [
        {
            id: 'general',
            label: '일반',
            description: '기본 로그인 검증용 계정을 생성합니다.',
            summary: 'uid, mail, displayName'
        },
        {
            id: 'research',
            label: '연구소',
            description: '연구원/랩 접근 검증용 eduPerson 속성을 포함합니다.',
            summary: 'eduPersonPrincipalName, eduPersonEntitlement'
        },
        {
            id: 'university',
            label: '학교',
            description: '학생/교직원 federation 검증용 속성을 포함합니다.',
            summary: 'eduPersonAffiliation, scoped affiliation'
        },
        {
            id: 'institution',
            label: '기관',
            description: '기관 직원/멤버십 검증용 권한 속성을 포함합니다.',
            summary: 'department, memberOf, entitlement'
        }
    ];

    constructor(public service: Service) { }

    public async ngOnInit() {
        await this.service.init();
        await this.load();
    }

    public async load() {
        this.loading = true;
        await this.service.render();

        try {
            const res = await this.service.request.post('/api/idpcore/users-temporary', { include_expired: 'true' });
            if (res.code === 200) {
                this.items = res.data.data || [];
            }
        } catch (e) {
            this.items = [];
        }

        this.loading = false;
        await this.service.render();
    }

    public isAdmin(): boolean {
        return this.service.auth.check.role && this.service.auth.check.role('admin');
    }

    private generateSuffix(): string {
        const letters = 'abcdefghijklmnopqrstuvwxyz';
        const digits = '0123456789';
        let s = '';
        for (let i = 0; i < 2; i++) s += letters.charAt(Math.floor(Math.random() * letters.length));
        for (let i = 0; i < 2; i++) s += digits.charAt(Math.floor(Math.random() * digits.length));
        return s;
    }

    public quickPresetById(presetId: string): any {
        return this.quickCreatePresets.find((item: any) => item.id === presetId) || this.quickCreatePresets[0];
    }

    public selectedQuickPresetLabel(): string {
        return this.quickPresetById(this.selectedQuickPreset).label;
    }

    public async selectQuickPreset(presetId: string) {
        if (this.creating) return;
        this.selectedQuickPreset = this.quickPresetById(presetId).id;
        await this.service.render();
    }

    private quickPresetDisplayName(presetId: string, suffix: string): string {
        const code = suffix.toUpperCase();
        if (presetId === 'research') return `Researcher ${code}`;
        if (presetId === 'university') return `Student ${code}`;
        if (presetId === 'institution') return `Member ${code}`;
        return `Tester ${code}`;
    }

    private quickPresetProfile(presetId: string): any {
        if (presetId === 'research') {
            return {
                department: 'research',
                groups: ['researchers', 'lab-users'],
                organization: 'Research Lab',
                affiliation: ['member', 'researcher'],
                scoped_affiliation: ['member@test-idp.local', 'researcher@test-idp.local'],
                entitlements: ['urn:test-idp:entitlement:research', 'urn:test-idp:entitlement:dataset-access']
            };
        }
        if (presetId === 'university') {
            return {
                department: 'academic',
                groups: ['students', 'course-demo'],
                organization: 'Example University',
                affiliation: ['student', 'member'],
                scoped_affiliation: ['student@test-idp.local', 'member@test-idp.local'],
                entitlements: ['urn:mace:dir:entitlement:common-lib-terms']
            };
        }
        if (presetId === 'institution') {
            return {
                department: 'platform',
                groups: ['staff', 'federation-users'],
                organization: 'Public Institution',
                affiliation: ['employee', 'member'],
                scoped_affiliation: ['employee@test-idp.local', 'member@test-idp.local'],
                entitlements: ['urn:test-idp:entitlement:agency-portal', 'urn:test-idp:entitlement:full-access']
            };
        }
        return {
            department: 'testing',
            groups: ['testers'],
            organization: 'Test IDP'
        };
    }

    private quickPresetSamlAttributes(presetId: string, context: any, profile: any): any {
        const attrs: any = {
            'urn:oid:0.9.2342.19200300.100.1.1': context.username,
            'urn:oid:0.9.2342.19200300.100.1.3': context.email,
            'urn:oid:2.16.840.1.113730.3.1.241': context.displayName
        };
        if (presetId === 'general') return attrs;

        const nameParts = String(context.displayName || '').split(' ');
        attrs['urn:oid:1.3.6.1.4.1.5923.1.1.1.6'] = context.email;
        attrs['urn:oid:1.3.6.1.4.1.5923.1.1.1.1'] = profile.affiliation;
        attrs['urn:oid:1.3.6.1.4.1.5923.1.1.1.9'] = profile.scoped_affiliation;
        attrs['urn:oid:1.3.6.1.4.1.5923.1.1.1.7'] = profile.entitlements;
        attrs['urn:oid:2.5.4.42'] = nameParts[0] || context.username;
        attrs['urn:oid:2.5.4.4'] = nameParts.slice(1).join(' ') || 'Tester';
        attrs['urn:oid:2.16.840.1.113730.3.1.2'] = profile.department;
        attrs['urn:oid:1.2.840.113556.1.2.102'] = profile.groups;
        return attrs;
    }

    private quickPresetOidcClaims(presetId: string, context: any, profile: any): any {
        const claims: any = {
            preferred_username: context.username,
            email: context.email,
            name: context.displayName
        };
        if (presetId === 'general') return claims;

        claims.organization = profile.organization;
        claims.department = profile.department;
        claims.groups = profile.groups;
        claims.eduPersonPrincipalName = context.email;
        claims.eduPersonAffiliation = profile.affiliation;
        claims.eduPersonScopedAffiliation = profile.scoped_affiliation;
        claims.eduPersonEntitlement = profile.entitlements;
        return claims;
    }

    public async quickCreate() {
        this.creating = true;
        await this.service.render();

        const preset = this.quickPresetById(this.selectedQuickPreset);
        const presetId = preset.id;
        const suffix = this.generateSuffix();
        const username = `tester_${suffix}`;
        const password = 'test1234';
        const email = `${username}@test-idp.local`;
        const displayName = this.quickPresetDisplayName(presetId, suffix);
        const profile = this.quickPresetProfile(presetId);
        const context = { username: username, email: email, displayName: displayName };

        const data: any = {
            username: username,
            password: password,
            display_name: displayName,
            email: email,
            profile: JSON.stringify(profile),
            saml_attributes: JSON.stringify(this.quickPresetSamlAttributes(presetId, context, profile)),
            oidc_claims: JSON.stringify(this.quickPresetOidcClaims(presetId, context, profile))
        };

        try {
            const res = await this.service.request.post('/api/idpcore/user-create-temporary', data);
            if (res.code === 200) {
                const created = res.data.data || res.data;
                this.lastCreated = {
                    username: username,
                    password: password,
                    display_name: created.display_name || data.display_name,
                    email: created.email || data.email,
                    expires: created.expires || '',
                    preset_label: preset.label
                };
                await this.load();
            } else {
                await this.service.modal.error(res.data?.message || '생성에 실패했습니다.');
            }
        } catch (e: any) {
            await this.service.modal.error(e.message || '오류가 발생했습니다.');
        }

        this.creating = false;
        await this.service.render();
    }

    public async dismissCreated() {
        this.lastCreated = null;
        await this.service.render();
    }

    public async copyText(text: string) {
        try {
            await navigator.clipboard.writeText(text);
        } catch (e) {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.left = '-9999px';
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
        }
    }

    public isExpired(item: any): boolean {
        if (!item.is_temporary || !item.expires) return false;
        return new Date() > new Date(item.expires);
    }

    public remainingTime(item: any): string {
        if (!item.expires) return item.is_temporary ? '영구' : '-';
        const now = new Date().getTime();
        const exp = new Date(item.expires).getTime();
        const diff = exp - now;
        if (diff <= 0) return '만료됨';
        const hours = Math.floor(diff / (1000 * 60 * 60));
        const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
        return `${hours}시간 ${minutes}분`;
    }

    public async openCreate() {
        this.formMode = 'create';
        this.editItem = null;
        this.showForm = true;
        await this.service.render();
    }

    public async openEdit(item: any) {
        this.formMode = 'edit';
        this.editItem = item;
        this.showForm = true;
        await this.service.render();
    }

    public async onFormSave(data: any) {
        this.showForm = false;
        this.editItem = null;
        await this.load();
    }

    public async onFormCancel() {
        this.showForm = false;
        this.editItem = null;
        await this.service.render();
    }

    public async deleteItem(item: any) {
        const res = await this.service.modal.show({
            title: '임시 계정 삭제',
            message: `'${item.username}' 계정을 삭제하시겠습니까?`,
            action: '삭제',
            cancel: '취소',
            status: 'error',
            actionBtn: 'error'
        });
        if (!res) return;

        try {
            const result = await this.service.request.post('/api/idpcore/user-delete', { id: item.id });
            if (result.code === 200) {
                await this.load();
            } else if (result.code === 403) {
                await this.service.modal.error('삭제 권한이 없습니다. admin 로그인 또는 등록한 IP에서만 삭제할 수 있습니다.');
            } else {
                await this.service.modal.error(result.data?.message || '삭제에 실패했습니다.');
            }
        } catch (e: any) {
            await this.service.modal.error(e.message || '오류가 발생했습니다.');
        }
    }

    public async cleanupExpired() {
        const res = await this.service.modal.show({
            title: '만료 계정 정리',
            message: '만료된 임시 계정을 모두 삭제하시겠습니까?',
            action: '정리',
            cancel: '취소',
            status: 'warning',
            actionBtn: 'warning'
        });
        if (!res) return;

        try {
            const result = await this.service.request.post('/api/idpcore/cleanup-expired', {});
            if (result.code === 200) {
                const deleted = result.data.data || [];
                if (deleted.length > 0) {
                    await this.service.modal.success(`${deleted.length}개의 만료 계정이 삭제되었습니다.`);
                } else {
                    await this.service.modal.success('삭제할 만료 계정이 없습니다.');
                }
                await this.load();
            }
        } catch (e: any) {
            await this.service.modal.error(e.message || '오류가 발생했습니다.');
        }
    }

    public async extendValidity(item: any) {
        if (!this.isAdmin()) return;

        try {
            const result = await this.service.request.post('/api/idpcore/user-extend-validity', { id: item.id, ttl_hours: '24' });
            if (result.code === 200) {
                await this.load();
                return;
            }
            await this.service.modal.error(result.data?.message || '유효 시간 연장에 실패했습니다.');
        } catch (e: any) {
            await this.service.modal.error(e.message || '오류가 발생했습니다.');
        }
    }

    public async setUnlimited(item: any) {
        if (!this.isAdmin()) return;

        const confirmed = await this.service.modal.show({
            title: '무기한 전환',
            message: `'${item.username}' 계정을 만료 없이 유지하시겠습니까?`,
            action: '무기한 유지',
            cancel: '취소',
            status: 'warning',
            actionBtn: 'warning'
        });
        if (!confirmed) return;

        try {
            const result = await this.service.request.post('/api/idpcore/user-set-unlimited', { id: item.id });
            if (result.code === 200) {
                await this.load();
                return;
            }
            await this.service.modal.error(result.data?.message || '무기한 전환에 실패했습니다.');
        } catch (e: any) {
            await this.service.modal.error(e.message || '오류가 발생했습니다.');
        }
    }
}
