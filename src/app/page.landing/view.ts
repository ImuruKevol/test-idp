import { OnInit } from '@angular/core';
import { Service } from '@wiz/libs/portal/season/service';

export class Component implements OnInit {
    public summary: any[] = [];
    public expirySummary: any[] = [];
    public defaultAccounts: any[] = [];
    public loading: boolean = true;
    public changingPassword: boolean = false;
    public passwordModalOpen: boolean = false;
    public passwordForm: any = {
        current_password: '',
        new_password: '',
        confirm_password: '',
    };

    constructor(public service: Service) { }

    public async ngOnInit() {
        await this.service.init();
        await this.loadInfo();
    }

    public isAdmin(): boolean {
        return this.service.auth.check.role && this.service.auth.check.role('admin');
    }

    public async loadInfo() {
        this.loading = true;
        await this.service.render();

        try {
            const res = await wiz.call("load", {});
            if (res.code === 200) {
                const data = res.data.data || res.data;
                const counts = data.counts || {};
                this.summary = [
                    { label: 'Test Users', value: `${counts.user || 0}`, description: '관리용 admin과 생성된 임시 테스트 계정 포함' },
                    { label: 'Active Temporary', value: `${counts.temporary_active || 0}`, description: '24시간 유효한 임시 테스트 계정' },
                    { label: 'SAML SP', value: `${counts.saml_sp || 0}`, description: 'SAML SP 메타데이터 등록 수' },
                    { label: 'OIDC RP', value: `${counts.oidc_rp || 0}`, description: 'OIDC RP 등록 및 credential 발급 수' },
                    { label: 'Attribute Presets', value: `${counts.attribute_preset || 0}`, description: 'SAML Attribute 및 OIDC Claims 프리셋' },
                    { label: 'Debug Payloads', value: `${counts.debug_payload || 0}`, description: 'Raw XML/JWT 디버그 저장소' },
                    { label: 'Audit Logs', value: `${counts.audit || 0}`, description: '인증·등록·삭제 감사 로그' },
                ];
                this.defaultAccounts = data.default_accounts || [];
                this.expirySummary = [
                    { label: 'Expired Temporary Accounts', value: `${counts.temporary_expired || 0}`, description: '아래 Test Users 카드에서 연장 또는 영구 전환' },
                    { label: 'Expired SAML SP', value: `${counts.saml_expired || 0}`, description: 'SAML 화면 상세에서 +24h 또는 영구 보관' },
                    { label: 'Expired OIDC RP', value: `${counts.oidc_expired || 0}`, description: 'OIDC 화면 상세에서 +24h 또는 영구 보관' },
                ];
            }
        } catch (e) {
            this.summary = [];
            this.expirySummary = [];
            this.defaultAccounts = [];
        }

        this.loading = false;
        await this.service.render();
    }

    public resetPasswordForm() {
        this.passwordForm = {
            current_password: '',
            new_password: '',
            confirm_password: '',
        };
    }

    public async openPasswordModal() {
        this.resetPasswordForm();
        this.passwordModalOpen = true;
        await this.service.render();
    }

    public async closePasswordModal() {
        if (this.changingPassword) {
            return;
        }
        this.passwordModalOpen = false;
        this.resetPasswordForm();
        await this.service.render();
    }

    public async changePassword() {
        if (!this.passwordForm.current_password.trim()) {
            await this.service.modal.error('현재 비밀번호를 입력해주세요.');
            return;
        }
        if (!this.passwordForm.new_password.trim()) {
            await this.service.modal.error('새 비밀번호를 입력해주세요.');
            return;
        }
        if (this.passwordForm.new_password.length < 8) {
            await this.service.modal.error('새 비밀번호는 8자 이상이어야 합니다.');
            return;
        }
        if (this.passwordForm.new_password !== this.passwordForm.confirm_password) {
            await this.service.modal.error('새 비밀번호 확인이 일치하지 않습니다.');
            return;
        }

        this.changingPassword = true;
        await this.service.render();

        try {
            const res = await wiz.call('change_password', this.passwordForm);
            if (res.code === 200) {
                this.passwordModalOpen = false;
                this.resetPasswordForm();
                await this.service.modal.success('관리자 비밀번호를 변경했습니다. 다음 로그인부터 새 비밀번호를 사용하세요.');
            } else {
                await this.service.modal.error(res.data?.message || '비밀번호 변경에 실패했습니다.');
            }
        } catch (e: any) {
            await this.service.modal.error(e.message || '비밀번호 변경 중 오류가 발생했습니다.');
        }

        this.changingPassword = false;
        await this.service.render();
    }
}
