import { OnInit, Input, Output, EventEmitter } from '@angular/core';
import { Service } from '@wiz/libs/portal/season/service';

export class Component implements OnInit {
    @Input() mode: string = 'create';
    @Input() item: any = null;
    @Output() onSave = new EventEmitter<any>();
    @Output() onCancel = new EventEmitter<void>();

    public form: any = {
        username: '',
        password: '',
        display_name: '',
        email: '',
        profile: '{}',
        saml_attributes: '{}',
        oidc_claims: '{}'
    };

    public saving: boolean = false;
    public samlAttributeCatalog: any[] = [];

    constructor(public service: Service) { }

    public async ngOnInit() {
        await this.service.init();
        if (this.item && this.mode === 'edit') {
            this.form.username = this.item.username || '';
            this.form.password = '';
            this.form.display_name = this.item.display_name || '';
            this.form.email = this.item.email || '';
            this.form.profile = JSON.stringify(this.item.profile || {}, null, 2);
            this.form.saml_attributes = JSON.stringify(this.item.saml_attributes || {}, null, 2);
            this.form.oidc_claims = JSON.stringify(this.item.oidc_claims || {}, null, 2);
        }
        await this.loadSamlAttributeCatalog();
        await this.service.render();
    }

    public async loadSamlAttributeCatalog() {
        try {
            const res = await this.service.request.post('/api/idpcore/saml-attribute-catalog', {});
            if (res.code === 200) {
                this.samlAttributeCatalog = res.data.data || [];
            }
        } catch (e) {
            this.samlAttributeCatalog = [];
        }
    }

    private parseObjectEditor(text: string): any {
        const source = String(text || '').trim();
        if (source === '') return {};
        try {
            const parsed = JSON.parse(source);
            if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
                return parsed;
            }
        } catch (e) { }
        return null;
    }

    public async insertSamlAttribute(attr: any) {
        const parsed = this.parseObjectEditor(this.form.saml_attributes);
        if (parsed === null) {
            await this.service.modal.error('SAML Attributes JSON 형식이 올바르지 않습니다. 먼저 JSON을 수정해 주세요.');
            return;
        }
        parsed[attr.urn] = attr.example;
        this.form.saml_attributes = JSON.stringify(parsed, null, 2);
        await this.service.render();
    }

    public stringifyValue(value: any): string {
        if (value === null || value === undefined) return '';
        if (typeof value === 'object') return JSON.stringify(value);
        return String(value);
    }

    public async save() {
        if (!this.form.username.trim()) {
            await this.service.modal.error('아이디를 입력해주세요.');
            return;
        }
        if (this.mode === 'create' && !this.form.password.trim()) {
            await this.service.modal.error('비밀번호를 입력해주세요.');
            return;
        }

        this.saving = true;
        await this.service.render();

        try {
            const data: any = {
                username: this.form.username.trim(),
                display_name: this.form.display_name.trim(),
                email: this.form.email.trim(),
                profile: this.form.profile,
                saml_attributes: this.form.saml_attributes,
                oidc_claims: this.form.oidc_claims
            };
            if (this.form.password.trim()) {
                data.password = this.form.password;
            }
            if (this.mode === 'edit' && this.item) {
                data.id = this.item.id;
            }

            let res;
            if (this.mode === 'create') {
                res = await this.service.request.post('/api/idpcore/user-create-temporary', data);
            } else {
                res = await this.service.request.post('/api/idpcore/user-update', data);
            }

            if (res.code === 200) {
                this.onSave.emit(res.data.data || res.data);
            } else {
                await this.service.modal.error(res.data?.message || '저장에 실패했습니다.');
            }
        } catch (e: any) {
            await this.service.modal.error(e.message || '오류가 발생했습니다.');
        }

        this.saving = false;
        await this.service.render();
    }

    public async cancel() {
        this.onCancel.emit();
    }
}
