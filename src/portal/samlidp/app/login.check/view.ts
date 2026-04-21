import { OnInit } from '@angular/core';
import { Service } from '@wiz/libs/portal/season/service';

export class Component implements OnInit {
    public mode: string = 'input';
    public loading: boolean = false;
    public spList: any[] = [];
    public users: any[] = [];
    public presets: any[] = [];
    public transactions: any[] = [];
    public samlAttributeCatalog: any[] = [];

    // Parse form
    public samlRequestInput: string = '';
    public relayStateInput: string = '';
    public bindingInput: string = 'POST';
    public parsedRequest: any = null;

    // Response form
    public selectedUserId: string = '';
    public selectedPresetId: string = '';
    public nameidFormat: string = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
    public nameidValue: string = '';
    public signResponse: boolean = true;
    public signAssertion: boolean = true;
    public sessionIndex: string = '';
    public attributeOverrides: string = '';

    // IdP Initiated
    public selectedSpId: string = '';
    public selectedSpAcs: string = '';

    // Result
    public responseResult: any = null;

    constructor(public service: Service) { }

    public async ngOnInit() {
        await this.service.init();
        await this.loadData();
    }

    public async loadData() {
        this.loading = true;
        await this.service.render();
        try {
            const [spRes, userRes, presetRes, txRes, catalogRes] = await Promise.all([
                wiz.call("sp_list", {}),
                wiz.call("user_list", {}),
                wiz.call("preset_list", {}),
                wiz.call("tx_list", {}),
                this.service.request.post('/api/idpcore/saml-attribute-catalog', {}),
            ]);
            this.spList = spRes.code === 200 ? (spRes.data.data || spRes.data || []) : [];
            this.users = userRes.code === 200 ? (userRes.data.data || userRes.data || []) : [];
            this.presets = presetRes.code === 200 ? (presetRes.data.data || presetRes.data || []) : [];
            this.transactions = txRes.code === 200 ? (txRes.data.data || txRes.data || []) : [];
            this.samlAttributeCatalog = catalogRes.code === 200 ? (catalogRes.data.data || []) : [];
        } catch (e) { }
        this.loading = false;
        await this.service.render();
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

    public async insertAttributeOverride(attr: any) {
        const parsed = this.parseObjectEditor(this.attributeOverrides);
        if (parsed === null) {
            await this.service.modal.error('Attribute Override JSON 형식이 올바르지 않습니다. 먼저 JSON을 수정해 주세요.');
            return;
        }
        parsed[attr.urn] = attr.example;
        this.attributeOverrides = JSON.stringify(parsed, null, 2);
        await this.service.render();
    }

    public async parseRequest() {
        if (!this.samlRequestInput.trim()) {
            await this.service.modal.error('SAMLRequest를 입력해 주세요.');
            return;
        }
        this.loading = true;
        await this.service.render();
        try {
            const res = await wiz.call("parse_request", {
                SAMLRequest: this.samlRequestInput,
                RelayState: this.relayStateInput,
                binding: this.bindingInput,
            });
            if (res.code === 200) {
                this.parsedRequest = res.data.data || res.data;
                this.nameidFormat = this.parsedRequest.nameid_format || this.nameidFormat;
                this.mode = 'respond';
            } else {
                await this.service.modal.error(res.data?.message || 'AuthnRequest 파싱에 실패했습니다.');
            }
        } catch (e: any) {
            await this.service.modal.error(e.message || '파싱 오류');
        }
        this.loading = false;
        await this.service.render();
    }

    public async buildResponse() {
        if (!this.selectedUserId) {
            await this.service.modal.error('테스트 사용자를 선택해 주세요.');
            return;
        }
        this.loading = true;
        await this.service.render();

        const params: any = {
            user_id: this.selectedUserId,
            sp_entity_id: this.parsedRequest?.issuer || '',
            acs_url: this.parsedRequest?.acs_url || '',
            request_id: this.parsedRequest?.request_id || '',
            relay_state: this.parsedRequest?.relay_state || '',
            transaction_id: this.parsedRequest?.transaction_id || '',
            nameid_format: this.nameidFormat,
            nameid_value: this.nameidValue,
            preset_id: this.selectedPresetId,
            sign_response: this.signResponse ? 'true' : 'false',
            sign_assertion: this.signAssertion ? 'true' : 'false',
            session_index: this.sessionIndex,
            attribute_overrides: this.attributeOverrides,
        };

        try {
            const res = await wiz.call("build_response", params);
            if (res.code === 200) {
                this.responseResult = res.data.data || res.data;
                this.mode = 'result';
            } else {
                await this.service.modal.error(res.data?.message || 'Response 생성에 실패했습니다.');
            }
        } catch (e: any) {
            await this.service.modal.error(e.message || 'Response 생성 오류');
        }
        this.loading = false;
        await this.service.render();
    }

    public async startIdpInitiated() {
        if (!this.selectedSpId || !this.selectedUserId) {
            await this.service.modal.error('SP와 테스트 사용자를 선택해 주세요.');
            return;
        }
        const sp = this.spList.find((s: any) => s.id === this.selectedSpId);
        if (!sp) return;
        const acs = sp.acs_url?.[0]?.location || '';
        if (!acs) {
            await this.service.modal.error('선택한 SP에 ACS URL이 없습니다.');
            return;
        }

        this.parsedRequest = {
            transaction_id: '',
            request_id: '',
            issuer: sp.entity_id,
            acs_url: acs,
            relay_state: '',
            nameid_format: this.nameidFormat,
        };
        this.mode = 'respond';
        await this.service.render();
    }

    public async showInput() {
        this.mode = 'input';
        this.parsedRequest = null;
        this.responseResult = null;
        await this.loadData();
    }

    public async copyText(text: string) {
        try {
            await navigator.clipboard.writeText(text);
        } catch (e) { }
    }

    public onSpChange() {
        const sp = this.spList.find((s: any) => s.id === this.selectedSpId);
        if (sp) {
            this.selectedSpAcs = sp.acs_url?.[0]?.location || '';
        }
        this.service.render();
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

    public stringifyValue(value: any): string {
        if (value === null || value === undefined) return '';
        if (typeof value === 'object') return JSON.stringify(value);
        return String(value);
    }
}
