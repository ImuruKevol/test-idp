import { OnInit } from '@angular/core';
import { Service } from '@wiz/libs/portal/season/service';

export class Component implements OnInit {
    public loading: boolean = true;
    public idpInfo: any = null;
    public metadataXml: string = '';
    public copied: string = '';
    public profileName: string = '';
    public profileOptions: any[] = [];
    public profilePreset: string = 'standard';
    public profileBusy: boolean = false;
    public profileResult: any = null;
    public signResponse: boolean = true;
    public signAssertion: boolean = true;
    public encryptAssertion: boolean = false;
    public contentEncryptionAlgorithm: string = 'aes256-gcm';
    public keyTransportAlgorithm: string = 'rsa-oaep-sha256';
    public responseVariant: string = 'standard';
    public timeOffsetSeconds: number = 0;
    public assertionTtlSeconds: number = 300;
    public omitAttributesText: string = '';
    public attributeValuesText: string = '{}';
    public profileMessage: string = '';
    public metadataVariant: string = 'standard';
    public federationOptions: any[] = [];
    public federationName: string = '';
    public federationIdpCount: number = 3;
    public federationPreset: string = 'standard';
    public federationIncludeBase: boolean = true;
    public federationBusy: boolean = false;
    public federationResult: any = null;

    constructor(public service: Service) { }

    public async ngOnInit() {
        await this.service.init();
        await this.loadInfo();
    }

    public async loadInfo() {
        this.loading = true;
        this.idpInfo = null;
        this.metadataXml = '';
        await this.service.render();
        const profile = String(this.profileName || '').trim();
        try {
            const res = await wiz.call("info", { reviewops_profile: profile });
            if (res.code === 200) {
                this.idpInfo = res.data.data || res.data;
                this.profileOptions = this.idpInfo.profiles || [];
                this.federationOptions = this.idpInfo.federations || [];
            }
        } catch (e) {
            this.idpInfo = null;
            this.profileOptions = [];
            this.federationOptions = [];
        }
        try {
            const xmlRes = await wiz.call("metadata_xml", {
                metadata_variant: this.metadataVariant,
                reviewops_profile: profile,
            });
            if (xmlRes.code === 200) {
                this.metadataXml = xmlRes.data.data || xmlRes.data?.xml || '';
            }
        } catch (e) {
            this.metadataXml = '';
        }
        this.loading = false;
        await this.service.render();
    }

    public async copyToClipboard(text: string, label: string) {
        try {
            await navigator.clipboard.writeText(text);
            this.copied = label;
            await this.service.render();
            setTimeout(async () => {
                this.copied = '';
                await this.service.render();
            }, 2000);
        } catch (e) { }
    }

    public downloadXml() {
        if (!this.metadataXml) return;
        const blob = new Blob([this.metadataXml], { type: 'application/xml' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'idp-metadata.xml';
        a.click();
        URL.revokeObjectURL(url);
    }

    public getNameIdShort(fmt: string) {
        const parts = fmt.split(':');
        return parts[parts.length - 1] || fmt;
    }

    public presetClass(name: string) {
        return this.profilePreset === name
            ? 'rounded-xl border border-orange-300 bg-orange-50 px-3 py-3 text-left text-orange-950 ring-1 ring-orange-200'
            : 'rounded-xl border border-slate-200 bg-white px-3 py-3 text-left text-slate-700 transition hover:border-orange-200 hover:bg-slate-50';
    }

    public async profileChanged() {
        this.profileResult = null;
        this.profileMessage = '';
        await this.service.render();
    }

    public profileOptionClass(name: string) {
        return this.profileName === name
            ? 'border-orange-300 bg-orange-50 text-orange-950 ring-1 ring-orange-200'
            : 'border-slate-200 bg-white text-slate-700 hover:border-orange-200 hover:bg-slate-50';
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
        this.signResponse = true;
        this.signAssertion = true;
        this.encryptAssertion = false;
        this.contentEncryptionAlgorithm = 'aes256-gcm';
        this.keyTransportAlgorithm = 'rsa-oaep-sha256';
        this.responseVariant = 'standard';
        this.timeOffsetSeconds = 0;
        this.assertionTtlSeconds = 300;
        this.omitAttributesText = '';
        this.attributeValuesText = '{}';
        if (name === 'encrypted') {
            this.encryptAssertion = true;
        } else if (name === 'attributes') {
            this.attributeValuesText = JSON.stringify({
                'urn:oid:1.3.6.1.4.1.5923.1.1.1.1': ['engineering', 'qa'],
            }, null, 2);
        } else if (name === 'error') {
            this.responseVariant = 'expired';
        }
        this.profileResult = null;
        this.profileMessage = '';
        await this.service.render();
    }

    public applyProfile(data: any) {
        this.signResponse = data.sign_response !== false;
        this.signAssertion = data.sign_assertion !== false;
        this.encryptAssertion = data.encrypt_assertion === true;
        this.contentEncryptionAlgorithm = data.content_encryption_algorithm || 'aes256-gcm';
        this.keyTransportAlgorithm = data.key_transport_algorithm || 'rsa-oaep-sha256';
        this.responseVariant = data.response_variant || 'standard';
        this.timeOffsetSeconds = Number(data.time_offset_seconds || 0);
        this.assertionTtlSeconds = Number(data.assertion_ttl_seconds || 300);
        this.omitAttributesText = (data.omit_attributes || []).join('\n');
        this.attributeValuesText = JSON.stringify(data.attribute_values || {}, null, 2);
        this.profileResult = data;
        this.profileMessage = data.configured ? '저장된 설정을 불러왔습니다.' : '이 이름에는 저장된 설정이 없습니다.';
    }

    public async loadProfile() {
        const profile = String(this.profileName || '').trim();
        if (!profile) {
            await this.service.modal.error('실행 설정 이름을 입력해주세요.');
            return;
        }
        this.profileBusy = true;
        await this.service.render();
        try {
            const res = await wiz.call('profile', { reviewops_profile: profile });
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

    public async saveProfile() {
        const profile = String(this.profileName || '').trim();
        if (!profile) {
            await this.service.modal.error('실행 설정 이름을 입력해주세요.');
            return;
        }
        this.profileBusy = true;
        await this.service.render();
        try {
            const values = JSON.parse(this.attributeValuesText || '{}');
            const omit = String(this.omitAttributesText || '').split('\n').map((item) => item.trim()).filter((item) => item);
            const res = await this.service.request.post('/api/saml/reviewops-profile-config', {
                reviewops_profile: profile,
                sign_response: this.signResponse ? 'true' : 'false',
                sign_assertion: this.signAssertion ? 'true' : 'false',
                encrypt_assertion: this.encryptAssertion ? 'true' : 'false',
                content_encryption_algorithm: this.contentEncryptionAlgorithm,
                key_transport_algorithm: this.keyTransportAlgorithm,
                response_variant: this.responseVariant,
                time_offset_seconds: String(this.timeOffsetSeconds),
                assertion_ttl_seconds: String(this.assertionTtlSeconds),
                omit_attributes: JSON.stringify(omit),
                attribute_values: JSON.stringify(values),
            });
            if (res.code !== 200) {
                await this.service.modal.error(res.data?.message || '실행 설정 저장에 실패했습니다.');
                this.profileBusy = false;
                await this.service.render();
                return;
            }
            this.applyProfile(res.data?.data || res.data);
            this.profileMessage = '설정을 저장했습니다.';
            await this.loadInfo();
            await this.service.render();
        } catch (e: any) {
            await this.service.modal.error(e.message || 'Attribute JSON을 확인해주세요.');
        }
        this.profileBusy = false;
        await this.service.render();
    }

    public async deleteProfile() {
        const profile = String(this.profileName || '').trim();
        if (!profile || !this.hasSavedProfile()) {
            await this.service.modal.error('삭제할 실행 설정을 목록에서 선택해주세요.');
            return;
        }
        const confirmed = await this.service.modal.error(
            `'${profile}' 실행 설정을 삭제할까요? 삭제한 설정은 복구할 수 없습니다.`,
            '취소',
            '삭제',
        );
        if (!confirmed) return;
        this.profileBusy = true;
        await this.service.render();
        try {
            const res = await this.service.request.post('/api/saml/reviewops-profile-clear', { reviewops_profile: profile });
            if (res.code !== 200) {
                await this.service.modal.error(res.data?.message || '실행 설정을 삭제하지 못했습니다.');
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

    public async reloadMetadataVariant() {
        const res = await wiz.call('metadata_xml', {
            metadata_variant: this.metadataVariant,
            reviewops_profile: String(this.profileName || '').trim(),
        });
        if (res.code === 200) {
            this.metadataXml = res.data.data || res.data?.xml || '';
            await this.service.render();
        }
    }

    public async createFederation() {
        const name = String(this.federationName || '').trim();
        const count = Number(this.federationIdpCount || 0);
        if (!/^[a-z0-9-]{1,57}$/.test(name)) {
            await this.service.modal.error('Federation 이름은 영문 소문자, 숫자, 하이픈만 사용해 1~57자로 입력해주세요.');
            return;
        }
        if (!Number.isInteger(count) || count < 1 || count > 20) {
            await this.service.modal.error('IdP 개수는 1~20 사이 정수여야 합니다.');
            return;
        }
        this.federationBusy = true;
        this.federationResult = null;
        await this.service.render();
        try {
            const res = await wiz.call('federation_create', {
                name,
                count: String(count),
                include_base: this.federationIncludeBase ? 'true' : 'false',
                preset: this.federationPreset,
            });
            if (res.code !== 200) {
                await this.service.modal.error(res.data?.message || 'Federation 구성에 실패했습니다.');
            } else {
                this.federationResult = res.data?.data || res.data;
                await this.loadInfo();
                await this.service.modal.success(`${count}개 IdP를 Federation으로 구성했습니다.`);
            }
        } catch (e: any) {
            await this.service.modal.error(e.message || 'Federation 구성에 실패했습니다.');
        }
        this.federationBusy = false;
        await this.service.render();
    }

    public async deleteFederation(item: any) {
        const name = String(item?.name || '').trim();
        if (!name) return;
        const confirmed = await this.service.modal.error(
            `'${name}' Federation 묶음만 삭제할까요? 생성된 IdP 실행 설정은 유지됩니다.`,
            '취소',
            '묶음 삭제',
        );
        if (!confirmed) return;
        this.federationBusy = true;
        await this.service.render();
        try {
            const res = await wiz.call('federation_delete', { name });
            if (res.code !== 200) {
                await this.service.modal.error(res.data?.message || 'Federation 삭제에 실패했습니다.');
            } else {
                if (this.federationResult?.name === name) this.federationResult = null;
                await this.loadInfo();
            }
        } catch (e: any) {
            await this.service.modal.error(e.message || 'Federation 삭제에 실패했습니다.');
        }
        this.federationBusy = false;
        await this.service.render();
    }
}
