import { OnInit } from '@angular/core';
import { Service } from '@wiz/libs/portal/season/service';

export class Component implements OnInit {
    public loading: boolean = true;
    public idpInfo: any = null;
    public metadataXml: string = '';
    public copied: string = '';

    constructor(public service: Service) { }

    public async ngOnInit() {
        await this.service.init();
        await this.loadInfo();
    }

    public async loadInfo() {
        this.loading = true;
        await this.service.render();
        try {
            const res = await wiz.call("info", {});
            if (res.code === 200) {
                this.idpInfo = res.data.data || res.data;
            }
            const xmlRes = await wiz.call("metadata_xml", {});
            if (xmlRes.code === 200) {
                this.metadataXml = xmlRes.data.data || xmlRes.data?.xml || '';
            }
        } catch (e) {
            this.idpInfo = null;
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
}
