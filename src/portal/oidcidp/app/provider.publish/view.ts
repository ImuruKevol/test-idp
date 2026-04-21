import { OnInit } from '@angular/core';
import { Service } from '@wiz/libs/portal/season/service';

export class Component implements OnInit {
    public loading: boolean = true;
    public provider: any = null;
    public discovery: any = {};
    public jwks: any = {};
    public clients: any[] = [];
    public clientCount: number = 0;
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
            const res = await wiz.call('info', {});
            if (res.code === 200) {
                const data = res.data.data || res.data;
                this.provider = data.provider || null;
                this.discovery = data.discovery || {};
                this.jwks = data.jwks || {};
                this.clients = data.clients || [];
                this.clientCount = data.client_count || 0;
            }
        } catch (e) {
            this.provider = null;
            this.discovery = {};
            this.jwks = {};
            this.clients = [];
            this.clientCount = 0;
        }

        this.loading = false;
        await this.service.render();
    }

    public stringify(value: any) {
        return JSON.stringify(value || {}, null, 2);
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
}