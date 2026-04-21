import { OnInit } from '@angular/core';
import { Service } from '@wiz/libs/portal/season/service';

export class Component implements OnInit {
    constructor(public service: Service) { }

    public async ngOnInit() {
        await this.service.init();
    }

    public isActive(prefix: string) {
        if (prefix === '/') return location.pathname === '/';
        return location.pathname.indexOf(prefix) === 0;
    }

    public navClass(prefix: string) {
        if (this.isActive(prefix)) {
            return 'inline-flex items-center rounded-full bg-orange-500 px-3 py-1.5 text-xs font-semibold text-white shadow-sm';
        }
        return 'inline-flex items-center rounded-full bg-white px-3 py-1.5 text-xs font-semibold text-zinc-600 ring-1 ring-inset ring-zinc-200 transition hover:bg-zinc-50';
    }
}