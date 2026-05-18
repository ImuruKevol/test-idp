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
            return 'inline-flex h-8 items-center rounded-md bg-zinc-950 px-3 text-xs font-semibold text-white';
        }
        return 'inline-flex h-8 items-center rounded-md px-3 text-xs font-semibold text-zinc-600 transition hover:bg-zinc-100 hover:text-zinc-950';
    }
}
