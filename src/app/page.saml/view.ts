import { OnDestroy, OnInit } from '@angular/core';
import { NavigationEnd, Router } from '@angular/router';
import { Service } from '@wiz/libs/portal/season/service';

export class Component implements OnInit, OnDestroy {
    public tab: string = 'register';
    private routerSub: any = null;

    constructor(
        public service: Service,
        public router: Router,
    ) { }

    public async ngOnInit() {
        await this.service.init();
        await this.syncTab();

        this.routerSub = this.router.events.subscribe(async (event) => {
            if (event instanceof NavigationEnd) {
                await this.syncTab();
            }
        });
    }

    public ngOnDestroy() {
        if (this.routerSub) {
            this.routerSub.unsubscribe();
        }
    }

    public isTab(name: string) {
        return this.tab === name;
    }

    public tabClass(name: string) {
        if (this.isTab(name)) {
            return 'inline-flex items-center rounded-full bg-orange-500 px-3 py-1.5 text-xs font-semibold text-white';
        }
        return 'inline-flex items-center rounded-full bg-white px-3 py-1.5 text-xs font-semibold text-zinc-600 ring-1 ring-inset ring-zinc-200 transition hover:bg-zinc-50';
    }

    private async syncTab() {
        const nextTab = `${WizRoute.segment.tab || ''}`.trim() || 'register';
        if (!WizRoute.segment.tab) {
            this.service.href('/saml/register');
            return;
        }
        if (this.tab !== nextTab) {
            this.tab = nextTab;
            await this.service.render();
        }
    }
}
