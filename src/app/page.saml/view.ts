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
            return 'flex min-w-0 items-center gap-3 rounded-xl border border-orange-200 bg-orange-50 px-3 py-3 text-orange-950 shadow-sm';
        }
        return 'flex min-w-0 items-center gap-3 rounded-xl border border-transparent px-3 py-3 text-slate-600 transition hover:border-slate-200 hover:bg-white hover:text-slate-950';
    }

    public stepClass(name: string) {
        return this.isTab(name)
            ? 'flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-orange-500 text-xs font-bold text-white'
            : 'flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-slate-200 text-xs font-bold text-slate-600';
    }

    public tabTitle() {
        const labels: any = {
            register: 'SP 관리',
            publish: 'IdP 정보',
            logincheck: '로그인 확인',
            logoutcheck: '로그아웃 확인',
        };
        return labels[this.tab] || labels.register;
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
