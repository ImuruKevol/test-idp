import { OnInit } from '@angular/core';
import { Service } from '@wiz/libs/portal/season/service';

export class Component implements OnInit {
    public mode: string = 'list';
    public spList: any[] = [];
    public loading: boolean = true;
    public registering: boolean = false;
    public xmlInput: string = '';
    public registerResult: any = null;
    public selectedSp: any = null;
    public detailTab: string = 'overview';

    constructor(public service: Service) { }

    public async ngOnInit() {
        await this.service.init();
        await this.loadList();
    }

    public async loadList() {
        this.loading = true;
        await this.service.render();
        try {
            const res = await wiz.call("list", {});
            if (res.code === 200) {
                this.spList = res.data.data || res.data || [];
            }
        } catch (e) {
            this.spList = [];
        }
        this.loading = false;
        await this.service.render();
    }

    public async showRegister() {
        this.mode = 'register';
        this.xmlInput = '';
        this.registerResult = null;
        await this.service.render();
    }

    public async showList() {
        this.mode = 'list';
        this.registerResult = null;
        this.selectedSp = null;
        await this.loadList();
    }

    public async showDetail(sp: any) {
        this.selectedSp = sp;
        this.detailTab = 'overview';
        this.mode = 'detail';
        await this.service.render();
    }

    public async setDetailTab(name: string) {
        this.detailTab = name;
        await this.service.render();
    }

    public detailTabClass(name: string) {
        return this.detailTab === name
            ? 'border-orange-500 text-orange-700'
            : 'border-transparent text-slate-500 hover:border-slate-300 hover:text-slate-800';
    }

    public async onFileUpload(event: any) {
        const file = event.target?.files?.[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = async (e: any) => {
            this.xmlInput = e.target.result;
            await this.service.render();
        };
        reader.readAsText(file);
    }

    public async registerSp() {
        if (!this.xmlInput.trim()) {
            await this.service.modal.error('XML 메타데이터를 입력하거나 파일을 업로드해 주세요.');
            return;
        }
        this.registering = true;
        await this.service.render();
        try {
            const res = await wiz.call("register", { xml: this.xmlInput });
            if (res.code === 200) {
                this.registerResult = res.data.data || res.data;
                this.mode = 'result';
            } else {
                const msg = res.data?.message || 'SP 등록에 실패했습니다.';
                await this.service.modal.error(msg);
            }
        } catch (e: any) {
            await this.service.modal.error(e.message || 'SP 등록 중 오류가 발생했습니다.');
        }
        this.registering = false;
        await this.service.render();
    }

    public async deleteSp(sp: any) {
        const confirmed = await this.service.modal.show({
            title: 'SP 삭제',
            message: `"${sp.entity_id}"를 삭제하시겠습니까?`,
            action: '삭제',
            cancel: '취소',
            status: 'error',
            actionBtn: 'error',
        });
        if (!confirmed) return;
        try {
            const res = await wiz.call("delete", { id: sp.id });
            if (res.code === 200) {
                if (this.selectedSp && this.selectedSp.id === sp.id) {
                    this.selectedSp = null;
                }
                if (this.registerResult && this.registerResult.id === sp.id) {
                    this.registerResult = null;
                }
                this.mode = 'list';
                await this.loadList();
                return;
            }
            if (res.code === 403) {
                await this.service.modal.error('삭제 권한이 없습니다. admin 로그인 또는 등록한 IP에서만 삭제할 수 있습니다.');
                return;
            }
            await this.service.modal.error(res.data?.message || 'SP 삭제에 실패했습니다.');
        } catch (e: any) {
            await this.service.modal.error(e.message || 'SP 삭제 중 오류가 발생했습니다.');
        }
    }

    public isAdmin(): boolean {
        return this.service.auth.check.role && this.service.auth.check.role('admin');
    }

    public isExpired(expires: string | null): boolean {
        if (!expires) return false;
        return new Date(expires).getTime() <= new Date().getTime();
    }

    public getBindingShort(binding: string) {
        if (binding.includes('POST')) return 'POST';
        if (binding.includes('Redirect')) return 'Redirect';
        return binding.split(':').pop() || binding;
    }

    public getTimeRemaining(expires: string | null): string {
        if (!expires) return '영구';
        const exp = new Date(expires);
        const now = new Date();
        const diff = exp.getTime() - now.getTime();
        if (diff <= 0) return '만료됨';
        const hours = Math.floor(diff / (1000 * 60 * 60));
        const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
        if (hours > 0) return `${hours}시간 ${minutes}분 남음`;
        return `${minutes}분 남음`;
    }

    public isExpiringSoon(expires: string | null): boolean {
        if (!expires) return false;
        const exp = new Date(expires);
        const now = new Date();
        const diff = exp.getTime() - now.getTime();
        return diff > 0 && diff < 2 * 60 * 60 * 1000;
    }

    public async extendSp(sp: any) {
        if (!this.isAdmin() || !sp.expires) return;

        try {
            const res = await wiz.call('extend_validity', { id: sp.id, ttl_hours: '24' });
            if (res.code === 200) {
                const item = res.data.data || res.data;
                this.selectedSp = this.selectedSp && this.selectedSp.id === item.id ? item : this.selectedSp;
                this.registerResult = this.registerResult && this.registerResult.id === item.id ? item : this.registerResult;
                await this.loadList();
                if (this.selectedSp && this.selectedSp.id === item.id) {
                    this.selectedSp = item;
                }
                return;
            }
            await this.service.modal.error(res.data?.message || '유효 시간 연장에 실패했습니다.');
        } catch (e: any) {
            await this.service.modal.error(e.message || '유효 시간 연장 중 오류가 발생했습니다.');
        }
    }

    public async setUnlimited(sp: any) {
        if (!this.isAdmin() || !sp.expires) return;

        const confirmed = await this.service.modal.show({
            title: '영구 보관 전환',
            message: `"${sp.entity_id}"를 무기한 보관으로 전환하시겠습니까?`,
            action: '영구 보관',
            cancel: '취소',
            status: 'warning',
            actionBtn: 'warning',
        });
        if (!confirmed) return;

        try {
            const res = await wiz.call('set_unlimited', { id: sp.id });
            if (res.code === 200) {
                const item = res.data.data || res.data;
                this.selectedSp = this.selectedSp && this.selectedSp.id === item.id ? item : this.selectedSp;
                this.registerResult = this.registerResult && this.registerResult.id === item.id ? item : this.registerResult;
                await this.loadList();
                if (this.selectedSp && this.selectedSp.id === item.id) {
                    this.selectedSp = item;
                }
                return;
            }
            await this.service.modal.error(res.data?.message || '영구 보관 전환에 실패했습니다.');
        } catch (e: any) {
            await this.service.modal.error(e.message || '영구 보관 전환 중 오류가 발생했습니다.');
        }
    }
}
