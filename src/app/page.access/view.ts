import { OnInit } from '@angular/core';
import { Service } from '@wiz/libs/portal/season/service';

export class Component implements OnInit {
    constructor(public service: Service) { }

    public view: string = 'login';

    public data: any = {
        username: '',
        password: ''
    };
    public loggingIn: boolean = false;

    public async ngOnInit() {
        await this.service.init();
        let check = await this.service.auth.check();
        if (check) return location.href = "/";
    }

    public async alert(message: string, status: string = 'error') {
        return await this.service.modal.show({
            title: "",
            message: message,
            cancel: false,
            actionBtn: status,
            action: '확인',
            status: status
        });
    }

    public async login() {
        if (this.loggingIn) return;

        let user = JSON.parse(JSON.stringify(this.data));
        if (!user.username) {
            await this.alert("사용자명을 입력해주세요.");
            return;
        }
        if (!user.password) {
            await this.alert("비밀번호를 입력해주세요.");
            return;
        }

        this.loggingIn = true;
        await this.service.render();

        try {
            let { code, data } = await wiz.call("login", user);

            if (code == 200) {
                location.href = "/";
                await this.service.render();
            } else {
                await this.alert(data.message || "로그인에 실패했습니다.", 'error');
            }
        } catch (e: any) {
            await this.alert(e.message || "로그인 중 오류가 발생했습니다.", 'error');
        } finally {
            this.loggingIn = false;
            await this.service.render();
        }
    }
}
