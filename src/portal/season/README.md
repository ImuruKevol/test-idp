# Season Package

WIZ 프레임워크의 공통 기반 패키지. 인증, ORM, 세션, UI 컴포넌트, 프론트엔드 Service 등을 제공한다.

---

## Installation

### Python Dependencies

```sh
apt install pkg-config libxml2-dev libxmlsec1-dev libxmlsec1-openssl
pip install peewee pymysql bcrypt python3-saml
```

### NPM Dependencies

- `tailwindcss`, `@tailwindcss/aspect-ratio`, `@tailwindcss/container-queries`, `@tailwindcss/forms`, `@tailwindcss/typography`
- `urlpattern-polyfill`, `moment`, `sortablejs`

---

## Frontend: Service API

`Service`는 모든 App의 `view.ts`에서 필수 주입하는 Angular 싱글톤 서비스이다.

```typescript
import { Service } from '@wiz/libs/portal/season/service';

export class Component implements OnInit {
    constructor(public service: Service) { }
    public async ngOnInit() {
        await this.service.init();
        // ...
    }
}
```

### Service 프로퍼티 요약

| 프로퍼티 | 타입 | 설명 |
|----------|------|------|
| `service.auth` | `Auth` | 인증 상태, 권한 검사 |
| `service.modal` | `Modal` | 확인/경고/에러 모달 다이얼로그 |
| `service.status` | `Status` | boolean 상태 토글 (로딩 등) |
| `service.event` | `Event` | 이벤트 바인딩/호출 |
| `service.lang` | `Lang` | 다국어 (i18n) |
| `service.crypto` | `Crypto` | SHA256 해시 |
| `service.file` | `File` | 파일 선택, 업로드, 리사이즈, 다운로드 |
| `service.request` | `Request` | HTTP POST 요청 |
| `service.formatter` | `Formatter` | 날짜/통화 포매팅 |

### Service 메서드

```typescript
await service.init(app?)       // 초기화 (layout에서 app=this 전달, 이후 page에서는 인자 없이 호출)
await service.render(time?)    // 화면 갱신 (detectChanges). time(ms) 지정 시 딜레이 후 갱신
await service.sleep(time)      // ms 대기
service.href(url)              // Angular Router 네비게이션
service.random(length?)        // 랜덤 영숫자 문자열 생성 (기본 16자)
```

---

### service.modal (Modal)

확인/경고/에러 모달 다이얼로그. Layout의 `view.pug`에 `wiz-portal-season-modal` 컴포넌트가 배치되어야 동작한다.

#### `show(opts): Promise<any>`

모달을 표시하고 사용자 응답을 기다린다. 액션 버튼 클릭 시 `true`, 취소 시 `false`를 반환한다.

```typescript
let res = await this.service.modal.show({
    title: '삭제 확인',
    message: '정말 삭제하시겠습니까?',
    action: '삭제',         // 액션 버튼 텍스트
    cancel: '취소',         // 취소 버튼 텍스트 (false로 설정 시 숨김)
    status: 'error',       // 'error' | 'warning' | 'success' (아이콘/색상)
    actionBtn: 'error'     // 'error' | 'warning' | 'success' (버튼 색상)
});
if (!res) return; // 취소됨
```

**opts 기본값:**

| 키 | 기본값 | 설명 |
|----|--------|------|
| `title` | `'Are you sure?'` | 모달 제목 |
| `message` | `"Do you really want to remove app?..."` | 본문 메시지 |
| `action` | `'Delete'` | 액션 버튼 텍스트 |
| `actionBtn` | `'error'` | 액션 버튼 색상 (`error`=빨강, `warning`=노랑, `success`=인디고) |
| `cancel` | `true` | 취소 버튼 (문자열=텍스트, `false`=숨김) |
| `status` | `'error'` | 아이콘 색상 (`error`=빨강, `warning`=노랑, `success`=인디고) |

#### 편의 메서드

```typescript
// 에러 모달 (빨간 아이콘/버튼)
await this.service.modal.error("오류가 발생했습니다.");
await this.service.modal.error("계속하시겠습니까?", "취소", "확인"); // cancel, action 텍스트

// 성공 모달 (인디고 아이콘/버튼)
await this.service.modal.success("저장되었습니다.");

// 경고 모달 (노란 아이콘/버튼)
await this.service.modal.warning("주의: 되돌릴 수 없습니다.", "취소", "계속");
```

#### `localize(opts): Modal`

기본값을 커스터마이징한 새 Modal 인스턴스를 생성한다.

```typescript
const deleteModal = this.service.modal.localize({
    title: '삭제',
    status: 'error',
    actionBtn: 'error',
    action: '삭제',
    cancel: '취소'
});
// 이후 deleteModal.show({ message: '...' }) 로 사용
```

---

### service.auth (Auth)

인증 상태 관리 및 권한 검사. `/auth/check` API를 호출하여 세션을 확인한다.

#### 프로퍼티

```typescript
service.auth.status     // 인증 상태 (boolean | null)
service.auth.session    // 세션 데이터 객체 { id, email, role, name, ... }
service.auth.loading    // 로딩 완료 여부 (null=미시작, true=완료)
service.auth.verified   // 인증 검증 상태
```

#### `check` (Proxy)

세션 필드를 기준으로 권한을 확인한다.

```typescript
service.auth.check()              // 인증 여부 (boolean)
service.auth.check.role('admin')  // role이 'admin'인지
service.auth.check.role(['admin', 'superadmin'])  // role이 배열 내 값인지
service.auth.check.id()           // id 필드 존재 여부
```

#### `allow` (Proxy)

권한 검사 + 실패 시 리다이렉트.

```typescript
// 인증 안 됐으면 '/' 로 이동
await this.service.auth.allow("/");

// admin이 아니면 '/' 로 이동
await this.service.auth.allow.role("admin", "/");

// 값만 확인 (리다이렉트 없음)
if (this.service.auth.allow.role("admin")) { ... }
```

#### `hash(password): string`

비밀번호를 SHA256으로 해시한다.

```typescript
const hashed = this.service.auth.hash("mypassword");
```

---

### service.status (Status)

UI 상태 (boolean) 토글 관리. 동적으로 프로퍼티를 생성하여 로딩, 편집 모드 등을 제어한다.

```typescript
// 상태 표시
await this.service.status.show("loading");     // service.status["loading"] = true
await this.service.status.hide("loading");     // service.status["loading"] = false
await this.service.status.toggle("editing");   // 토글
await this.service.status.toggle("editing", true);  // 명시적 설정
```

```pug
//- view.pug에서 사용
div(*ngIf="service.status.loading") Loading...
button((click)="service.status.toggle('editing')") Edit
```

---

### service.event (Event)

컴포넌트 간 이벤트 통신.

```typescript
// 이벤트 등록 (보통 ngOnInit에서)
this.service.event.bind("refresh", async () => {
    await this.load();
});

// 이벤트 발생 (다른 컴포넌트에서)
await this.service.event.call("refresh");

// 이벤트 해제
this.service.event.unbind("refresh", fn);

// 이벤트 전체 해제
this.service.event.clear("refresh");
```

---

### service.lang (Lang)

다국어 지원 (TranslateModule 사용 시에만 활성화).

```typescript
// 언어 설정
await this.service.lang.set("ko");   // 'ko' | 'en'

// 현재 언어 확인
this.service.lang.get();             // 'ko'
this.service.lang.is("en");          // false

// 번역 키 조회
const text = await this.service.lang.translate("common.save");
```

---

### service.file (File)

파일 선택, 읽기, 업로드, 다운로드 유틸리티.

#### `select(opts?): Promise<FileList>`

파일 선택 다이얼로그를 열고 선택된 파일을 반환한다.

```typescript
// 파일 선택
const files = await this.service.file.select();
const images = await this.service.file.select({ accept: 'image/*', multiple: false });

// 폴더 선택
const folder = await this.service.file.select({ type: 'folder' });
```

#### `read(opts?): Promise<any>`

파일 선택 후 내용을 읽어 반환한다.

```typescript
// 텍스트 파일 읽기
const text = await this.service.file.read({ type: 'text' });

// JSON 파일 읽기
const json = await this.service.file.read({ type: 'json' });

// 이미지 파일 읽기 (리사이즈 + base64)
const image = await this.service.file.read({
    type: 'image',
    accept: 'image/*',
    width: 512,      // 최대 너비
    quality: 0.8     // 압축 품질
});
```

#### `upload(url, formData, callback?): Promise<any>`

파일을 PUT/POST 업로드한다. 진행률 콜백을 지원한다.

```typescript
const fd = new FormData();
fd.append('file', file);
const res = await this.service.file.upload('/api/upload', fd, async (percent, total, position) => {
    console.log(`${percent}%`);
});
```

#### `resize(file, width?, quality?): Promise<string>`

이미지를 리사이즈하여 base64 데이터 URL로 반환한다.

```typescript
const base64 = await this.service.file.resize(file, 256, 0.8);
```

#### `download(data, filename?): void`

JSON 객체를 파일로 다운로드한다.

```typescript
this.service.file.download({ key: "value" }, "export.json");
```

#### `drop($event): Promise<File[]>`

드래그 앤 드롭 이벤트에서 파일 목록을 추출한다 (폴더 재귀 탐색 포함).

```typescript
// view.pug: div((drop)="onDrop($event)", (dragover)="$event.preventDefault()")
public async onDrop(event) {
    const files = await this.service.file.drop(event);
}
```

---

### service.request (Request)

HTTP POST 요청 유틸리티.

```typescript
const { code, data } = await this.service.request.post('/auth/check', { key: 'value' });
```

> **참고**: App 내 `api.py` 함수 호출은 `wiz.call("함수명", data)` 를 사용한다. `service.request`는 직접 URL 호출이 필요한 경우에만 사용한다.

---

### service.crypto (Crypto)

해시 유틸리티.

```typescript
const hash = this.service.crypto.SHA256("text");  // SHA256 해시 문자열
```

---

### service.formatter (Formatter)

날짜/통화 포매팅 유틸리티.

```typescript
// 날짜 포매팅 (moment.js 기반)
this.service.formatter.date(date)            // "2026-02-20"
this.service.formatter.date(null, "N/A")     // "N/A" (값 없을 때 대체 텍스트)

// 통화 포매팅 (한국 원화)
this.service.formatter.currency(1234567)              // "1,234,567원"
this.service.formatter.currency(1234567, false)        // "123만 4567원" (한글 단위)
```

---

## Backend: Model API

### ORM (`portal/season/orm`)

Peewee ORM 래퍼. DB 테이블 정의 및 CRUD 헬퍼를 제공한다.

```python
orm = wiz.model("portal/season/orm")

# DB 테이블 base 클래스 생성
base = orm.base("namespace")  # config/database.py의 namespace

# CRUD 헬퍼
db = orm.use("table_name", module="package_name")
db.get(id=id)                    # 단건 조회
db.rows(page=1, dump=20, **where)  # 목록 (페이징, 정렬, LIKE)
db.count(**where)                # 카운트
db.insert(data)                  # 삽입 (자동 ID)
db.update(data, id=id)           # 수정
db.delete(id=id)                 # 삭제
db.upsert(data, keys="id")      # Upsert
```

### Session (`portal/season/session`)

Flask 세션 래퍼.

```python
session = wiz.model("portal/season/session").use()
session.get("key")           # 값 조회
session.set(key="value")     # 값 설정
session.has("key")           # 존재 확인
session.delete("key")        # 삭제
session.clear()              # 전체 삭제
session.age_seconds("auth_time")
session.is_expired("auth_time", ttl_seconds=28800)
```

### Config (`portal/season/config`)

`config/season.py` 설정값 접근.

```python
config = wiz.model("portal/season/config")
config.auth_saml_use        # SAML 사용 여부
config.default_url           # 기본 URL
config.session_create(wiz, key)  # 세션 생성 함수 호출
```

---

## App Components

| 컴포넌트 | 태그 | 설명 |
|----------|------|------|
| Modal | `wiz-portal-season-modal` | 확인/경고 다이얼로그 (`service.modal`과 연동) |
| Pagination | `wiz-portal-season-pagination` | 페이지네이션 |
| Loading (Season) | `wiz-portal-season-loading-season` | 로딩 오버레이 |
| Loading (Default) | `wiz-portal-season-loading-default` | 기본 로딩 |
| Dropdown | `wiz-portal-season-form-dropdown` | 드롭다운 폼 |
| Tree | `wiz-portal-season-tree` | 트리 뷰어 |

### Modal 컴포넌트 배치 (필수)

Layout의 `view.pug`에 modal 컴포넌트를 배치해야 `service.modal`이 동작한다.

```pug
//- layout.sidebar/view.pug
router-outlet
wiz-portal-season-modal
```

### Pagination 사용

```pug
wiz-portal-season-pagination(
    [current]="pagination.current",
    [start]="pagination.start",
    [end]="pagination.end",
    (pageMove)="load($event)")
```

---

## Release History

### 1.2.4
- 언어 패칭 기능 추가 (service.lang)
- event trigger 기능 추가 (service.event)

### 1.2.3
- auth api 업데이트

### 1.2.2
- pagenation 페이지 크기 설정 기능 추가
- service.init 관련 오류 수정 (auth.init 관련)

### 1.2.1
- app 이름 영문으로 변경
- Statusbar 기능 추가
- Tab 기능 추가

### 1.2.0
- Tree Viewer 추가
- 드롭다운 메뉴 추가
