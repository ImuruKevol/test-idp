# SAML SP 등록 화면의 삭제/확인 모달 동작 복구

- **ID**: 004
- **날짜**: 2026-04-21
- **유형**: 버그 수정

## 작업 요약

SAML SP 목록/상세 화면의 삭제 버튼과 만료 관리 확인 모달이 동작하지 않던 원인을 확인한 결과, `sp.register` 컴포넌트가 season 공통 서비스에 없는 `service.alert` API를 호출하고 있었다.

이를 `service.modal` 기반 호출로 교체하고, 삭제 성공 시 상세 화면에서도 목록 상태로 안전하게 복귀하도록 정리했다.

## 변경 파일 목록

- `src/portal/samlidp/app/sp.register/view.ts`
  - `service.alert` 호출을 `service.modal.error()` 및 `service.modal.show()`로 교체
  - 삭제 확인 모달 옵션을 season modal 규격(`status`, `actionBtn`)에 맞게 수정
  - 삭제 성공 시 `selectedSp`, `registerResult`, `mode` 상태를 정리하고 목록으로 복귀하도록 보강
  - 삭제/연장/영구 전환 실패 시 런타임 오류 없이 오류 모달이 표시되도록 정리

## 검증

- WIZ project build (`clean: false`) 완료
- `src/portal/samlidp/app/sp.register/view.ts` 에러 없음 확인