# Overview 관리자 패널 레이아웃 정리 및 비밀번호 변경 모달 전환

- **ID**: 004
- **날짜**: 2026-04-14
- **유형**: 버그 수정

## 작업 요약
Overview 화면에서 관리자 계정/만료 데이터 카드가 우측 컬럼을 과도하게 점유해 레이아웃이 깨지는 문제를 정리했다.
관리자 비밀번호 변경은 우측 상단 액션 버튼으로 분리하고 로컬 모달로 전환했으며, 만료 데이터 현황 카드는 왼쪽 넓은 컬럼으로 이동했다.

## 변경 파일 목록
- `src/app/page.landing/view.ts`: 비밀번호 변경 모달 open/close/reset 상태 추가
- `src/app/page.landing/view.pug`: 우측 상단 비밀번호 변경 버튼, 로컬 모달, 왼쪽 Expiry Overview 카드 재배치

## 검증
- WIZ project build (`clean: false`) 완료