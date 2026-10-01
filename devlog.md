| 날짜 | ID | 작업 내용 | 상세 |
|------|-----|----------|------|
| 2026-02-21 | 001 | 기존 인프라 page 앱 전체 삭제 및 일반 서비스 샘플 page 앱 생성 | [상세](devlog/2026-02-21/001-sample-pages-rebuild.md) |
| 2026-03-18 | 001 | kafe-debug 기반 테스트용 IdP 상세 설계 문서 작성 | [상세](devlog/2026-03-18/001-test-idp-design.md) |
| 2026-03-18 | 002 | test-idp 기반 앱, 패키지, metadata, config 스켈레톤 생성 | [상세](devlog/2026-03-18/002-foundation-scaffold.md) |
| 2026-03-31 | 001 | idpcore 공통 데이터 모델과 저장소 구현, CRUD/seed 검증 | [상세](devlog/2026-03-31/001-idpcore-data-model.md) |
| 2026-03-31 | 002 | 24시간 임시 테스트 계정 생성 기능 구현 | [상세](devlog/2026-03-31/002-temporary-account.md) |
| 2026-03-31 | 003 | 공통 레이아웃과 랜딩 UX 구현 | [상세](devlog/2026-03-31/003-landing-ux.md) |
| 2026-03-31 | 004 | SAML SP 등록과 IdP 메타데이터 배포 구현 | [상세](devlog/2026-03-31/004-saml-sp-registration.md) |
| 2026-03-31 | 005 | SAML SSO Response 생성 및 디버그 구현 | [상세](devlog/2026-03-31/005-saml-sso-response.md) |
| 2026-03-31 | 006 | 샘플 코드 정리, 인증 검증 및 통합 테스트 38개 작성 | [상세](devlog/2026-03-31/006-cleanup-and-tests.md) |
| 2026-03-31 | 007 | SAML 로그아웃과 세션 정리 구현 (SLO) | [상세](devlog/2026-03-31/007-saml-slo.md) |
| 2026-03-31 | 008 | SAML/OIDC 인증 제거 및 SP 24시간 자동 만료 구현 | [상세](devlog/2026-03-31/008-auth-removal-sp-expiry.md) |
| 2026-04-01 | 001 | 종합 보안 강화: XXE, 레이트리밋, 비밀번호 해시 제거, 경로 순회, Mass Assignment | [상세](devlog/2026-04-01/001-security-hardening.md) |
| 2026-04-01 | 002 | IP 기반 삭제 제한 및 보안 제한 UI 표시 | [상세](devlog/2026-04-01/002-ip-delete-restriction.md) |
| 2026-04-13 | 001 | SAML SSO route를 브라우저용 ACS POST 응답으로 수정 | [상세](devlog/2026-04-13/001-saml-sso-browser-postback.md) |
| 2026-04-13 | 002 | SAML SSO 미인증 진입 시 계정 선택 및 로그인 프롬프트 추가 | [상세](devlog/2026-04-13/002-saml-sso-login-prompt.md) |
| 2026-04-13 | 003 | SAML Attribute를 OID URN으로 정규화하고 입력 UI에 OID 선택 보조 추가 | [상세](devlog/2026-04-13/003-saml-attribute-oid-normalization.md) |
| 2026-04-14 | 001 | OIDC 운영 화면군과 RP/discovery/authorize/logout 시뮬레이션 UI 구현 | [상세](devlog/2026-04-14/001-oidc-operations-ui.md) |
| 2026-04-14 | 002 | Test IdP용 SVG favicon 제작 및 head favicon 링크 교체 | [상세](devlog/2026-04-14/002-test-idp-favicon-svg.md) |
| 2026-04-14 | 003 | 관리자 비밀번호 변경, 만료 데이터 연장·영구 전환, 헤더 브랜드 아이콘 반영 | [상세](devlog/2026-04-14/003-admin-controls-and-validity-management.md) |
| 2026-04-14 | 004 | Overview 관리자 패널 레이아웃 정리 및 비밀번호 변경 모달 전환 | [상세](devlog/2026-04-14/004-overview-admin-layout-refine.md) |
| 2026-04-14 | 005 | Overview 기본 계정 카드 추가 및 5번째 샘플 계정 반영 | [상세](devlog/2026-04-14/005-overview-default-accounts.md) |
| 2026-04-14 | 006 | Overview 기본 계정 목록에서 admin 제외 및 테이블형 재배치 | [상세](devlog/2026-04-14/006-overview-default-account-table-refine.md) |
| 2026-04-14 | 007 | 기본 샘플 계정 정리 및 admin 전용 로그인 정책 적용 | [상세](devlog/2026-04-14/007-admin-only-login-and-sample-cleanup.md) |
| 2026-04-14 | 008 | 강제 seed의 admin 비밀번호 초기화 문제 수정 및 초기 비밀번호 안내 제거 | [상세](devlog/2026-04-14/008-admin-password-seed-fix.md) |
| 2026-04-14 | 009 | OIDC Provider issuer 도메인을 debug-idp.nanoha.kr로 교체 | [상세](devlog/2026-04-14/009-oidc-issuer-domain-update.md) |
| 2026-04-14 | 010 | OIDC discovery와 JWKS public route 추가 및 외부 well-known 경로 복구 | [상세](devlog/2026-04-14/010-oidc-public-routes.md) |
| 2026-04-14 | 011 | OIDC Provider 메타데이터와 endpoint 복사 버튼 확장 | [상세](devlog/2026-04-14/011-oidc-provider-copy-actions.md) |
| 2026-04-14 | 012 | OIDC authorization code + PKCE 실제 흐름과 token/userinfo/debug raw 구현 | [상세](devlog/2026-04-14/012-oidc-code-pkce-flow.md) |
| 2026-04-21 | 001 | OIDC RP 인덱스 복구와 authorize 로그인 프롬프트 추가 | [상세](devlog/2026-04-21/001-oidc-db-reindex-and-authorize-prompt.md) |
| 2026-04-21 | 002 | OIDC RP 수정 기능과 authorize admin 숨김 처리 | [상세](devlog/2026-04-21/002-oidc-rp-edit-and-admin-filter.md) |
| 2026-04-21 | 003 | OIDC authorize quick account top-navigation 전환 | [상세](devlog/2026-04-21/003-oidc-authorize-quick-account-top-navigation.md) |
| 2026-04-21 | 004 | SAML SP 등록 화면의 삭제/확인 모달 동작 복구 | [상세](devlog/2026-04-21/004-saml-sp-register-modal-fix.md) |
| 2026-05-18 | 001 | Test IdP 화면을 컴팩트한 운영 UI로 재설계 | [상세](devlog/2026-05-18/001-compact-ui-redesign.md) |
| 2026-05-18 | 002 | Overview 임시 계정 편집 OID 선택의 OIDC Claims 동시 적용 및 2단 배치 | [상세](devlog/2026-05-18/002-temp-account-oidc-claim-selector.md) |
| 2026-05-18 | 003 | 임시 계정 기본 SAML/OIDC 속성 자동 생성 및 pysaml2 속성 카탈로그 적용 | [상세](devlog/2026-05-18/003-temp-account-pysaml2-attribute-catalog.md) |
| 2026-05-19 | 001 | SAML SSO 빠른 계정 선택에서 admin 계정 제외 | [상세](devlog/2026-05-19/001-saml-sso-admin-quick-pick-filter.md) |
| 2026-05-20 | 001 | Quick Create 프리셋 선택과 eduPerson 속성 payload 추가 | [상세](devlog/2026-05-20/001-quick-create-presets.md) |
| 2026-05-20 | 002 | Test IdP README 한영 재작성 및 1920x1080 화면 캡처 추가 | [상세](devlog/2026-05-20/002-readme-refresh.md) |
| 2026-05-20 | 003 | README WIZ Framework 정보 추가 및 캡처 도구 문구 정리 | [상세](devlog/2026-05-20/003-readme-framework-note.md) |
| 2026-05-20 | 004 | GitHub 공개 전 민감 정보 및 불필요 산출물 정리 | [상세](devlog/2026-05-20/004-github-publish-sanitization.md) |
| 2026-05-20 | 005 | GitHub 공개용 MIT 라이센스 파일 추가 | [상세](devlog/2026-05-20/005-mit-license.md) |
| 2026-05-27 | 001 | SAML REFEDS AuthnContextClassRef 입력 및 응답 반영 추가 | [상세](devlog/2026-05-27/001-saml-refeds-authn-context-class-ref.md) |
| 2026-05-27 | 002 | SAML 로그인 화면 AuthnContextClassRef 설정 노출 개선 | [상세](devlog/2026-05-27/002-saml-authn-context-ui-visibility.md) |
| 2026-05-27 | 003 | SAML AuthnContextClassRef 입력 영역 중복 제거 | [상세](devlog/2026-05-27/003-saml-authn-context-single-input.md) |
| 2026-07-10 | 001 | README에 WIZ 기반 설치·실행 가이드와 재현 가능한 DB 설정 추가 | [상세](devlog/2026-07-10/001-readme-installation-guide.md) |
| 2026-07-10 | 002 | README Python 환경 구성을 Conda 중심 절차로 변경 | [상세](devlog/2026-07-10/002-readme-conda-environment.md) |
| 2026-07-10 | 003 | 신규 서버의 admin 비밀번호 변경 시 idpcore DB 자동 초기화 | [상세](devlog/2026-07-10/003-admin-password-db-bootstrap.md) |
| 2026-07-14 | 001 | ReviewOps 임시 OIDC·SAML 프로필 별칭과 인증 바인딩 추가 | [상세](devlog/2026-07-14/001-reviewops-stateless-protocol-profile.md) |
| 2026-07-14 | 002 | ReviewOps SAML 브라우저 SLO·Passive·응답 서명 조합 보강 | [상세](devlog/2026-07-14/002-reviewops-saml-browser-slo-and-response-defaults.md) |
| 2026-07-14 | 003 | ReviewOps federation metadata와 Assertion 속성 누락 검증 보강 | [상세](devlog/2026-07-14/003-reviewops-federation-metadata-and-attribute-omit.md) |
| 2026-07-14 | 004 | ReviewOps 프로필별 SAML Attribute OID 값 주입 및 실제 응답 검증 보강 | [상세](devlog/2026-07-14/004-reviewops-saml-profile-attribute-values.md) |
| 2026-07-15 | 001 | OIDC 토큰 시간대 독립 epoch 발급 수정 | [상세](devlog/2026-07-15/001-oidc-token-epoch-timezone-fix.md) |
| 2026-07-16 | 001 | ReviewOps SAML Redirect 원문 서명과 SLO 바인딩 보강 | [상세](devlog/2026-07-16/001-reviewops-saml-redirect-signature-hardening.md) |
| 2026-08-18 | 001 | admin 계정 패스워드 갱신 | [상세](devlog/2026-08-18/001-admin-password-update.md) |
| 2026-09-15 | 001 | OIDC·SAML 표준 기능과 호환성 표시 및 운영 화면 보강 | [상세](devlog/2026-09-15/001-modernize-oidc-saml.md) |
| 2026-09-15 | 002 | OIDC·SAML 작업 메뉴, 실행 설정, 상세 화면 UX 개편 | [상세](devlog/2026-09-15/002-redesign-protocol-console-ux.md) |
| 2026-09-15 | 003 | 실행 설정 선택, SAML 세션·로그인 성능, 화면 여백 보강 | [상세](devlog/2026-09-15/003-execution-settings-session-performance-spacing.md) |
| 2026-09-15 | 004 | SAML IdP 정보 로딩 오류 수정 및 실행 중 확인 | [상세](devlog/2026-09-15/004-fix-saml-idp-info-loading.md) |
| 2026-09-15 | 005 | OIDC·SAML 실행 설정 삭제 기능 추가 | [상세](devlog/2026-09-15/005-delete-execution-settings.md) |
| 2026-09-15 | 006 | OIDC end_session과 SAML SLO 표준 흐름 보강 | [상세](devlog/2026-09-15/006-end-session-and-slo-support.md) |
| 2026-09-15 | 007 | 검증용 IdP 세션 만료 및 메모리 상한 보강 | [상세](devlog/2026-09-15/007-session-and-memory-safety.md) |
| 2026-09-15 | 008 | ReviewOps 기능 개선 변경 커밋 정리 | [상세](devlog/2026-09-15/008-commit-reviewops-improvements.md) |
| 2026-10-01 | 001 | OIDC·SAML 표준 전수 감사, refresh token 및 SAML Federation IdP 보강 | [상세](devlog/2026-10-01/001-standards-audit-and-saml-federation-idp.md) |
| 2026-10-01 | 002 | Quick Federation과 SAML metadata signing/encryption credential 분리 보강 | [상세](devlog/2026-10-01/002-quick-federation-and-metadata-credentials.md) |
| 2026-10-01 | 003 | SAML Publish 화면을 Metadata와 Quick Federation 중심으로 단순화 | [상세](devlog/2026-10-01/003-saml-publish-simplification.md) |
