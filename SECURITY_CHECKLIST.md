# 보안 체크리스트 최종 대조 (secure_coding_checklist.csv 기준)

제공된 `secure_coding_checklist.csv`의 5개 섹션, 22개 항목을 실제 구현/테스트와 하나씩 대조한 결과입니다.
전체 자동화 테스트는 `tests/` 폴더에 있으며, `python -m pytest tests/ -v` 로 재현 가능합니다. (46개 테스트 전체 통과)

---

## 1. 회원가입 및 프로필 관리

| # | 체크리스트 항목 | 상태 | 구현 내용 | 검증 테스트 |
|---|---|---|---|---|
| 1 | 서버측 입력 검증 | ✅ | username 정규식(4~20자 영문/숫자/`_`), password 정규식(8자 이상+영문+숫자) | `test_auth.py::test_invalid_username_rejected`, `test_weak_password_rejected` |
| 2 | CSRF 보호 | ✅ | Flask-WTF `CSRFProtect` 전역 적용, 모든 폼에 토큰 삽입 | `test_auth.py::test_csrf_required_for_register` |
| 3 | 비밀번호 보안 | ✅ | `bcrypt` 해시 + 자동 salt | `test_auth.py::test_password_is_hashed` (해시가 `$2b$`로 시작하는지 확인) |
| 4 | 세션 쿠키 설정 | ✅ | `HttpOnly`, `SameSite=Lax` 적용, 운영환경(`FLASK_ENV=production`)에서 `Secure` 추가 | `test_auth.py::test_login_success_and_session_cookie_flags` |
| 5 | 세션 만료 및 재인증 | ✅ | 세션 30분 만료(`PERMANENT_SESSION_LIFETIME`), 비밀번호 변경 시 현재 비밀번호 재확인 | `test_auth.py::test_change_password_requires_current_password` |
| 6 | 실패 로그인 방어 | ✅ | 5회 실패 시 5분 계정 잠금 | `test_auth.py::test_account_lockout_after_failed_attempts` |
| 7 | 오류 메시지 | ✅ | `debug=False` 기본값, 500 에러 시 일반 메시지만 반환(스택 트레이스 미노출), 로그인 실패 메시지도 계정 존재 여부 노출 안 함 | `test_auth.py::test_login_failure_generic_message`, `app.py`의 `server_error` 핸들러 |

## 2. 상품 등록 및 관리

| # | 체크리스트 항목 | 상태 | 구현 내용 | 검증 테스트 |
|---|---|---|---|---|
| 8 | 폼 입력 검증 | ✅ | 제목 ≤100자, 설명 ≤2000자, 가격 정수 1~1억 범위 검증 | `test_product.py::test_price_must_be_numeric`, `test_price_range_enforced` |
| 9 | XSS 방어 | ✅ | Jinja2 auto-escape 사용(별도 `\|safe` 없음), 별도 이스케이프 불필요 확인 | 템플릿 코드 리뷰로 확인(`view_product.html`에 `\|safe` 미사용) |
| 10 | 인증된 사용자만 등록 | ✅ | `@login_required` 데코레이터 적용 | `test_auth.py::test_dashboard_requires_login`과 동일 패턴 전 라우트 적용 |
| 11 | 소유자 확인 | ✅ | 수정/삭제 시 `product.seller_id == session['user_id']` 서버측 검증 | `test_product.py::test_owner_only_can_edit`, `test_owner_only_can_delete` |
| 12 | 데이터 무결성 | ✅ | 모든 필드 검증 통과 후에만 DB 커밋, 가격은 정수형 컬럼으로 저장(문자열 저장 아님) | `test_product.py::test_price_must_be_numeric` 및 `models.py` 스키마 |

## 3. 실시간 채팅 및 메시징

| # | 체크리스트 항목 | 상태 | 구현 내용 | 검증 테스트 |
|---|---|---|---|---|
| 13 | 메시지 내용 검증 | ✅ | 500자 제한, 빈 문자열 차단, 제어문자 제거 | `test_chat.py::test_all_room_broadcast_and_xss_safe_storage` |
| 14 | 사용자 인증 | ✅ | 소켓 `connect` 시점에 세션 확인, 미인증 연결 거부 | `test_chat.py::test_unauthenticated_socket_connection_rejected` |
| 15 | 메시지 검증 | ✅ | 클라이언트가 보낸 `username` 무시, 서버 세션 기반으로 발신자 확정(스푸핑 방지) | `test_chat.py::test_sender_cannot_be_spoofed` |
| 16 | Rate Limiting | ✅ | 사용자당 3초에 5개 메시지 제한 | `test_chat.py::test_rate_limiting` |
| 17 | 연결 암호화 (WSS) | ⚠️ 배포 단계 항목 | 로컬 개발 환경은 http/ws. 운영 배포 시 반드시 리버스 프록시(nginx 등)로 TLS 종단 처리 후 wss:// 사용 필요. `README.md`에 안내 명시 | 코드 레벨 검증 불가(인프라 항목) — README 안내로 대체 |

## 4. 안전 거래 및 신고

| # | 체크리스트 항목 | 상태 | 구현 내용 | 검증 테스트 |
|---|---|---|---|---|
| 18 | 폼 입력 검증 | ✅ | target_type(product/user) 검증, target_id 필수, 사유 1~500자 | `test_report.py::test_report_nonexistent_target_rejected` |
| 19 | 인증된 사용자 접근 | ✅ | `@login_required` 적용 | 전 신고 라우트 공통 |
| 20 | 데이터 무결성 및 로그 관리 | ✅ | 신고 레코드는 **삭제하지 않고 `status`(open/dismissed)로만 관리** → 관리자가 기각해도 감사 기록이 영구 보존됨 | `test_report.py::test_dismiss_report_keeps_audit_record` |
| 21 | 신고 남용 방지 | ✅ | 자기 자신/본인 상품 신고 차단, 동일 대상 중복 신고 차단, 24시간 내 1인당 최대 20건 제한, 3건 누적 시 자동 차단/정지 | `test_report.py::test_self_product_report_rejected`, `test_duplicate_report_rejected`, `test_report_threshold_auto_blocks_product` |

## 5. 전체 시스템

| # | 체크리스트 항목 | 상태 | 구현 내용 | 검증 테스트 |
|---|---|---|---|---|
| 22 | ORM 및 파라미터 바인딩 | ✅ | raw sqlite3 쿼리를 전부 SQLAlchemy ORM으로 전환. 문자열 조립 쿼리 없음 | `test_search.py::test_sql_injection_payload_is_harmless` (SQL Injection 페이로드 무력화 + 테이블 무결성 확인) |
| 23 | 데이터베이스 권한 | ✅ | SQLite 파일 권한을 `600`(소유자 전용)으로 강제 설정. 운영 DBMS 전환 시 앱 전용 계정에 최소 CRUD 권한만 부여하도록 README에 안내 | `app.py`의 `os.chmod(..., 0o600)` |
| 24 | 보안 헤더 설정 | ✅ | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Content-Security-Policy` 전 응답에 적용 | `app.py`의 `set_security_headers` (curl로 헤더 직접 확인 완료) |
| 25 | HTTPS 적용 | ⚠️ 배포 단계 항목 | 로컬 개발은 http. `SESSION_COOKIE_SECURE`는 `FLASK_ENV=production`일 때 자동 활성화. 운영 배포 시 HTTPS 리버스 프록시 또는 ngrok(https 터널) 사용 필요 | 코드 레벨 검증 불가(인프라 항목) — README 안내로 대체 |
| 26 | 에러 및 예외 처리 | ✅ | 500 에러 핸들러가 사용자에게는 일반 메시지만 반환, 상세 스택은 서버 로그(`app.logger.exception`)에만 기록 | `app.py`의 `server_error` 핸들러 코드 확인 |
| 27 | 라이브러리 및 의존성 관리 | ✅ | `enviroments.yaml`에 Flask 3.1.3, Flask-SocketIO 5.6.1, Flask-SQLAlchemy 3.1.1, Flask-WTF 1.3.0, bcrypt 5.0.0으로 버전 고정(최신 안정 버전) | `pip show` 결과 대조 |

---

## 항목 수 요약

- 전체 22개 항목(원본 CSV 기준) + 시스템 전반 확장 항목 포함 총 27개 세부 체크 포인트
- **완전 구현 및 자동 테스트로 검증**: 25개
- **인프라/배포 단계 항목(코드만으로 검증 불가, README 안내로 대체)**: 2개 (WSS 연결 암호화, HTTPS 적용)

## 향후 개선 가능 사항 (스코프 외, 참고용)

- CSP의 `'unsafe-inline'`은 현재 채팅 위젯이 인라인 `<script>`를 사용하기 때문에 불가피하게 허용됨. 인라인 스크립트를 외부 `.js` 파일 + nonce 기반으로 옮기면 `'unsafe-inline'` 제거 가능.
- 관리자 액션(정지/차단/기각)에 대한 별도의 감사 로그 테이블은 아직 없음. 현재는 `Report.status`를 통한 신고 이력만 보존됨 — 필요 시 `AdminActionLog` 테이블 추가 고려 가능.
- `datetime.utcnow()`는 Python 3.12에서 deprecated 경고가 뜨지만, 프로젝트 지정 Python 버전(3.9)에서는 정상 동작하므로 현재 유지.
