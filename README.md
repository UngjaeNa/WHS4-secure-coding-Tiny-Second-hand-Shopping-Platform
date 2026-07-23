# -WHS4-secure-coding-Tiny-Second-hand-Shopping-Platform
WHS 4기 나웅재 Secure-Coding 과제
<hr>
<hr>

# Secure Coding - Tiny Secondhand Shopping Platform

간단한 중고거래 플랫폼입니다. 시큐어 코딩 과제로 개발되었으며, 회원가입/로그인부터
상품 거래, 실시간 채팅, 신고, 가상 잔액 송금, 검색, 관리자 기능까지 구현하면서
각 기능별 보안 취약점을 식별하고 대응했습니다.

전체 보안 체크리스트 대조 결과는 [`SECURITY_CHECKLIST.md`](./SECURITY_CHECKLIST.md)를 참고하세요.

## 주요 기능

- 회원가입 / 로그인 (비밀번호 해시, 로그인 실패 잠금, 세션 보안)
- 상품 등록 / 조회 / 수정 / 삭제 (소유자 검증)
- 실시간 전체 채팅 + 1:1 채팅 (Socket.IO, 인증 기반)
- 상품/유저 신고 (남용 방지, 누적 시 자동 차단·정지)
- 가상 잔액 충전 / 송금 (동시성 안전 처리)
- 상품 검색 (키워드/가격/판매자/상태 다중 필터)
- 관리자 기능 (운영자/최고관리자 등급, RBAC)

## 기술 스택

- Python 3.9, Flask 3.x, Flask-SocketIO, Flask-SQLAlchemy (ORM), Flask-WTF (CSRF), bcrypt
- DB: SQLite (개발/과제용 기본값, 환경변수로 다른 DB로 교체 가능)

---

## 1. 환경 설정

miniconda(또는 anaconda)가 없다면 먼저 설치하세요.
https://docs.anaconda.com/free/miniconda/index.html

```bash
git clone https://github.com/UngjaeNa/WHS4-secure-coding-Tiny-Second-hand-Shopping-Platform
cd WHS4-secure-coding-Tiny-Second-hand-Shopping-Platform
conda env create -f enviroments.yaml
conda activate secure_coding
```

### 환경변수 (선택)

기본값으로도 로컬 실행에는 문제가 없지만, 아래 환경변수로 동작을 조정할 수 있습니다.

| 변수 | 기본값 | 설명 |
|---|---|---|
| `SECRET_KEY` | 매 실행마다 랜덤 생성 | 세션 서명 키. **운영 배포 시에는 반드시 고정값으로 지정**해야 서버 재시작 시 기존 세션이 무효화되지 않습니다. |
| `FLASK_ENV` | (미설정) | `production`으로 설정하면 세션 쿠키에 `Secure` 플래그와 HSTS 헤더가 추가로 적용됩니다. HTTPS 환경에서만 사용하세요. |
| `FLASK_DEBUG` | `0` | `1`로 설정하면 Flask 디버그 모드로 실행됩니다 (로컬 개발용, 운영 환경 절대 금지). |
| `DATABASE_URL` | `sqlite:///market.db` | 다른 DB(PostgreSQL 등)를 사용하려면 SQLAlchemy 접속 문자열로 지정하세요. |

---

## 2. 서버 실행

```bash
python app.py
```

기본적으로 `http://127.0.0.1:5000` 에서 서비스가 시작됩니다. 최초 실행 시 `market.db`
SQLite 파일과 테이블이 자동으로 생성됩니다.

외부 기기(모바일 등)에서 접속 테스트를 하려면 ngrok으로 포워딩할 수 있습니다.

```bash
# optional
sudo snap install ngrok
ngrok http 5000
```

> ngrok이 제공하는 URL은 기본적으로 HTTPS이므로, 외부 테스트 시 채팅(WSS)과 세션 쿠키
> 보안 옵션(`Secure`)이 정상적으로 검증하기 좋은 환경입니다.

---

## 3. 관리자(admin) 계정 생성

관리자 지정 기능은 보안상 **웹 화면이 아닌 CLI로만** 제공됩니다. (웹 라우트로 노출하면
권한 상승 공격의 표면이 되기 때문입니다.)

1. 먼저 일반 회원가입으로 계정을 하나 만듭니다. (`/register` 페이지 또는 아래 순서대로)
2. 서버가 실행 중인 상태에서, 별도 터미널에서 아래 명령을 실행합니다.

```bash
FLASK_APP=app.py flask create-admin
```

프롬프트가 뜨면 admin으로 지정할 사용자명을 입력하세요.

```
관리자로 지정할 사용자명: your_username
"your_username"을(를) 최고관리자로 지정했습니다.
```

이후 해당 계정으로 로그인하면 상단 메뉴에 **관리자** 링크가 나타나고, `/admin`에서
유저/상품/신고 관리 및 `/admin/operators`에서 운영자 등급 부여가 가능합니다.

- **user < operator < admin** 3단계 등급이며, admin만 운영자 등급을 부여/해제할 수 있습니다.
- 마지막 남은 admin 계정은 강등할 수 없도록 안전장치가 있습니다.

---

## 4. 테스트 실행

pytest 기반 자동화 테스트가 `tests/` 폴더에 있습니다 (46개, 회원/상품/채팅/신고/송금/검색/관리자 전 기능 커버).

```bash
pip install pytest
python -m pytest tests/ -v
```

테스트는 실제 `market.db`를 건드리지 않고 임시 DB를 사용하므로, 개발 중인 데이터에
영향을 주지 않고 언제든 실행할 수 있습니다.

---

## 5. 프로젝트 구조

```
.
├── app.py                     # Flask 앱 (라우트, 소켓 핸들러, 보안 로직)
├── models.py                  # SQLAlchemy 모델 (User, Product, Report, Transaction, Message)
├── enviroments.yaml           # conda 환경설정 (의존성 버전 고정)
├── secure_coding_checklist.csv  # 과제 제공 보안 체크리스트
├── SECURITY_CHECKLIST.md      # 체크리스트 22개 항목 최종 대조 결과
├── templates/                 # Jinja2 HTML 템플릿
└── tests/                     # pytest 테스트 스위트
    ├── conftest.py
    ├── test_auth.py
    ├── test_product.py
    ├── test_report.py
    ├── test_search.py
    ├── test_wallet.py
    ├── test_chat.py
    └── test_admin.py
```

---

## 6. 배포 시 참고사항 (로컬 개발 환경에서는 해당 없음)

- **HTTPS/WSS**: 이 저장소의 개발 서버는 HTTP로 동작합니다. 실제 배포 시에는 nginx 등
  리버스 프록시로 TLS를 종단 처리하고, `FLASK_ENV=production`으로 설정해 세션 쿠키에
  `Secure` 플래그가 적용되도록 해야 합니다.
- **프로덕션 WSGI 서버**: 코드 내 `allow_unsafe_werkzeug=True` 옵션은 로컬 개발용입니다.
  운영 배포 시에는 `gunicorn` + `eventlet`(또는 `gevent`) 조합 등 프로덕션 WSGI 서버 사용을
