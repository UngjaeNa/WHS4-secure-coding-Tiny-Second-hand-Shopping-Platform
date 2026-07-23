import os
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta

import bcrypt
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit, join_room, disconnect
from flask_wtf import CSRFProtect

from models import db, User, Product, Report, Message, Transaction

# ---------------------------------------------------------------------------
# 앱 / 확장 초기화
# ---------------------------------------------------------------------------
app = Flask(__name__)

# SECRET_KEY: 환경변수로 관리 (없으면 개발용 임시 키 생성 - 운영 배포 시 반드시 환경변수 지정 필요)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(32).hex())

# DB 설정 (SQLAlchemy ORM 사용 - 파라미터 바인딩 자동 적용으로 SQL Injection 방지)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_default_db_path = 'sqlite:///' + os.path.join(BASE_DIR, 'market.db')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', _default_db_path)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['TESTING'] = os.environ.get('FLASK_TESTING', '0') == '1'

# 세션 쿠키 보안 설정
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# 운영(HTTPS) 환경에서는 True로. 로컬 http 개발 환경에서는 False로 두지 않으면 쿠키가 전송되지 않음.
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

db.init_app(app)
csrf = CSRFProtect(app)
socketio = SocketIO(app)

with app.app_context():
    db.create_all()

# 최소 권한 원칙: SQLite 파일 자체가 DB이므로, 파일시스템 권한으로 접근을 제한한다.
# (실제 운영 DBMS를 사용할 경우, 애플리케이션 전용 계정에 필요한 CRUD 권한만 부여하고
#  DDL/슈퍼유저 권한은 부여하지 않아야 한다.)
try:
    os.chmod(os.path.join(BASE_DIR, 'market.db'), 0o600)
except OSError:
    pass


@app.context_processor
def inject_current_role():
    uid = session.get('user_id')
    role = None
    if uid:
        u = db.session.get(User, uid)
        role = u.role if u else None
    return {'current_role': role}


# ---------------------------------------------------------------------------
# 보안 헤더 (모든 응답에 공통 적용)
#  - CSP: 우리 페이지는 socket.io 클라이언트를 cdnjs.cloudflare.com에서 로드하고,
#    인라인 <script>를 사용하므로 이를 허용하는 범위에서 최대한 제한적으로 설정.
#    (인라인 스크립트를 없애고 nonce/외부 파일로 옮기면 'unsafe-inline' 제거 가능 - 향후 개선 과제)
#  - X-Frame-Options: 클릭재킹 방지 (다른 사이트의 iframe에 삽입 금지)
#  - X-Content-Type-Options: MIME 스니핑 방지
#  - Referrer-Policy: 외부 링크 클릭 시 URL 정보 과다 노출 방지
# ---------------------------------------------------------------------------
@app.after_request
def set_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self' ws: wss:; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    if os.environ.get('FLASK_ENV') == 'production':
        # HSTS: 운영(HTTPS) 환경에서만 적용 (로컬 http 개발환경에서는 브라우저가 강제 https로
        # 전환해버려 개발이 불편해지므로 조건부 적용)
        response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains'
    return response

# ---------------------------------------------------------------------------
# 검증 규칙
# ---------------------------------------------------------------------------
USERNAME_RE = re.compile(r'^[A-Za-z0-9_]{4,20}$')
# 8자 이상, 영문+숫자 최소 1개씩 포함
PASSWORD_RE = re.compile(r'^(?=.*[A-Za-z])(?=.*\d).{8,64}$')

MAX_FAILED_ATTEMPTS = 5
LOCK_DURATION = timedelta(minutes=5)

# --- 신고 관련 상수 ---
REPORT_REASON_MAX_LEN = 500
REPORT_BLOCK_THRESHOLD = 3       # 이 횟수 이상 신고되면 상품 자동 차단 / 유저 자동 정지
REPORT_DAILY_LIMIT = 20          # 사용자 1명이 하루에 접수 가능한 최대 신고 수 (남용 방지)

# --- 송금/충전 관련 상수 ---
WALLET_CHARGE_MIN = 1
WALLET_CHARGE_MAX = 1_000_000
WALLET_TRANSFER_MIN = 1
WALLET_TRANSFER_MAX = 1_000_000
WALLET_HISTORY_LIMIT = 50
CHAT_MESSAGE_MAX_LEN = 500
CHAT_RATE_LIMIT_COUNT = 5      # 허용 메시지 수
CHAT_RATE_LIMIT_WINDOW = 3.0   # 초 단위 윈도우
CHAT_HISTORY_LIMIT = 50        # 페이지 로드시 불러올 과거 메시지 수

# 사용자별 최근 메시지 전송 시각 기록 (in-memory, 단일 프로세스 기준)
_message_timestamps = defaultdict(lambda: deque(maxlen=CHAT_RATE_LIMIT_COUNT))
# 소켓 세션(sid) -> user_id 매핑 (연결 인증 확인용)
_sid_to_user = {}


def all_chat_room():
    return 'room:all'


def dm_room(user_id_a, user_id_b):
    ids = sorted([user_id_a, user_id_b])
    return 'room:dm:' + ':'.join(ids)


def is_rate_limited(user_id):
    now = datetime.utcnow().timestamp()
    dq = _message_timestamps[user_id]
    if len(dq) == CHAT_RATE_LIMIT_COUNT and (now - dq[0]) < CHAT_RATE_LIMIT_WINDOW:
        return True
    dq.append(now)
    return False


def sanitize_message(raw):
    """채팅 메시지 서버측 검증. 통과하면 정제된 문자열, 실패하면 None."""
    if not isinstance(raw, str):
        return None
    content = raw.strip()
    if not content:
        return None
    if len(content) > CHAT_MESSAGE_MAX_LEN:
        content = content[:CHAT_MESSAGE_MAX_LEN]
    # 제어문자(개행/탭 제외) 제거 - 터미널 이스케이프 등 악용 방지
    content = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', content)
    if not content:
        return None
    return content


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode('utf-8'), hashed.encode('utf-8'))
    except ValueError:
        # 저장된 해시 형식이 올바르지 않은 경우 등 - 검증 실패로 처리
        return False


def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    return db.session.get(User, uid)


def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        user = current_user()
        if user is None or user.status != 'active':
            session.clear()
            flash('로그인이 필요하거나 계정이 비활성화되었습니다.')
            return redirect(url_for('login'))
        return view(*args, **kwargs)

    return wrapped


ROLE_RANK = {'user': 0, 'operator': 1, 'admin': 2}


def role_required(min_role):
    """지정한 등급 이상의 role을 가진 사용자만 접근 허용 (RBAC).
    반드시 login_required와 함께 사용 (세션 인증이 선행되어야 함)."""
    from functools import wraps

    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            user = current_user()
            if ROLE_RANK.get(user.role, 0) < ROLE_RANK[min_role]:
                flash('접근 권한이 없습니다.')
                return redirect(url_for('dashboard'))
            return view(*args, **kwargs)

        return wrapped

    return decorator


# ---------------------------------------------------------------------------
# 기본 라우트
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    if session.get('user_id'):
        return redirect(url_for('dashboard'))
    return render_template('index.html')


# ---------------------------------------------------------------------------
# 회원가입
# ---------------------------------------------------------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''

        if not USERNAME_RE.match(username):
            flash('사용자명은 4~20자의 영문, 숫자, 밑줄(_)만 사용할 수 있습니다.')
            return redirect(url_for('register'))

        if not PASSWORD_RE.match(password):
            flash('비밀번호는 8자 이상이며 영문과 숫자를 모두 포함해야 합니다.')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        user = User(username=username, password_hash=hash_password(password))
        db.session.add(user)
        db.session.commit()

        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))

    return render_template('register.html')


# ---------------------------------------------------------------------------
# 로그인 / 로그아웃
# ---------------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''

        # 공통 실패 메시지 (계정 존재 여부를 노출하지 않기 위해 동일 메시지 사용)
        generic_error = '아이디 또는 비밀번호가 올바르지 않습니다.'

        user = User.query.filter_by(username=username).first()

        if user is None:
            flash(generic_error)
            return redirect(url_for('login'))

        if user.status != 'active':
            flash('비활성화된 계정입니다. 관리자에게 문의하세요.')
            return redirect(url_for('login'))

        if user.locked_until and user.locked_until > datetime.utcnow():
            remaining = int((user.locked_until - datetime.utcnow()).total_seconds() // 60) + 1
            flash(f'로그인 시도가 너무 많습니다. {remaining}분 후 다시 시도해주세요.')
            return redirect(url_for('login'))

        if not verify_password(password, user.password_hash):
            user.failed_attempts += 1
            if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
                user.locked_until = datetime.utcnow() + LOCK_DURATION
                user.failed_attempts = 0
                db.session.commit()
                flash('로그인 시도가 너무 많아 5분간 계정이 잠깁니다.')
                return redirect(url_for('login'))
            db.session.commit()
            flash(generic_error)
            return redirect(url_for('login'))

        # 로그인 성공: 실패 카운트 초기화 + 세션 고정(session fixation) 방지를 위해 세션 재발급
        user.failed_attempts = 0
        user.locked_until = None
        db.session.commit()

        session.clear()
        session['user_id'] = user.id
        session.permanent = True

        flash('로그인 성공!')
        return redirect(url_for('dashboard'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))


# ---------------------------------------------------------------------------
# 대시보드
# ---------------------------------------------------------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user()
    products = Product.query.filter_by(status='active').order_by(Product.created_at.desc()).all()
    history = (
        Message.query.filter_by(room_type='all', room_id=all_chat_room())
        .order_by(Message.created_at.desc())
        .limit(CHAT_HISTORY_LIMIT)
        .all()
    )
    history.reverse()
    return render_template('dashboard.html', products=products, user=user, history=history)


# ---------------------------------------------------------------------------
# 프로필 (소개글 수정)
# ---------------------------------------------------------------------------
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = current_user()
    if request.method == 'POST':
        bio = (request.form.get('bio') or '')[:500]
        user.bio = bio
        db.session.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))
    return render_template('profile.html', user=user)


@app.route('/profile/password', methods=['POST'])
@login_required
def change_password():
    # 민감 작업 - 현재 비밀번호 재확인 (재인증)
    user = current_user()
    current_password = request.form.get('current_password') or ''
    new_password = request.form.get('new_password') or ''

    if not verify_password(current_password, user.password_hash):
        flash('현재 비밀번호가 올바르지 않습니다.')
        return redirect(url_for('profile'))

    if not PASSWORD_RE.match(new_password):
        flash('새 비밀번호는 8자 이상이며 영문과 숫자를 모두 포함해야 합니다.')
        return redirect(url_for('profile'))

    user.password_hash = hash_password(new_password)
    db.session.commit()
    flash('비밀번호가 변경되었습니다.')
    return redirect(url_for('profile'))


# ---------------------------------------------------------------------------
# 상품 관리
# ---------------------------------------------------------------------------
PRODUCT_TITLE_MAX = 100
PRODUCT_DESC_MAX = 2000
PRODUCT_PRICE_MIN = 1
PRODUCT_PRICE_MAX = 100_000_000


def validate_product_form(title, description, price_raw):
    """상품 등록/수정 공통 서버측 검증. 실패 시 오류 메시지를 반환, 성공 시 None."""
    if not title or not title.strip():
        return '제목을 입력해주세요.', None
    title = title.strip()
    if len(title) > PRODUCT_TITLE_MAX:
        return f'제목은 {PRODUCT_TITLE_MAX}자 이하여야 합니다.', None

    if not description or not description.strip():
        return '상품 설명을 입력해주세요.', None
    description = description.strip()
    if len(description) > PRODUCT_DESC_MAX:
        return f'설명은 {PRODUCT_DESC_MAX}자 이하여야 합니다.', None

    # 가격: 정수만 허용, 범위 검증 (숫자가 아니거나 범위 밖이면 거부)
    try:
        price = int(price_raw)
    except (TypeError, ValueError):
        return '가격은 숫자로 입력해주세요.', None
    if not (PRODUCT_PRICE_MIN <= price <= PRODUCT_PRICE_MAX):
        return f'가격은 {PRODUCT_PRICE_MIN}원 이상 {PRODUCT_PRICE_MAX:,}원 이하로 입력해주세요.', None

    return None, (title, description, price)


@app.route('/product/new', methods=['GET', 'POST'])
@login_required
def new_product():
    if request.method == 'POST':
        error, cleaned = validate_product_form(
            request.form.get('title'), request.form.get('description'), request.form.get('price')
        )
        if error:
            flash(error)
            return redirect(url_for('new_product'))

        title, description, price = cleaned
        product = Product(title=title, description=description, price=price, seller_id=session['user_id'])
        db.session.add(product)
        db.session.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')


@app.route('/product/<product_id>')
def view_product(product_id):
    product = db.session.get(Product, product_id)
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    # 차단된 상품은 소유자 본인 외에는 조회 불가 (신고 누적으로 차단된 상품 노출 방지)
    if product.status == 'blocked' and session.get('user_id') != product.seller_id:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    seller = db.session.get(User, product.seller_id)
    return render_template('view_product.html', product=product, seller=seller)


@app.route('/my-products')
@login_required
def my_products():
    products = Product.query.filter_by(seller_id=session['user_id']).order_by(Product.created_at.desc()).all()
    return render_template('my_products.html', products=products)


@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    product = db.session.get(Product, product_id)
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    # 소유자 확인: 요청자가 이 상품의 판매자인지 서버측에서 반드시 검증
    if product.seller_id != session['user_id']:
        flash('본인이 등록한 상품만 수정할 수 있습니다.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        error, cleaned = validate_product_form(
            request.form.get('title'), request.form.get('description'), request.form.get('price')
        )
        if error:
            flash(error)
            return redirect(url_for('edit_product', product_id=product.id))

        status = request.form.get('status')
        if status not in ('active', 'sold'):
            flash('올바르지 않은 상태 값입니다.')
            return redirect(url_for('edit_product', product_id=product.id))

        title, description, price = cleaned
        product.title = title
        product.description = description
        product.price = price
        product.status = status
        db.session.commit()
        flash('상품이 수정되었습니다.')
        return redirect(url_for('view_product', product_id=product.id))

    return render_template('edit_product.html', product=product)


@app.route('/product/<product_id>/delete', methods=['POST'])
@login_required
def delete_product(product_id):
    product = db.session.get(Product, product_id)
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    # 소유자 확인
    if product.seller_id != session['user_id']:
        flash('본인이 등록한 상품만 삭제할 수 있습니다.')
        return redirect(url_for('dashboard'))

    db.session.delete(product)
    db.session.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('my_products'))


# ---------------------------------------------------------------------------
# 검색
#
# 보안 고려사항:
#  - SQLAlchemy ORM의 filter()/ilike()는 자동으로 파라미터 바인딩되어 SQL Injection이
#    구조적으로 불가능하다 (문자열을 직접 이어붙여 쿼리를 만들지 않음).
#  - LIKE 패턴에서 %, _ 는 와일드카드로 해석되므로, 사용자가 입력한 문자열에 포함된
#    %, _ 는 리터럴로 처리되도록 이스케이프한다 (그렇지 않으면 예상 밖의 광범위 매칭 가능).
#  - 페이지당 결과 수와 최대 페이지를 제한하여 과도한 OFFSET 스캔으로 인한 서버 부하를 방지한다.
# ---------------------------------------------------------------------------
SEARCH_KEYWORD_MAX_LEN = 100
SEARCH_PAGE_SIZE = 20
SEARCH_MAX_PAGE = 50  # 그 이상은 결과를 좁혀서 다시 검색하도록 유도


def escape_like(value: str) -> str:
    return value.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')


@app.route('/search')
@login_required
def search():
    keyword = (request.args.get('q') or '').strip()[:SEARCH_KEYWORD_MAX_LEN]
    seller_username = (request.args.get('seller') or '').strip()[:20]
    status_filter = request.args.get('status', 'active')
    if status_filter not in ('active', 'sold'):
        status_filter = 'active'

    def parse_price(name):
        raw = request.args.get(name)
        if raw is None or raw == '':
            return None
        try:
            v = int(raw)
        except (TypeError, ValueError):
            return None
        return max(0, v)

    min_price = parse_price('min_price')
    max_price = parse_price('max_price')
    if min_price is not None and max_price is not None and min_price > max_price:
        min_price, max_price = max_price, min_price

    try:
        page = max(1, min(SEARCH_MAX_PAGE, int(request.args.get('page', 1))))
    except (TypeError, ValueError):
        page = 1

    query = Product.query.filter(Product.status == status_filter)

    if keyword:
        query = query.filter(Product.title.ilike(f"%{escape_like(keyword)}%", escape='\\'))

    if seller_username:
        seller = User.query.filter_by(username=seller_username).first()
        if seller:
            query = query.filter(Product.seller_id == seller.id)
        else:
            query = query.filter(db.false())  # 존재하지 않는 판매자 -> 결과 없음

    if min_price is not None:
        query = query.filter(Product.price >= min_price)
    if max_price is not None:
        query = query.filter(Product.price <= max_price)

    query = query.order_by(Product.created_at.desc())
    products = query.limit(SEARCH_PAGE_SIZE).offset((page - 1) * SEARCH_PAGE_SIZE).all()

    return render_template(
        'search.html',
        products=products,
        q=keyword, seller=seller_username, status=status_filter,
        min_price=min_price, max_price=max_price, page=page,
        has_more=len(products) == SEARCH_PAGE_SIZE,
    )


# ---------------------------------------------------------------------------
# 채팅
# ---------------------------------------------------------------------------
@app.route('/chat/<other_user_id>')
@login_required
def chat_dm(other_user_id):
    user = current_user()
    if other_user_id == user.id:
        flash('본인과는 채팅할 수 없습니다.')
        return redirect(url_for('dashboard'))

    other = db.session.get(User, other_user_id)
    if not other:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    room = dm_room(user.id, other.id)
    history = (
        Message.query.filter_by(room_type='dm', room_id=room)
        .order_by(Message.created_at.desc())
        .limit(CHAT_HISTORY_LIMIT)
        .all()
    )
    history.reverse()
    return render_template('chat_dm.html', other=other, room=room, history=history)


@socketio.on('connect')
def handle_connect():
    # 소켓 연결 시점에 로그인 여부 확인. 미인증이면 연결 자체를 거부.
    user_id = session.get('user_id')
    if not user_id:
        return False  # 연결 거부
    user = db.session.get(User, user_id)
    if not user or user.status != 'active':
        return False
    _sid_to_user[request.sid] = user_id


@socketio.on('disconnect')
def handle_disconnect():
    _sid_to_user.pop(request.sid, None)


@socketio.on('join')
def handle_join(data):
    """클라이언트가 특정 채팅방(room)에 입장. room_type: 'all' 또는 'dm'."""
    user_id = _sid_to_user.get(request.sid)
    if not user_id:
        disconnect()
        return

    room_type = (data or {}).get('room_type')
    if room_type == 'all':
        room = all_chat_room()
    elif room_type == 'dm':
        other_id = (data or {}).get('other_user_id', '')
        other = db.session.get(User, other_id)
        if not other or other_id == user_id:
            return
        room = dm_room(user_id, other_id)
    else:
        return

    join_room(room)


@socketio.on('send_message')
def handle_send_message_event(data):
    # 서버측에서 세션 기반으로 발신자를 확정 (클라이언트가 보낸 username은 절대 신뢰하지 않음)
    user_id = _sid_to_user.get(request.sid)
    if not user_id:
        disconnect()
        return

    user = db.session.get(User, user_id)
    if not user or user.status != 'active':
        disconnect()
        return

    if is_rate_limited(user_id):
        emit('chat_error', {'message': '메시지를 너무 빠르게 보내고 있습니다. 잠시 후 다시 시도해주세요.'}, room=request.sid)
        return

    if not isinstance(data, dict):
        return

    content = sanitize_message(data.get('message'))
    if content is None:
        emit('chat_error', {'message': '메시지 내용이 올바르지 않습니다.'}, room=request.sid)
        return

    room_type = data.get('room_type')
    if room_type == 'all':
        room = all_chat_room()
        db_room_type = 'all'
    elif room_type == 'dm':
        other_id = data.get('other_user_id', '')
        other = db.session.get(User, other_id)
        if not other or other_id == user_id:
            return
        room = dm_room(user_id, other_id)
        db_room_type = 'dm'
    else:
        return

    msg = Message(room_type=db_room_type, room_id=room, sender_id=user_id, content=content)
    db.session.add(msg)
    db.session.commit()

    emit('new_message', {
        'username': user.username,
        'message': content,
        'timestamp': msg.created_at.strftime('%H:%M:%S'),
    }, room=room)


# ---------------------------------------------------------------------------
# 신고
# ---------------------------------------------------------------------------
@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    if request.method == 'POST':
        reporter_id = session['user_id']
        target_type = request.form.get('target_type', '')
        target_id = (request.form.get('target_id') or '').strip()
        reason = (request.form.get('reason') or '').strip()

        form_defaults = {'target_type': target_type, 'target_id': target_id, 'reason': reason}

        if target_type not in ('product', 'user'):
            flash('올바르지 않은 신고 대상 종류입니다.')
            return render_template('report.html', **form_defaults)

        if not target_id:
            flash('신고 대상 ID를 입력해주세요.')
            return render_template('report.html', **form_defaults)

        if not reason:
            flash('신고 사유를 입력해주세요.')
            return render_template('report.html', **form_defaults)
        if len(reason) > REPORT_REASON_MAX_LEN:
            flash(f'신고 사유는 {REPORT_REASON_MAX_LEN}자 이하로 입력해주세요.')
            return render_template('report.html', **form_defaults)

        # 대상 존재 여부 검증
        if target_type == 'product':
            target = db.session.get(Product, target_id)
        else:
            target = db.session.get(User, target_id)

        if not target:
            flash('신고 대상을 찾을 수 없습니다.')
            return render_template('report.html', **form_defaults)

        # 자기 자신 / 본인 소유 상품 신고 방지
        if target_type == 'user' and target_id == reporter_id:
            flash('본인을 신고할 수 없습니다.')
            return render_template('report.html', **form_defaults)
        if target_type == 'product' and target.seller_id == reporter_id:
            flash('본인이 등록한 상품은 신고할 수 없습니다.')
            return render_template('report.html', **form_defaults)

        # 중복 신고 방지: 동일 대상에 대해 이미 신고한 이력이 있으면 거부
        existing = Report.query.filter_by(
            reporter_id=reporter_id, target_type=target_type, target_id=target_id
        ).first()
        if existing:
            flash('이미 신고한 대상입니다.')
            return render_template('report.html', **form_defaults)

        # 남용 방지: 최근 24시간 내 본인의 총 신고 건수 제한
        since = datetime.utcnow() - timedelta(hours=24)
        recent_count = Report.query.filter(
            Report.reporter_id == reporter_id, Report.created_at >= since
        ).count()
        if recent_count >= REPORT_DAILY_LIMIT:
            flash('신고 가능 횟수를 초과했습니다. 잠시 후 다시 시도해주세요.')
            return render_template('report.html', **form_defaults)

        r = Report(reporter_id=reporter_id, target_type=target_type, target_id=target_id, reason=reason)
        db.session.add(r)
        db.session.commit()

        # 누적 신고 수 확인 후 자동 차단/정지 처리
        total_reports = Report.query.filter_by(target_type=target_type, target_id=target_id).count()
        if total_reports >= REPORT_BLOCK_THRESHOLD:
            if target_type == 'product' and target.status == 'active':
                target.status = 'blocked'
                db.session.commit()
            elif target_type == 'user' and target.status == 'active':
                target.status = 'suspended'
                db.session.commit()

        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))

    # GET: 쿼리 파라미터로 대상 프리필 (상품 상세페이지 등에서 링크로 진입)
    target_type = request.args.get('target_type', 'product')
    target_id = request.args.get('target_id', '')
    if target_type not in ('product', 'user'):
        target_type = 'product'
    return render_template('report.html', target_type=target_type, target_id=target_id)


# ---------------------------------------------------------------------------
# 송금(가상 잔액) 기능
#
# 동시성 처리 방침:
#  "잔액 조회 -> 파이썬에서 차감 계산 -> UPDATE" 패턴은 두 요청이 동시에 들어오면
#  둘 다 같은 잔액을 읽어 조건 검사를 통과해버리는 lost-update / 이중 지불 문제가
#  발생할 수 있다. 이를 막기 위해 "잔액 검증 + 차감"을 하나의 원자적 UPDATE 문으로
#  수행한다: UPDATE user SET balance = balance - :amt WHERE id=:id AND balance >= :amt
#  이 문장은 DB 엔진이 단일 원자 연산으로 처리하므로, 어떤 동시성 상황에서도
#  잔액이 음수가 되는 것을 원천적으로 방지한다. rowcount로 성공 여부를 확인한다.
# ---------------------------------------------------------------------------
@app.route('/wallet')
@login_required
def wallet():
    user = current_user()
    history = (
        Transaction.query.filter(
            (Transaction.from_user_id == user.id) | (Transaction.to_user_id == user.id)
        )
        .order_by(Transaction.created_at.desc())
        .limit(WALLET_HISTORY_LIMIT)
        .all()
    )
    # 상대방 username 표시를 위해 매핑
    other_ids = {t.from_user_id for t in history if t.from_user_id} | {t.to_user_id for t in history}
    others = {u.id: u.username for u in User.query.filter(User.id.in_(other_ids)).all()}
    return render_template('wallet.html', user=user, history=history, others=others)


@app.route('/wallet/charge', methods=['POST'])
@login_required
def wallet_charge():
    user_id = session['user_id']
    amount_raw = request.form.get('amount')

    try:
        amount = int(amount_raw)
    except (TypeError, ValueError):
        flash('충전 금액은 숫자로 입력해주세요.')
        return redirect(url_for('wallet'))

    if not (WALLET_CHARGE_MIN <= amount <= WALLET_CHARGE_MAX):
        flash(f'충전 금액은 {WALLET_CHARGE_MIN}원 이상 {WALLET_CHARGE_MAX:,}원 이하만 가능합니다.')
        return redirect(url_for('wallet'))

    # 원자적 증가 (동시 충전 요청이 있어도 balance = balance + amount 형태로 안전)
    db.session.execute(
        db.update(User).where(User.id == user_id).values(balance=User.balance + amount)
    )
    db.session.add(Transaction(from_user_id=None, to_user_id=user_id, amount=amount, type='charge'))
    db.session.commit()

    flash(f'{amount:,}원이 충전되었습니다.')
    return redirect(url_for('wallet'))


@app.route('/wallet/transfer', methods=['POST'])
@login_required
def wallet_transfer():
    sender_id = session['user_id']
    recipient_username = (request.form.get('recipient') or '').strip()
    amount_raw = request.form.get('amount')

    recipient = User.query.filter_by(username=recipient_username).first()
    if not recipient:
        flash('받는 사람을 찾을 수 없습니다.')
        return redirect(url_for('wallet'))

    if recipient.id == sender_id:
        flash('본인에게는 송금할 수 없습니다.')
        return redirect(url_for('wallet'))

    if recipient.status != 'active':
        flash('받는 사람의 계정 상태로 인해 송금할 수 없습니다.')
        return redirect(url_for('wallet'))

    try:
        amount = int(amount_raw)
    except (TypeError, ValueError):
        flash('송금 금액은 숫자로 입력해주세요.')
        return redirect(url_for('wallet'))

    if not (WALLET_TRANSFER_MIN <= amount <= WALLET_TRANSFER_MAX):
        flash(f'송금 금액은 {WALLET_TRANSFER_MIN}원 이상 {WALLET_TRANSFER_MAX:,}원 이하만 가능합니다.')
        return redirect(url_for('wallet'))

    # 1) 원자적 차감: balance >= amount 조건을 UPDATE 문 자체에 포함시켜
    #    "확인 후 차감" 사이의 race condition을 제거한다.
    result = db.session.execute(
        db.update(User)
        .where(User.id == sender_id, User.balance >= amount)
        .values(balance=User.balance - amount)
    )

    if result.rowcount == 0:
        db.session.rollback()
        flash('잔액이 부족합니다.')
        return redirect(url_for('wallet'))

    # 2) 수취인 잔액 증가 + 거래 로그 기록 (같은 트랜잭션 내에서 커밋 -> 원자성 보장)
    db.session.execute(
        db.update(User).where(User.id == recipient.id).values(balance=User.balance + amount)
    )
    db.session.add(Transaction(from_user_id=sender_id, to_user_id=recipient.id, amount=amount, type='transfer'))
    db.session.commit()

    flash(f'{recipient.username}님에게 {amount:,}원을 송금했습니다.')
    return redirect(url_for('wallet'))


# ---------------------------------------------------------------------------
# 관리자 기능
#
# 등급: user(일반) < operator(운영자) < admin(최고관리자)
#  - operator: 유저/상품/신고 조회 및 정지·차단·신고 처리 가능
#  - admin   : operator 권한 전부 + 운영자 등급 부여/해제 가능
# ---------------------------------------------------------------------------
@app.route('/admin')
@role_required('operator')
def admin_dashboard():
    stats = {
        'user_count': User.query.count(),
        'suspended_count': User.query.filter_by(status='suspended').count(),
        'product_count': Product.query.count(),
        'blocked_count': Product.query.filter_by(status='blocked').count(),
        'report_count': Report.query.count(),
    }
    return render_template('admin_dashboard.html', stats=stats, user=current_user())


@app.route('/admin/users')
@role_required('operator')
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin_users.html', users=users, user=current_user())


@app.route('/admin/users/<user_id>/toggle-status', methods=['POST'])
@role_required('operator')
def admin_toggle_user_status(user_id):
    target = db.session.get(User, user_id)
    if not target:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('admin_users'))

    # 운영자/관리자는 다른 운영자·관리자의 상태를 변경할 수 없음 (일반 유저에게만 적용)
    if ROLE_RANK.get(target.role, 0) > 0:
        flash('운영자/관리자 계정은 이 화면에서 상태를 변경할 수 없습니다.')
        return redirect(url_for('admin_users'))

    target.status = 'suspended' if target.status == 'active' else 'active'
    db.session.commit()
    flash(f'{target.username}님의 상태가 {target.status}(으)로 변경되었습니다.')
    return redirect(url_for('admin_users'))


@app.route('/admin/products')
@role_required('operator')
def admin_products():
    products = Product.query.order_by(Product.created_at.desc()).all()
    return render_template('admin_products.html', products=products, user=current_user())


@app.route('/admin/products/<product_id>/toggle-status', methods=['POST'])
@role_required('operator')
def admin_toggle_product_status(product_id):
    product = db.session.get(Product, product_id)
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('admin_products'))

    product.status = 'active' if product.status == 'blocked' else 'blocked'
    db.session.commit()
    flash(f'상품 상태가 {product.status}(으)로 변경되었습니다.')
    return redirect(url_for('admin_products'))


@app.route('/admin/reports')
@role_required('operator')
def admin_reports():
    reports = Report.query.order_by(Report.created_at.desc()).limit(200).all()
    reporter_ids = {r.reporter_id for r in reports}
    reporters = {u.id: u.username for u in User.query.filter(User.id.in_(reporter_ids)).all()}
    return render_template('admin_reports.html', reports=reports, reporters=reporters, user=current_user())


@app.route('/admin/reports/<report_id>/dismiss', methods=['POST'])
@role_required('operator')
def admin_dismiss_report(report_id):
    r = db.session.get(Report, report_id)
    if not r:
        flash('신고를 찾을 수 없습니다.')
        return redirect(url_for('admin_reports'))
    # 감사 로그 보존을 위해 삭제하지 않고 상태만 변경한다.
    r.status = 'dismissed'
    db.session.commit()
    flash('신고가 처리(기각)되었습니다.')
    return redirect(url_for('admin_reports'))


@app.route('/admin/operators')
@role_required('admin')
def admin_operators():
    operators = User.query.filter(User.role.in_(['operator', 'admin'])).order_by(User.role.desc()).all()
    return render_template('admin_operators.html', operators=operators, user=current_user())


@app.route('/admin/operators/promote', methods=['POST'])
@role_required('admin')
def admin_promote_operator():
    username = (request.form.get('username') or '').strip()
    target = User.query.filter_by(username=username).first()
    if not target:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('admin_operators'))
    if target.role != 'user':
        flash('이미 운영자 이상 등급인 사용자입니다.')
        return redirect(url_for('admin_operators'))

    target.role = 'operator'
    db.session.commit()
    flash(f'{target.username}님을 운영자로 지정했습니다.')
    return redirect(url_for('admin_operators'))


@app.route('/admin/operators/<user_id>/demote', methods=['POST'])
@role_required('admin')
def admin_demote_operator(user_id):
    target = db.session.get(User, user_id)
    if not target:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('admin_operators'))

    if target.role == 'admin':
        # 마지막 남은 admin을 강등시켜 관리 기능이 전부 잠기는 상황 방지
        remaining_admins = User.query.filter_by(role='admin').count()
        if remaining_admins <= 1:
            flash('마지막 남은 최고관리자는 강등할 수 없습니다.')
            return redirect(url_for('admin_operators'))

    target.role = 'user'
    db.session.commit()
    flash(f'{target.username}님의 운영자 권한을 해제했습니다.')
    return redirect(url_for('admin_operators'))


# ---------------------------------------------------------------------------
# 에러 핸들링: 내부 정보(스택 트레이스 등) 노출 방지
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 보안 헤더
#
# 참고: script-src에 'unsafe-inline'을 포함한 이유 - 채팅 위젯 등에서 인라인
# <script> 블록을 사용하기 때문. 더 엄격하게 하려면 모든 인라인 스크립트를
# 외부 .js 파일로 분리하고 nonce 기반 CSP로 전환해야 한다 (향후 개선 과제로 명시).
# ---------------------------------------------------------------------------
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "connect-src 'self' ws: wss:;"
    )
    if os.environ.get('FLASK_ENV') == 'production':
        response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains'
    return response


@app.errorhandler(404)
def not_found(e):
    return render_template('index.html'), 404


@app.errorhandler(500)
def server_error(e):
    app.logger.exception('Internal server error')
    return "내부 서버 오류가 발생했습니다.", 500


# ---------------------------------------------------------------------------
# 관리자 CLI 명령
#   최초 admin 계정 지정은 웹 라우트로 제공하지 않고(권한 상승 공격 표면 제거)
#   서버 운영자만 접근 가능한 CLI로 제공한다.
#   사용법: flask --app app.py create-admin <username>
# ---------------------------------------------------------------------------
@app.cli.command('create-admin')
def create_admin_command():
    import click
    username = click.prompt('관리자로 지정할 사용자명')
    user = User.query.filter_by(username=username).first()
    if not user:
        click.echo(f'사용자 "{username}"을(를) 찾을 수 없습니다.')
        return
    user.role = 'admin'
    db.session.commit()
    click.echo(f'"{username}"을(를) 최고관리자로 지정했습니다.')


if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    # 주의: allow_unsafe_werkzeug는 로컬 개발/과제 테스트 용도. 운영 배포 시에는
    # gunicorn + eventlet(또는 gevent) 등 프로덕션 WSGI 서버 사용을 권장.
    socketio.run(app, debug=debug_mode, allow_unsafe_werkzeug=True)
