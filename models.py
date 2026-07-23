"""
데이터베이스 모델 정의 (Flask-SQLAlchemy)

- 보안 체크리스트 '전체 시스템 > ORM 및 파라미터 바인딩' 항목 반영:
  raw sqlite3 쿼리 대신 SQLAlchemy ORM을 사용하여 SQL Injection 표면을 최소화한다.
"""
import uuid
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def gen_uuid():
    return str(uuid.uuid4())


class User(db.Model):
    __tablename__ = "user"

    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)
    username = db.Column(db.String(20), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    bio = db.Column(db.String(500), default="")

    # 권한 / 상태 관리
    role = db.Column(db.String(10), nullable=False, default="user")  # user / operator / admin
    status = db.Column(db.String(10), nullable=False, default="active")  # active / suspended

    # 잔액 (송금 기능에서 사용, 음수 방지는 애플리케이션 레벨에서 트랜잭션으로 보장)
    balance = db.Column(db.Integer, nullable=False, default=0)

    # 로그인 실패 방어용
    failed_attempts = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    products = db.relationship("Product", backref="seller", lazy=True)


class Product(db.Model):
    __tablename__ = "product"

    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(2000), nullable=False)
    price = db.Column(db.Integer, nullable=False)  # 정수(원 단위)로 저장, 서버측에서 숫자 검증
    seller_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    status = db.Column(db.String(10), nullable=False, default="active")  # active / sold / blocked
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Report(db.Model):
    __tablename__ = "report"

    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)
    reporter_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    target_type = db.Column(db.String(10), nullable=False)  # user / product
    target_id = db.Column(db.String(36), nullable=False)
    reason = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(10), nullable=False, default="open")  # open / dismissed / actioned
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Transaction(db.Model):
    __tablename__ = "transaction"

    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)
    from_user_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=True)  # 충전이면 NULL
    to_user_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    type = db.Column(db.String(10), nullable=False)  # charge / transfer
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Message(db.Model):
    __tablename__ = "message"

    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)
    room_type = db.Column(db.String(10), nullable=False)  # all / dm
    room_id = db.Column(db.String(80), nullable=False)  # dm인 경우 정렬된 두 user_id 조합
    sender_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    sender = db.relationship("User")
