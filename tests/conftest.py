import os
import tempfile
import re
import importlib
import sys

import pytest


@pytest.fixture
def app_module(tmp_path, monkeypatch):
    """각 테스트마다 독립된 SQLite DB로 앱 모듈을 새로 로드한다."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("FLASK_TESTING", "1")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")

    # app 모듈을 매번 새로 import해서 모듈 전역 상태(rate-limit dict 등)를 초기화
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if "app" in sys.modules:
        del sys.modules["app"]
    if "models" in sys.modules:
        del sys.modules["models"]
    import app as app_mod
    app_mod.app.config['WTF_CSRF_ENABLED'] = True
    yield app_mod


@pytest.fixture
def client(app_module):
    app_module.app.config['TESTING'] = True
    return app_module.app.test_client()


def get_csrf(client, url):
    resp = client.get(url)
    m = re.search(r'name="csrf_token" value="([^"]+)"', resp.get_data(as_text=True))
    assert m, f"{url} 페이지에서 csrf_token을 찾지 못함"
    return m.group(1)


def register(client, username, password):
    csrf = get_csrf(client, "/register")
    return client.post("/register", data={"csrf_token": csrf, "username": username, "password": password},
                        follow_redirects=True)


def login(client, username, password):
    csrf = get_csrf(client, "/login")
    return client.post("/login", data={"csrf_token": csrf, "username": username, "password": password},
                        follow_redirects=True)


def register_and_login(client, username, password):
    register(client, username, password)
    return login(client, username, password)
