from conftest import get_csrf, register, login, register_and_login


class TestAuth:
    def test_csrf_required_for_register(self, client):
        resp = client.post("/register", data={"username": "nocsrf", "password": "Passw0rd1"})
        assert resp.status_code == 400

    def test_weak_password_rejected(self, client):
        csrf = get_csrf(client, "/register")
        resp = client.post("/register", data={"csrf_token": csrf, "username": "weakpw", "password": "1234"},
                            follow_redirects=True)
        assert "8자 이상" in resp.get_data(as_text=True)

    def test_invalid_username_rejected(self, client):
        csrf = get_csrf(client, "/register")
        resp = client.post("/register", data={"csrf_token": csrf, "username": "a", "password": "Passw0rd1"},
                            follow_redirects=True)
        assert "영문, 숫자, 밑줄" in resp.get_data(as_text=True)

    def test_duplicate_username_rejected(self, client):
        register(client, "dupuser", "Passw0rd1")
        csrf = get_csrf(client, "/register")
        resp = client.post("/register", data={"csrf_token": csrf, "username": "dupuser", "password": "Passw0rd1"},
                            follow_redirects=True)
        assert "이미 존재하는" in resp.get_data(as_text=True)

    def test_password_is_hashed(self, client, app_module):
        register(client, "hashcheck", "Passw0rd1")
        with app_module.app.app_context():
            user = app_module.User.query.filter_by(username="hashcheck").first()
            assert user.password_hash != "Passw0rd1"
            assert user.password_hash.startswith("$2b$")  # bcrypt 해시 형식

    def test_login_success_and_session_cookie_flags(self, client):
        register(client, "loginuser", "Passw0rd1")
        csrf = get_csrf(client, "/login")
        resp = client.post("/login", data={"csrf_token": csrf, "username": "loginuser", "password": "Passw0rd1"})
        set_cookie = resp.headers.get("Set-Cookie", "")
        assert "HttpOnly" in set_cookie
        assert "SameSite=Lax" in set_cookie

    def test_login_failure_generic_message(self, client):
        register(client, "genericmsg", "Passw0rd1")
        csrf = get_csrf(client, "/login")
        resp = client.post("/login", data={"csrf_token": csrf, "username": "genericmsg", "password": "wrongpass"},
                            follow_redirects=True)
        text = resp.get_data(as_text=True)
        assert "아이디 또는 비밀번호가 올바르지 않습니다" in text

        csrf = get_csrf(client, "/login")
        resp2 = client.post("/login", data={"csrf_token": csrf, "username": "no_such_user", "password": "x"},
                            follow_redirects=True)
        text2 = resp2.get_data(as_text=True)
        # 존재하지 않는 계정과 비밀번호 오류가 동일한 메시지를 반환해야 함 (계정 존재 여부 노출 방지)
        assert "아이디 또는 비밀번호가 올바르지 않습니다" in text2

    def test_account_lockout_after_failed_attempts(self, client, app_module):
        register(client, "lockoutuser", "Passw0rd1")
        for _ in range(5):
            csrf = get_csrf(client, "/login")
            client.post("/login", data={"csrf_token": csrf, "username": "lockoutuser", "password": "wrong"})

        csrf = get_csrf(client, "/login")
        resp = client.post("/login", data={"csrf_token": csrf, "username": "lockoutuser", "password": "Passw0rd1"},
                            follow_redirects=True)
        assert "로그인 시도가 너무 많" in resp.get_data(as_text=True)

    def test_change_password_requires_current_password(self, client):
        register_and_login(client, "pwchange", "Passw0rd1")
        csrf = get_csrf(client, "/profile")
        resp = client.post("/profile/password", data={
            "csrf_token": csrf, "current_password": "wrongcurrent", "new_password": "NewPassw0rd1"
        }, follow_redirects=True)
        assert "현재 비밀번호가 올바르지 않습니다" in resp.get_data(as_text=True)

    def test_dashboard_requires_login(self, client):
        resp = client.get("/dashboard", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]
