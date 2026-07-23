from conftest import get_csrf, register_and_login


def make_admin(app_module, username):
    with app_module.app.app_context():
        user = app_module.User.query.filter_by(username=username).first()
        user.role = "admin"
        app_module.db.session.commit()


def make_operator(app_module, username):
    with app_module.app.app_context():
        user = app_module.User.query.filter_by(username=username).first()
        user.role = "operator"
        app_module.db.session.commit()


class TestAdmin:
    def test_regular_user_cannot_access_admin(self, client):
        register_and_login(client, "a_plain1", "Passw0rd1")
        resp = client.get("/admin", follow_redirects=True)
        assert "접근 권한이 없습니다" in resp.get_data(as_text=True)

    def test_operator_can_access_dashboard_but_not_operator_page(self, client, app_module):
        register_and_login(client, "a_op1", "Passw0rd1")
        make_operator(app_module, "a_op1")

        resp = client.get("/admin")
        assert "관리자 대시보드" in resp.get_data(as_text=True)

        resp = client.get("/admin/operators", follow_redirects=True)
        assert "접근 권한이 없습니다" in resp.get_data(as_text=True)

    def test_operator_cannot_promote_others(self, client, app_module):
        register_and_login(client, "a_op2", "Passw0rd1")
        make_operator(app_module, "a_op2")
        register_and_login(client, "a_target1", "Passw0rd1")  # 세션이 target으로 바뀜
        register_and_login(client, "a_op2", "Passw0rd1")  # 다시 operator로 로그인

        csrf = get_csrf(client, "/admin/users")
        resp = client.post("/admin/operators/promote",
                            data={"csrf_token": csrf, "username": "a_target1"},
                            follow_redirects=True)
        assert "접근 권한이 없습니다" in resp.get_data(as_text=True)

        with app_module.app.app_context():
            target = app_module.User.query.filter_by(username="a_target1").first()
            assert target.role == "user"

    def test_admin_can_promote_and_demote_operator(self, client, app_module):
        register_and_login(client, "a_admin1", "Passw0rd1")
        make_admin(app_module, "a_admin1")
        register_and_login(client, "a_target2", "Passw0rd1")
        register_and_login(client, "a_admin1", "Passw0rd1")

        csrf = get_csrf(client, "/admin/users")
        client.post("/admin/operators/promote", data={"csrf_token": csrf, "username": "a_target2"},
                    follow_redirects=True)

        with app_module.app.app_context():
            target = app_module.User.query.filter_by(username="a_target2").first()
            assert target.role == "operator"
            target_id = target.id

        csrf = get_csrf(client, "/admin/operators")
        client.post(f"/admin/operators/{target_id}/demote", data={"csrf_token": csrf}, follow_redirects=True)

        with app_module.app.app_context():
            target = app_module.User.query.filter_by(username="a_target2").first()
            assert target.role == "user"

    def test_last_admin_cannot_be_demoted(self, client, app_module):
        register_and_login(client, "a_admin2", "Passw0rd1")
        make_admin(app_module, "a_admin2")

        with app_module.app.app_context():
            admin_user = app_module.User.query.filter_by(username="a_admin2").first()
            admin_id = admin_user.id

        csrf = get_csrf(client, "/admin/operators")
        resp = client.post(f"/admin/operators/{admin_id}/demote", data={"csrf_token": csrf},
                            follow_redirects=True)
        assert "마지막 남은 최고관리자는 강등할 수 없습니다" in resp.get_data(as_text=True)

    def test_operator_cannot_suspend_other_operator_or_admin(self, client, app_module):
        register_and_login(client, "a_op3", "Passw0rd1")
        make_operator(app_module, "a_op3")
        register_and_login(client, "a_admin3", "Passw0rd1")
        make_admin(app_module, "a_admin3")

        with app_module.app.app_context():
            admin_id = app_module.User.query.filter_by(username="a_admin3").first().id

        register_and_login(client, "a_op3", "Passw0rd1")
        csrf = get_csrf(client, "/report")
        resp = client.post(f"/admin/users/{admin_id}/toggle-status", data={"csrf_token": csrf},
                            follow_redirects=True)
        assert "이 화면에서 상태를 변경할 수 없습니다" in resp.get_data(as_text=True)

    def test_suspended_user_blocked_after_admin_action(self, client, app_module):
        register_and_login(client, "a_op4", "Passw0rd1")
        make_operator(app_module, "a_op4")
        register_and_login(client, "a_victim1", "Passw0rd1")
        register_and_login(client, "a_op4", "Passw0rd1")

        with app_module.app.app_context():
            victim_id = app_module.User.query.filter_by(username="a_victim1").first().id

        csrf = get_csrf(client, "/admin/users")
        client.post(f"/admin/users/{victim_id}/toggle-status", data={"csrf_token": csrf}, follow_redirects=True)

        other = app_module.app.test_client()
        csrf = get_csrf(other, "/login")
        resp = other.post("/login", data={"csrf_token": csrf, "username": "a_victim1", "password": "Passw0rd1"},
                           follow_redirects=True)
        assert "비활성화된 계정" in resp.get_data(as_text=True)

    def test_admin_can_block_product(self, client, app_module):
        register_and_login(client, "a_seller1", "Passw0rd1")
        csrf = get_csrf(client, "/product/new")
        client.post("/product/new", data={
            "csrf_token": csrf, "title": "AdminBlockItem", "description": "d", "price": 1000
        })
        register_and_login(client, "a_admin4", "Passw0rd1")
        make_admin(app_module, "a_admin4")
        register_and_login(client, "a_admin4", "Passw0rd1")

        with app_module.app.app_context():
            pid = app_module.Product.query.filter_by(title="AdminBlockItem").first().id

        csrf = get_csrf(client, "/admin/products")
        client.post(f"/admin/products/{pid}/toggle-status", data={"csrf_token": csrf}, follow_redirects=True)

        with app_module.app.app_context():
            product = app_module.db.session.get(app_module.Product, pid)
            assert product.status == "blocked"
