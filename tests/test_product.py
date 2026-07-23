from conftest import get_csrf, register_and_login


def add_product(client, title, price, description="desc"):
    csrf = get_csrf(client, "/product/new")
    return client.post("/product/new", data={
        "csrf_token": csrf, "title": title, "description": description, "price": price
    }, follow_redirects=True)


class TestProduct:
    def test_price_must_be_numeric(self, client):
        register_and_login(client, "p_user1", "Passw0rd1")
        resp = add_product(client, "Item", "abc")
        assert "가격은 숫자로" in resp.get_data(as_text=True)

    def test_price_range_enforced(self, client):
        register_and_login(client, "p_user2", "Passw0rd1")
        resp = add_product(client, "Item", 999999999)
        assert "이하로 입력해주세요" in resp.get_data(as_text=True)

    def test_owner_only_can_edit(self, client, app_module):
        register_and_login(client, "owner1", "Passw0rd1")
        add_product(client, "OwnedItem", 1000)

        with app_module.app.app_context():
            product = app_module.Product.query.filter_by(title="OwnedItem").first()
            pid = product.id

        # 다른 클라이언트(세션)로 로그인
        with app_module.app.test_client() as other_client:
            register_and_login(other_client, "notowner1", "Passw0rd1")
            resp = other_client.get(f"/product/{pid}/edit", follow_redirects=True)
            assert "본인이 등록한 상품만 수정할 수 있습니다" in resp.get_data(as_text=True)

    def test_owner_only_can_delete(self, client, app_module):
        register_and_login(client, "owner2", "Passw0rd1")
        add_product(client, "OwnedItem2", 1000)

        with app_module.app.app_context():
            product = app_module.Product.query.filter_by(title="OwnedItem2").first()
            pid = product.id

        with app_module.app.test_client() as other_client:
            register_and_login(other_client, "notowner2", "Passw0rd1")
            csrf = get_csrf(other_client, "/product/new")
            resp = other_client.post(f"/product/{pid}/delete", data={"csrf_token": csrf}, follow_redirects=True)
            assert "본인이 등록한 상품만 삭제할 수 있습니다" in resp.get_data(as_text=True)

        with app_module.app.app_context():
            assert app_module.db.session.get(app_module.Product, pid) is not None

    def test_blocked_product_hidden_from_others(self, client, app_module):
        register_and_login(client, "blockedowner", "Passw0rd1")
        add_product(client, "BlockedItem", 1000)

        with app_module.app.app_context():
            product = app_module.Product.query.filter_by(title="BlockedItem").first()
            product.status = "blocked"
            app_module.db.session.commit()
            pid = product.id

        with app_module.app.test_client() as other_client:
            register_and_login(other_client, "outsider1", "Passw0rd1")
            resp = other_client.get(f"/product/{pid}", follow_redirects=True)
            assert "찾을 수 없습니다" in resp.get_data(as_text=True)
