from conftest import get_csrf, register_and_login


def add_product(client, title, price, description="desc"):
    csrf = get_csrf(client, "/product/new")
    return client.post("/product/new", data={
        "csrf_token": csrf, "title": title, "description": description, "price": price
    }, follow_redirects=True)


class TestSearch:
    def test_keyword_search(self, client):
        register_and_login(client, "s_seller_a", "Passw0rd1")
        add_product(client, "Nice Laptop", 500000)
        add_product(client, "50% off Chair", 20000)

        resp = client.get("/search", query_string={"q": "Laptop"})
        text = resp.get_data(as_text=True)
        assert "Nice Laptop" in text
        assert "Chair" not in text

    def test_sql_injection_payload_is_harmless(self, client, app_module):
        register_and_login(client, "s_seller_b", "Passw0rd1")
        add_product(client, "SafeItem", 1000)

        for payload in ["' OR '1'='1", "'; DROP TABLE product; --"]:
            resp = client.get("/search", query_string={"q": payload})
            assert resp.status_code == 200
            # 전체 상품이 노출되면 안 됨 (SafeItem이 페이로드와 무관하게 매칭되지 않아야 함)
            assert "SafeItem" not in resp.get_data(as_text=True)

        with app_module.app.app_context():
            # 테이블이 실제로 삭제되지 않았는지 확인
            assert app_module.Product.query.count() >= 1

    def test_wildcard_percent_is_escaped(self, client):
        register_and_login(client, "s_seller_c", "Passw0rd1")
        add_product(client, "Nice Laptop", 500000)
        add_product(client, "50% off Chair", 20000)

        resp = client.get("/search", query_string={"q": "%"})
        text = resp.get_data(as_text=True)
        assert "50% off Chair" in text
        assert "Nice Laptop" not in text

    def test_price_range_filter(self, client):
        register_and_login(client, "s_seller_d", "Passw0rd1")
        add_product(client, "Cheap Item", 5000)
        add_product(client, "Expensive Item", 900000)

        resp = client.get("/search", query_string={"min_price": 1000, "max_price": 10000})
        text = resp.get_data(as_text=True)
        assert "Cheap Item" in text
        assert "Expensive Item" not in text

    def test_search_requires_login(self, client):
        resp = client.get("/search", query_string={"q": "x"}, follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_blocked_product_not_searchable(self, client, app_module):
        register_and_login(client, "s_seller_e", "Passw0rd1")
        add_product(client, "BlockedSearchItem", 1000)
        with app_module.app.app_context():
            p = app_module.Product.query.filter_by(title="BlockedSearchItem").first()
            p.status = "blocked"
            app_module.db.session.commit()

        resp = client.get("/search", query_string={"q": "BlockedSearchItem"})
        # 검색창에 입력값 자체는 echo될 수 있으므로, 실제 결과 링크(<a>...</a>) 형태로만 검증
        assert ">BlockedSearchItem</a>" not in resp.get_data(as_text=True)
