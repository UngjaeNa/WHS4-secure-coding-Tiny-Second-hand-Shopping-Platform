from conftest import get_csrf, register_and_login


def add_product(client, title, price, description="desc"):
    csrf = get_csrf(client, "/product/new")
    return client.post("/product/new", data={
        "csrf_token": csrf, "title": title, "description": description, "price": price
    }, follow_redirects=True)


class TestReport:
    def test_report_nonexistent_target_rejected(self, client):
        register_and_login(client, "rep_user1", "Passw0rd1")
        csrf = get_csrf(client, "/report")
        resp = client.post("/report", data={
            "csrf_token": csrf, "target_type": "product", "target_id": "no-such-id", "reason": "test"
        }, follow_redirects=True)
        assert "찾을 수 없습니다" in resp.get_data(as_text=True)

    def test_self_product_report_rejected(self, client, app_module):
        register_and_login(client, "rep_seller1", "Passw0rd1")
        add_product(client, "SelfReportItem", 1000)
        with app_module.app.app_context():
            pid = app_module.Product.query.filter_by(title="SelfReportItem").first().id

        csrf = get_csrf(client, "/report")
        resp = client.post("/report", data={
            "csrf_token": csrf, "target_type": "product", "target_id": pid, "reason": "test"
        }, follow_redirects=True)
        assert "본인이 등록한 상품은 신고할 수 없습니다" in resp.get_data(as_text=True)

    def test_duplicate_report_rejected(self, client, app_module):
        register_and_login(client, "rep_seller2", "Passw0rd1")
        add_product(client, "DupReportItem", 1000)
        with app_module.app.app_context():
            pid = app_module.Product.query.filter_by(title="DupReportItem").first().id

        with app_module.app.test_client() as reporter:
            register_and_login(reporter, "rep_user2", "Passw0rd1")
            csrf = get_csrf(reporter, "/report")
            reporter.post("/report", data={
                "csrf_token": csrf, "target_type": "product", "target_id": pid, "reason": "first"
            }, follow_redirects=True)
            csrf = get_csrf(reporter, "/report")
            resp = reporter.post("/report", data={
                "csrf_token": csrf, "target_type": "product", "target_id": pid, "reason": "second"
            }, follow_redirects=True)
            assert "이미 신고한 대상입니다" in resp.get_data(as_text=True)

    def test_report_threshold_auto_blocks_product(self, client, app_module):
        register_and_login(client, "rep_seller3", "Passw0rd1")
        add_product(client, "ThresholdItem", 1000)
        with app_module.app.app_context():
            pid = app_module.Product.query.filter_by(title="ThresholdItem").first().id

        for i in range(app_module.REPORT_BLOCK_THRESHOLD):
            with app_module.app.test_client() as reporter:
                register_and_login(reporter, f"rep_thresh_{i}", "Passw0rd1")
                csrf = get_csrf(reporter, "/report")
                reporter.post("/report", data={
                    "csrf_token": csrf, "target_type": "product", "target_id": pid, "reason": f"reason{i}"
                }, follow_redirects=True)

        with app_module.app.app_context():
            product = app_module.db.session.get(app_module.Product, pid)
            assert product.status == "blocked"

    def test_dismiss_report_keeps_audit_record(self, client, app_module):
        register_and_login(client, "rep_seller4", "Passw0rd1")
        add_product(client, "AuditItem", 1000)
        with app_module.app.app_context():
            pid = app_module.Product.query.filter_by(title="AuditItem").first().id

        with app_module.app.test_client() as reporter:
            register_and_login(reporter, "rep_user4", "Passw0rd1")
            csrf = get_csrf(reporter, "/report")
            reporter.post("/report", data={
                "csrf_token": csrf, "target_type": "product", "target_id": pid, "reason": "audit test"
            }, follow_redirects=True)

        with app_module.app.app_context():
            report = app_module.Report.query.filter_by(reason="audit test").first()
            report_id = report.id
            admin_user = app_module.User.query.filter_by(username="rep_seller4").first()
            admin_user.role = "admin"
            app_module.db.session.commit()

        with app_module.app.test_client() as admin_client:
            from conftest import login as do_login
            do_login(admin_client, "rep_seller4", "Passw0rd1")
            csrf = get_csrf(admin_client, "/admin/reports")
            admin_client.post(f"/admin/reports/{report_id}/dismiss", data={"csrf_token": csrf},
                               follow_redirects=True)

        with app_module.app.app_context():
            report = app_module.db.session.get(app_module.Report, report_id)
            assert report is not None  # 삭제되지 않고 남아있어야 함 (감사 로그)
            assert report.status == "dismissed"
