import threading
from conftest import get_csrf, register_and_login


class TestWallet:
    def test_transfer_without_balance_rejected(self, client):
        register_and_login(client, "w_sender1", "Passw0rd1")
        register_and_login(client, "w_recv1", "Passw0rd1")  # 세션이 recv로 덮어써지지만 유저 생성 목적
        register_and_login(client, "w_sender1", "Passw0rd1")  # 다시 sender로 로그인

        csrf = get_csrf(client, "/wallet")
        resp = client.post("/wallet/transfer", data={
            "csrf_token": csrf, "recipient": "w_recv1", "amount": 1000
        }, follow_redirects=True)
        assert "잔액이 부족합니다" in resp.get_data(as_text=True)

    def test_charge_and_transfer_success(self, client):
        register_and_login(client, "w_recv2", "Passw0rd1")
        register_and_login(client, "w_sender2", "Passw0rd1")

        csrf = get_csrf(client, "/wallet")
        client.post("/wallet/charge", data={"csrf_token": csrf, "amount": 1000})
        csrf = get_csrf(client, "/wallet")
        resp = client.post("/wallet/transfer", data={
            "csrf_token": csrf, "recipient": "w_recv2", "amount": 1000
        }, follow_redirects=True)
        assert "송금했습니다" in resp.get_data(as_text=True)

    def test_charge_amount_range_validated(self, client):
        register_and_login(client, "w_charge1", "Passw0rd1")
        csrf = get_csrf(client, "/wallet")
        resp = client.post("/wallet/charge", data={"csrf_token": csrf, "amount": 99999999},
                            follow_redirects=True)
        assert "이하만 가능합니다" in resp.get_data(as_text=True)

    def test_self_transfer_rejected(self, client):
        register_and_login(client, "w_self1", "Passw0rd1")
        csrf = get_csrf(client, "/wallet")
        client.post("/wallet/charge", data={"csrf_token": csrf, "amount": 1000})
        csrf = get_csrf(client, "/wallet")
        resp = client.post("/wallet/transfer", data={
            "csrf_token": csrf, "recipient": "w_self1", "amount": 100
        }, follow_redirects=True)
        assert "본인에게는 송금할 수 없습니다" in resp.get_data(as_text=True)

    def test_transfer_to_nonexistent_user_rejected(self, client):
        register_and_login(client, "w_user1", "Passw0rd1")
        csrf = get_csrf(client, "/wallet")
        resp = client.post("/wallet/transfer", data={
            "csrf_token": csrf, "recipient": "no_such_user_xyz", "amount": 100
        }, follow_redirects=True)
        assert "받는 사람을 찾을 수 없습니다" in resp.get_data(as_text=True)

    def test_concurrent_transfer_race_condition_safe(self, app_module):
        """잔액 500원 상태에서 500원씩 동시에 2번 송금 -> 정확히 1건만 성공, 잔액은 음수가 되지 않아야 함."""
        with app_module.app.test_client() as sender:
            register_and_login(sender, "race_sender", "Passw0rd1")
        with app_module.app.test_client() as r1:
            register_and_login(r1, "race_recv1", "Passw0rd1")
        with app_module.app.test_client() as r2:
            register_and_login(r2, "race_recv2", "Passw0rd1")

        sender = app_module.app.test_client()
        register_and_login(sender, "race_sender", "Passw0rd1")
        csrf = get_csrf(sender, "/wallet")
        sender.post("/wallet/charge", data={"csrf_token": csrf, "amount": 500})

        results = []

        def do_transfer(recipient_name):
            local_client = app_module.app.test_client()
            register_and_login(local_client, "race_sender", "Passw0rd1")
            csrf_local = get_csrf(local_client, "/wallet")
            r = local_client.post("/wallet/transfer", data={
                "csrf_token": csrf_local, "recipient": recipient_name, "amount": 500
            }, follow_redirects=True)
            results.append("송금했습니다" in r.get_data(as_text=True))

        t1 = threading.Thread(target=do_transfer, args=("race_recv1",))
        t2 = threading.Thread(target=do_transfer, args=("race_recv2",))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        with app_module.app.app_context():
            sender_user = app_module.User.query.filter_by(username="race_sender").first()
            assert sender_user.balance >= 0
            assert results.count(True) == 1
            assert sender_user.balance == 0
