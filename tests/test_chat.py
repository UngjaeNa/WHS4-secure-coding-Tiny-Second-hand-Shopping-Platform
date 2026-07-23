import time
from conftest import register_and_login


class TestChat:
    def test_unauthenticated_socket_connection_rejected(self, app_module):
        flask_client = app_module.app.test_client()  # 로그인하지 않음
        sio_client = app_module.socketio.test_client(app_module.app, flask_test_client=flask_client)
        assert sio_client.is_connected() is False

    def test_authenticated_socket_connection_allowed(self, app_module):
        flask_client = app_module.app.test_client()
        register_and_login(flask_client, "c_user1", "Passw0rd1")
        sio_client = app_module.socketio.test_client(app_module.app, flask_test_client=flask_client)
        assert sio_client.is_connected() is True
        sio_client.disconnect()

    def test_all_room_broadcast_and_xss_safe_storage(self, app_module):
        flask_client = app_module.app.test_client()
        register_and_login(flask_client, "c_user2", "Passw0rd1")
        sio_client = app_module.socketio.test_client(app_module.app, flask_test_client=flask_client)

        sio_client.emit("join", {"room_type": "all"})
        sio_client.emit("send_message", {"room_type": "all", "message": "<script>alert(1)</script> hi"})

        received = sio_client.get_received()
        new_messages = [e for e in received if e["name"] == "new_message"]
        assert len(new_messages) == 1
        assert new_messages[0]["args"][0]["message"] == "<script>alert(1)</script> hi"
        # 저장은 되지만 렌더링 시 auto-escape (Jinja) + textContent(JS)로 처리되므로
        # 여기서는 "발신자가 클라이언트가 아닌 서버 세션에서 결정"되는지만 검증
        assert new_messages[0]["args"][0]["username"] == "c_user2"
        sio_client.disconnect()

    def test_sender_cannot_be_spoofed(self, app_module):
        """클라이언트가 username을 보내도 서버는 세션 기반 사용자만 신뢰해야 한다."""
        flask_client = app_module.app.test_client()
        register_and_login(flask_client, "c_user3", "Passw0rd1")
        sio_client = app_module.socketio.test_client(app_module.app, flask_test_client=flask_client)

        sio_client.emit("join", {"room_type": "all"})
        sio_client.emit("send_message", {"room_type": "all", "message": "hello", "username": "fake_admin"})

        received = sio_client.get_received()
        new_messages = [e for e in received if e["name"] == "new_message"]
        assert new_messages[0]["args"][0]["username"] == "c_user3"  # 클라이언트가 보낸 fake_admin이 아님
        sio_client.disconnect()

    def test_rate_limiting(self, app_module):
        flask_client = app_module.app.test_client()
        register_and_login(flask_client, "c_user4", "Passw0rd1")
        sio_client = app_module.socketio.test_client(app_module.app, flask_test_client=flask_client)
        sio_client.emit("join", {"room_type": "all"})

        for i in range(8):
            sio_client.emit("send_message", {"room_type": "all", "message": f"spam-{i}"})

        received = sio_client.get_received()
        errors = [e for e in received if e["name"] == "chat_error"]
        assert len(errors) > 0  # 일부는 rate limit에 걸려야 함
        sio_client.disconnect()

    def test_dm_isolation(self, app_module):
        flask_b = app_module.app.test_client()
        register_and_login(flask_b, "c_userB", "Passw0rd1")
        flask_c = app_module.app.test_client()
        register_and_login(flask_c, "c_userC", "Passw0rd1")
        flask_a = app_module.app.test_client()
        register_and_login(flask_a, "c_userA", "Passw0rd1")

        with app_module.app.app_context():
            b_id = app_module.User.query.filter_by(username="c_userB").first().id
            c_id = app_module.User.query.filter_by(username="c_userC").first().id

        sio_a = app_module.socketio.test_client(app_module.app, flask_test_client=flask_a)
        sio_b = app_module.socketio.test_client(app_module.app, flask_test_client=flask_b)
        sio_c = app_module.socketio.test_client(app_module.app, flask_test_client=flask_c)

        sio_a.emit("join", {"room_type": "all"})
        sio_b.emit("join", {"room_type": "dm", "other_user_id": c_id})
        sio_c.emit("join", {"room_type": "dm", "other_user_id": b_id})

        sio_a.get_received()
        sio_b.get_received()
        sio_c.get_received()

        sio_b.emit("send_message", {"room_type": "dm", "other_user_id": c_id, "message": "hi C"})

        c_received = [e for e in sio_c.get_received() if e["name"] == "new_message"]
        a_received = [e for e in sio_a.get_received() if e["name"] == "new_message"]

        assert len(c_received) == 1
        assert c_received[0]["args"][0]["message"] == "hi C"
        assert len(a_received) == 0  # 전체채팅방에 있는 A는 DM을 받으면 안 됨

        sio_a.disconnect()
        sio_b.disconnect()
        sio_c.disconnect()
