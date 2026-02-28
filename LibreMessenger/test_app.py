from pathlib import Path

from LibreMessenger.app import create_app


def _register(client, username: str, password: str) -> None:
    response = client.post(
        "/register",
        data={"username": username, "password": password},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Account created" in response.data


def _login(client, username: str, password: str) -> None:
    response = client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Welcome back" in response.data


def _logout(client) -> None:
    response = client.post("/logout", follow_redirects=True)
    assert response.status_code == 200


def test_cross_user_encryption_and_sender_local_copy(tmp_path: Path):
    app = create_app(data_dir=tmp_path)
    app.config.update(TESTING=True)
    client = app.test_client()

    _register(client, "alice", "Password123!")
    _register(client, "bob", "Password123!")

    _login(client, "alice", "Password123!")
    send_response = client.post(
        "/messages/send",
        data={"recipient": "bob", "message": "hello bob from alice"},
        follow_redirects=True,
    )
    assert send_response.status_code == 200
    assert b"Message sent." in send_response.data

    # Alice should be able to decrypt her sender-side encrypted copy.
    assert b"hello bob from alice" in send_response.data
    _logout(client)

    # Bob should decrypt using bob private + alice public.
    _login(client, "bob", "Password123!")
    inbox_response = client.get("/messages?dm=alice")
    assert inbox_response.status_code == 200
    assert b"hello bob from alice" in inbox_response.data

