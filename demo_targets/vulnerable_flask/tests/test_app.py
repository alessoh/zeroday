"""
Minimal test suite for the vulnerable-flask demo application.

These tests verify the application's basic behaviour and serve as the
test harness that ZeroDay's test_runner stage will execute after applying
a generated patch.
"""

import pytest
from app import app as flask_app


@pytest.fixture()
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        yield c


def test_index_returns_200(client):
    resp = client.get("/")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "running"


def test_ping(client):
    resp = client.get("/ping")
    assert resp.status_code == 200
    assert resp.get_json()["pong"] is True


def test_register_valid_email(client):
    resp = client.post(
        "/register",
        json={"username": "alice", "email": "alice@example.com"},
    )
    assert resp.status_code == 200
    assert resp.get_json()["registered"] is True


def test_register_invalid_email_returns_422(client):
    resp = client.post(
        "/register",
        json={"username": "bob", "email": "not-an-email"},
    )
    assert resp.status_code == 422
    assert resp.get_json()["registered"] is False


def test_register_missing_fields_returns_422(client):
    resp = client.post("/register", json={"username": "charlie"})
    assert resp.status_code == 422
