import os
import tempfile

_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_db.close()
os.environ["DATABASE_URL"] = "sqlite:///" + _db.name
os.environ["JWT_SECRET"] = "test-secret-that-is-long-enough-for-testing-only"
os.environ["UPSTREAM_URL"] = "http://127.0.0.1:9/v1"

from fastapi.testclient import TestClient
from sqlalchemy import insert
import main
from main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"

def test_dashboard_and_auth_status():
    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert "RAG Security Gateway" in dashboard.text
    assert 'id="show-signup">Sign up' in dashboard.text
    assert 'id="show-signin">Sign in' in dashboard.text
    assert "Ctrl K" not in dashboard.text
    response = client.get("/auth/status")
    assert response.status_code == 200
    assert response.json() == {"admin_exists": False, "public_signup": True}


def test_auth_required_for_scan():
    response = client.post("/scan", files={"f": ("x.txt", b"hello", "text/plain")})
    assert response.status_code == 401


def test_public_signup_creates_viewer_and_scopes_document_access():
    too_short = client.post("/auth/register", json={"email": "short-test@example.com", "password": "Short8"})
    assert too_short.status_code == 422
    response = client.post("/auth/register", json={"email": "admin-test@example.com", "password": "Admin123"})
    assert response.status_code == 200
    assert response.json()["role"] == "admin"
    assert client.get("/auth/status").json() == {"admin_exists": True, "public_signup": True}
    second = client.post("/auth/register", json={"email": "other-test@example.com", "password": "correct-horse-battery-10"})
    assert second.status_code == 200
    assert second.json()["role"] == "viewer"
    viewer_login = client.post("/auth/login", json={"email": "other-test@example.com", "password": "correct-horse-battery-10"})
    assert viewer_login.status_code == 200
    viewer_headers = {"Authorization": f"Bearer {viewer_login.json()['token']}"}

    with main.DB.begin() as conn:
        own = conn.execute(insert(main.docs).values(
            name="own.txt", owner="other-test@example.com", risk=40,
            findings='[{"cat":"pii","label":"Email address","count":1,"evidence":["use••••••"]}]',
            body="Contact [REDACTED:pii].", sha256="a" * 64, created_at="2026-01-01T00:00:00+00:00",
        )).inserted_primary_key[0]
        conn.execute(insert(main.docs).values(
            name="admin.txt", owner="admin-test@example.com", risk=0,
            findings="[]", body="Admin-only document.", sha256="b" * 64, created_at="2026-01-01T00:00:00+00:00",
        ))

    listing = client.get("/documents", headers=viewer_headers)
    assert listing.status_code == 200
    assert [doc["name"] for doc in listing.json()["documents"]] == ["own.txt"]
    detail = client.get(f"/documents/{own}", headers=viewer_headers)
    assert detail.status_code == 200
    assert detail.json()["body"] == "Contact [REDACTED:pii]."
    assert client.get(f"/documents/{own + 1}", headers=viewer_headers).status_code == 404


def test_password_change_updates_backend_credentials():
    login = client.post("/auth/login", json={"email": "admin-test@example.com", "password": "Admin123"})
    headers = {"Authorization": f"Bearer {login.json()['token']}"}
    changed = client.post("/auth/password", headers=headers, json={
        "current_password": "Admin123",
        "new_password": "NewDemo8",
    })
    assert changed.status_code == 200
    assert client.post("/auth/login", json={"email": "admin-test@example.com", "password": "NewDemo8"}).status_code == 200
    reset_login = client.post("/auth/login", json={"email": "admin-test@example.com", "password": "NewDemo8"})
    reset_headers = {"Authorization": f"Bearer {reset_login.json()['token']}"}
    reset = client.post("/auth/password", headers=reset_headers, json={
        "current_password": "NewDemo8",
        "new_password": "Admin123",
    })
    assert reset.status_code == 200


def test_gateway_response_override_is_filtered():
    login = client.post("/auth/login", json={"email": "admin-test@example.com", "password": "Admin123"})
    headers = {"Authorization": f"Bearer {login.json()['token']}"}
    response = client.post("/gateway", headers=headers, json={
        "question": "Summarize the leave policy.",
        "response_override": "Contact admin@example.com for help.",
    })
    assert response.status_code == 200
    assert response.json()["decision"] == "Redact"
    assert "admin@example.com" not in response.json()["answer"]

def test_gateway_rate_limit(monkeypatch):
    login = client.post("/auth/login", json={"email": "admin-test@example.com", "password": "Admin123"})
    headers = {"Authorization": f"Bearer {login.json()['token']}"}
    monkeypatch.setattr(main, "GATEWAY_RATE_LIMIT", 1)
    main._gateway_attempts.clear()
    payload = {"question": "Summarize the leave policy.", "response_override": "Use the normal leave process."}
    assert client.post("/gateway", headers=headers, json=payload).status_code == 200
    limited = client.post("/gateway", headers=headers, json=payload)
    assert limited.status_code == 429
    assert limited.headers["retry-after"] == str(main.GATEWAY_RATE_WINDOW_SECONDS)


def test_login_and_document_listing():
    login = client.post("/auth/login", json={"email": "admin-test@example.com", "password": "Admin123"})
    assert login.status_code == 200
    token = login.json()["token"]
    response = client.get("/documents", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
