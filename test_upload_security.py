import main
from fastapi.testclient import TestClient


def test_upload_security(monkeypatch):
    monkeypatch.setitem(
        main.app.dependency_overrides,
        main.current_user,
        lambda: {"sub": "upload-test@example.com", "role": "admin"},
    )

    monkeypatch.setattr(main, "MAX_UPLOAD_BYTES", 10)
    client = TestClient(main.app)

    try:
        # Unsupported file extension
        response = client.post(
            "/scan",
            files={"f": ("payload.exe", b"example", "application/octet-stream")},
        )
        assert response.status_code == 415, response.text

        # Empty file
        response = client.post(
            "/scan",
            files={"f": ("empty.txt", b"", "text/plain")},
        )
        assert response.status_code == 400, response.text

        # File exceeds the configured test limit of 10 bytes
        response = client.post(
            "/scan",
            files={"f": ("large.txt", b"A" * 11, "text/plain")},
        )
        assert response.status_code == 413, response.text

        # Safe text file within the test limit
        response = client.post(
            "/scan",
            files={"f": ("safe.txt", b"hello", "text/plain")},
        )
        assert response.status_code == 200, response.text
        assert response.json()["retrievable"] is True

        print("PASS: Unsupported extensions are rejected.")
        print("PASS: Empty uploads are rejected.")
        print("PASS: Oversized uploads are rejected.")
        print("PASS: Small safe text uploads are accepted.")

    finally:
        client.close()
        main.app.dependency_overrides.pop(main.current_user, None)

