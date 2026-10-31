
import json
import uuid
from datetime import datetime, timezone

import main
from fastapi.testclient import TestClient
from sqlalchemy import insert


def test_trace_access_requires_an_authorized_role(monkeypatch):
    trace_id = "TRACE-TEST-" + uuid.uuid4().hex[:12].upper()

    with main.DB.begin() as conn:
        conn.execute(
            insert(main.traces).values(
                id=trace_id,
                actor="admin@example.com",
                question="Test question",
                decision="Allow",
                detail=json.dumps({"retrieved_documents": 1}),
                created_at=datetime.now(timezone.utc).isoformat(),
            )
        )

    try:
        with TestClient(main.app) as client:
            # Analyst cannot access another user's trace.
            monkeypatch.setitem(
                main.app.dependency_overrides,
                main.current_user,
                lambda: {
                    "sub": "analyst@example.com",
                    "role": "analyst",
                },
            )

            analyst_response = client.get(f"/traces/{trace_id}")
            assert analyst_response.status_code == 403, (
                analyst_response.status_code,
                analyst_response.text,
            )

            # Admin can access the same trace.
            monkeypatch.setitem(
                main.app.dependency_overrides,
                main.current_user,
                lambda: {
                    "sub": "admin@example.com",
                    "role": "admin",
                },
            )

            admin_response = client.get(f"/traces/{trace_id}")
            assert admin_response.status_code == 200, admin_response.text
            assert admin_response.json()["actor"] == "admin@example.com"

        print("PASS: Analyst cannot access another user's trace.")
        print("PASS: Admin can access the trace.")

    finally:
        with main.DB.begin() as conn:
            conn.execute(
                main.traces.delete().where(main.traces.c.id == trace_id)
            )
