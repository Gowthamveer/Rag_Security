import main
from fastapi.testclient import TestClient
from sqlalchemy import insert, select, update


def test_audit_chain_detects_tampering(monkeypatch):
    monkeypatch.setitem(
        main.app.dependency_overrides,
        main.current_user,
        lambda: {
            "sub": "audit-test@example.com",
            "role": "admin",
        },
    )

    client = TestClient(main.app)

    try:
        # Add a unique audit record using the application's own hash-chain writer.
        marker = "AUDIT_INTEGRITY_TEST"
        main._audit(
            "audit-test@example.com",
            "integrity_test",
            {"marker": marker},
        )

        with main.DB.connect() as conn:
            row = conn.execute(
                select(main.audit)
                .where(main.audit.c.event == "integrity_test")
                .order_by(main.audit.c.id.desc())
                .limit(1)
            ).mappings().first()

        assert row is not None
        record_id = row["id"]

        # The chain should be valid before tampering.
        response = client.get("/audit/verify")
        assert response.status_code == 200, response.text
        assert response.json()["valid"] is True, response.json()

        # Modify the record without recalculating its hash.
        with main.DB.begin() as conn:
            conn.execute(
                update(main.audit)
                .where(main.audit.c.id == record_id)
                .values(detail='{"marker":"TAMPERED"}')
            )

        # The verifier must detect the changed record.
        response = client.get("/audit/verify")
        assert response.status_code == 200, response.text
        result = response.json()

        assert result["valid"] is False, result
        assert result["first_invalid_record"] == record_id, result

        print("PASS: Valid audit chain was accepted.")
        print("PASS: Modified audit record was detected.")

    finally:
        client.close()
        main.app.dependency_overrides.pop(main.current_user, None)
