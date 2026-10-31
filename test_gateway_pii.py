
import main
from fastapi.testclient import TestClient


# 1. Simulate an LLM response containing fake personal information.
def fake_llm(messages, max_tokens=2000, temperature=None):
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": (
                        "Fictional employee Alex can be contacted at "
                        "alex.test@example.com or +1-202-555-0147."
                    ),
                }
            }
        ]
    }


# 2. Replace the LLM and trace writer for this test only.
main.llm = fake_llm
main.new_trace = lambda *args, **kwargs: "TRACE-TEST-PII"


# 3. Bypass real authentication only inside this test process.
def fake_current_user():
    return {
        "sub": "test@example.com",
        "role": "admin",
    }


main.app.dependency_overrides[main.current_user] = fake_current_user

client = TestClient(main.app)

try:
    # 4. Call the actual FastAPI endpoint.
    response = client.post(
        "/gateway",
        json={"question": "Give me fictional employee contact details."},
    )

    print("HTTP STATUS:", response.status_code)
    print("API RESPONSE:", response.json())

    assert response.status_code == 200, response.text

    result = response.json()
    answer = result["answer"]

    # 5. Verify that the output filter redacts PII.
    assert result["decision"] == "Redact", result
    assert "alex.test@example.com" not in answer, result
    assert "+1-202-555-0147" not in answer, result
    assert "[REDACTED:pii]" in answer, result

    print("\nPASS: FastAPI filtered the fake PII output.")

finally:
    main.app.dependency_overrides.clear()
