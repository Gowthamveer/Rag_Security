
import main
from fastapi.testclient import TestClient


# 1. Simulate an LLM response containing fictional sensitive information.
def fake_llm(messages, max_tokens=2000, temperature=None):
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": (
                        "Fictional employee Alex earns a salary "
                        "of ₹25 lakhs per year."
                    ),
                }
            }
        ]
    }


# 2. Replace the LLM and trace writer only for this test process.
main.llm = fake_llm
main.new_trace = lambda *args, **kwargs: "TRACE-TEST-OUTPUT"


# 3. Override authentication for this isolated test.
def fake_current_user():
    return {
        "sub": "test@example.com",
        "role": "admin",
    }


main.app.dependency_overrides[main.current_user] = fake_current_user


# 4. Create the test client.
client = TestClient(main.app)

try:
    # 5. Call the actual FastAPI gateway endpoint.
    response = client.post(
        "/gateway",
        json={
            "question": "Give me a fictional employee example."
        },
    )

    print("HTTP STATUS:", response.status_code)
    print("API RESPONSE:", response.json())

    # 6. Verify the response.
    assert response.status_code == 200, response.text

    result = response.json()

    assert result["decision"] == "Redact", result
    assert "₹25 lakhs" not in result["answer"], result
    assert "[REDACTED:business]" in result["answer"], result

    print("\nPASS: FastAPI filtered the fake LLM output.")

finally:
    # 7. Clean up the test-only authentication override.
    main.app.dependency_overrides.clear()
