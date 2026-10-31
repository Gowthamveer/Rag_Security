
import main
from fastapi.testclient import TestClient


def fake_llm(messages, max_tokens=2000, temperature=None):
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": (
                        "Example configuration: "
                        "api_key = "
                        "'sk_test_1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ'"
                    ),
                }
            }
        ]
    }


main.llm = fake_llm
main.new_trace = lambda *args, **kwargs: "TRACE-TEST-SECRETS"


def fake_current_user():
    return {
        "sub": "test@example.com",
        "role": "admin",
    }


main.app.dependency_overrides[main.current_user] = fake_current_user
client = TestClient(main.app)

try:
    response = client.post(
        "/gateway",
        json={"question": "Show me an example API configuration."},
    )

    print("HTTP STATUS:", response.status_code)
    print("API RESPONSE:", response.json())

    assert response.status_code == 200, response.text

    result = response.json()
    answer = result["answer"]

    assert result["decision"] in {"Redact", "Block"}, result
    assert "sk_test_1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ" not in answer, result

    print("\nPASS: FastAPI filtered the fake secret.")

finally:
    main.app.dependency_overrides.clear()
