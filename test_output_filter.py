
from detectors import gate

fake_llm_answer = (
    "Fictional employee Alex earns a salary of "
    "₹25 lakhs per year."
)

action, safe_answer, findings = gate(fake_llm_answer)

print("OUTPUT ACTION:", action)
print("ORIGINAL ANSWER:", fake_llm_answer)
print("FILTERED ANSWER:", safe_answer)
print("FINDINGS:", findings)

assert action == "Redact", (
    f"Expected Redact, got {action}"
)

assert "₹25 lakhs" not in safe_answer, (
    "FAIL: Salary amount was not removed"
)

print("PASS: Output detector redacted the fictional salary.")
