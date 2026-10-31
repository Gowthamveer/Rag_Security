
from detectors import scan, gate

text = "Compensation runs into tens of crores of rupees each month."

print("Findings:")
print(scan(text))

print("\nGate result:")
action, safe_text, findings = gate(text)
print("Action:", action)
print("Safe text:", safe_text)

assert action == "Redact", f"Expected Redact, got {action}"
assert "[REDACTED:business]" in safe_text

print("\nPASS: Salary detector and redaction work.")
