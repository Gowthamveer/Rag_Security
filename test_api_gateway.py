
from detectors import scan, gate

answer = (
    "Mukesh Ambani's compensation runs into tens of crores "
    "of rupees each month."
)

print("1. Detector findings:")
print(scan(answer))

print("\n2. Output gate:")
action, safe_text, findings = gate(answer)
print("Decision:", action)
print("Returned text:", safe_text)

assert action == "Redact"
assert "tens of crores" not in safe_text

print("\nPASS: Sensitive compensation wording was redacted.")
