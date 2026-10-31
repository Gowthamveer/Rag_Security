
from detectors import scan, gate

text = "The employee's salary is ₹25 lakhs per year."

print("1. Detector findings:")
print(scan(text))

print("\n2. Gate result:")
print(gate(text))
