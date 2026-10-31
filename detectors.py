"""Detectors and policy gate for the RAG Security Gateway.

Regex-based detection is a defense-in-depth signal, not a complete prompt-injection
or data-loss-prevention solution. Keep rules versioned and test them against your data.
"""
from __future__ import annotations
import base64
import re
import time
from typing import Any


def luhn(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0

# (category, label, regex, score, version)
DETECTORS = [
    ("injection", "Instruction override", r"(?i)\b(ignore|disregard|forget)\b[^.\n]{0,50}\b(previous|prior|above|earlier|system)\b[^.\n]{0,30}\b(instructions?|rules?|prompts?)\b", 85, "v1"),
    ("injection", "Secret or prompt exfiltration", r"(?i)\b(reveal|show|print|leak|dump|exfiltrate)\b[^.\n]{0,35}\b(system prompt|confidential|salary|hidden instructions?|secrets?|credentials?|passwords?|api keys?)\b", 85, "v1"),
    ("injection", "Role hijack or jailbreak", r"(?i)\b(you are now|act as (an? )?(unrestricted|dan)|developer mode|jailbreak|do anything now)\b", 75, "v1"),
    ("injection", "Hidden instruction tags", r"(?i)<\s*(system|instructions?|assistant)\s*>", 80, "v1"),
    ("injection", "Markdown image exfiltration", r"!\[[^\]]*\]\(https?://[^)\s]+\?[^)\s]*\)", 85, "v1"),
    ("injection", "Instruction override (non-English)", r"(?i)\b(ignora|ignorez|ignoriere|olvida|oubliez|vergiss)\b[^.\n]{0,40}\b(instrucciones|instructions|anweisungen|reglas|règles|regeln|anteriores|précédentes|vorherigen)\b", 82, "v2"),
    ("injection", "Instruction override (Devanagari)", r"(निर्देश|अनदेखा|पासवर्ड|गोपनीय|प्रकट)", 82, "v2"),
    ("injection", "Spaced-out instruction word", r"(?i)\b(?:i\s+g\s+n\s+o\s+r\s+e|d\s+i\s+s\s+r\s+e\s+g\s+a\s+r\s+d|r\s+e\s+v\s+e\s+a\s+l|s\s+h\s+o\s+w|p\s+r\s+i\s+n\s+t)\b", 78, "v2"),
    ("secrets", "AWS access key", r"\bAKIA[0-9A-Z]{16}\b", 95, "v1"),
    ("secrets", "Private key block", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", 98, "v1"),
    ("secrets", "GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{30,}\b", 92, "v1"),
    ("secrets", "Stripe live key", r"\b[sr]k_live_[A-Za-z0-9]{16,}\b", 92, "v1"),
    ("secrets", "Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b", 92, "v2"),
    ("secrets", "JWT or bearer token", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", 90, "v2"),
    ("secrets", "Slack token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", 90, "v2"),
    ("secrets", "Database connection string", r"(?i)\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s\"']+", 90, "v1"),
    ("secrets", "Password or API key assignment", r"(?i)\b(api[_-]?key|secret|token|passwd|password|pwd)\b[\"']?\s*[:=]\s*[\"']?[^\s\"',;]{6,}", 90, "v1"),
    ("pii", "Email address", r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b", 40, "v1"),
    ("pii", "Phone number", r"(?<!\w)(?:\+91[\s-]?)?[6-9]\d{9}(?!\w)", 45, "v2"),
    ("pii", "Aadhaar number", r"\b\d{4}[ -]\d{4}[ -]\d{4}\b", 70, "v1"),
    ("pii", "PAN number", r"\b[A-Z]{5}\d{4}[A-Z]\b", 65, "v2"),
    ("pii", "US Social Security number", r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b", 75, "v1"),
    ("pii", "UK National Insurance number", r"\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b", 70, "v2"),
    ("pii", "IBAN", r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", 70, "v2"),
    ("pii", "Passport number", r"(?i)\bpassport(?: no\.?| number)?[:\s#]+[A-Z0-9]{6,9}\b", 60, "v2"),
    ("pii", "IPv4 address", r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", 35, "v2"),
    ("pii", "Medical record or diagnosis", r"(?i)\b(?:diagnos(?:is|ed)|prescription|patient id|mrn)\b[^.\n]{0,40}", 65, "v2"),
    ("pii", "Date of birth", r"(?i)\b(?:date_of_birth|date of birth|dob)\b\s*[,=:]\s*[^,;\n]{4,20}", 60, "v1"),
    ("pii", "National ID field", r"(?i)\b(?:national_id|national id|aadhaar|ssn)\b\s*[,=:]\s*[^,;\n]{4,24}", 70, "v1"),
    ("pii", "Payment card number", r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)", 75, "v1"),
    
    (
        "pii",
        "International phone number",
        r"(?<!\w)(?:\+\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)\d{3}[\s.-]?\d{4}(?!\w)",
        40,
        "v2",
    ),

    ("business", "Salary or financial figure", r"(?i)\b(salary|salaries|payroll|compensation|ctc|bonus|revenue|net worth|annual_salary)\b[^.\n]{0,40}?(?:₹|rs\.?|inr|\$|usd)?\s?\d[\d,]{3,}", 70, "v1"),
    ("business", "Confidential marking", r"(?i)\b(strictly )?confidential\b|\binternal use only\b", 50, "v1"),
    ("business", "Deal or pricing data", r"(?i)\b(contract value|deal size|pricing sheet|margin)\b[^.\n]{0,30}\d", 55, "v2"),
    (
    "business",
    "Salary or financial figure (written amount)",
    r"(?i)\b(?:salary|salaries|payroll|compensation|ctc|bonus|revenue|net worth|remuneration|earnings|pay package)\b[^.\n]{0,100}\b(?:tens|hundreds|thousands|millions|billions|crores?|lakhs?|lacs?)\b",
    70,
    "v3",
),
]
ACTION = {"injection": "Block", "secrets": "Redact", "pii": "Redact", "business": "Redact"}
BLOCK_CATEGORIES = {"injection"}


def norm(text: str) -> str:
    text = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", text).lower()
    text = text.translate(str.maketrans({"1":"i", "0":"o", "3":"e", "4":"a", "5":"s", "$":"s", "@":"a"}))
    return re.sub(r"\s+", " ", re.sub(r"[^a-z\s]", " ", text))


def mask(value: str, category: str) -> str:
    if category in ("secrets", "pii") and len(value) > 3:
        return value[:3] + "•" * min(8, len(value) - 3)
    return value[:60]


def _run(text: str, label_suffix: str = "") -> list[dict[str, Any]]:
    out = []
    for cat, label, pattern, score, version in DETECTORS:
        started = time.perf_counter()
        hits = [m for m in re.finditer(pattern, text) if label != "Payment card number" or luhn(m.group())]
        if hits:
            out.append({"cat": cat, "label": label + label_suffix, "score": score,
                        "count": len(hits), "version": version,
                        "evidence": [mask(m.group(), cat) for m in hits[:3]],
                        "latency_ms": round((time.perf_counter() - started) * 1000, 2)})
    return out


def scan(text: str) -> list[dict[str, Any]]:
    if not isinstance(text, str):
        text = str(text)
    found = _run(text[:2_000_000])
    seen = {f["label"].removesuffix(" (obfuscated)") for f in found}
    found.extend(f for f in _run(norm(text[:2_000_000]), " (obfuscated)")
                 if f["cat"] == "injection" and f["label"].removesuffix(" (obfuscated)") not in seen)
    # Decode only bounded candidate strings; never execute decoded content.
    for blob in re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", text[:2_000_000])[:20]:
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if decoded.isprintable():
            found.extend(_run(decoded, " (base64)"))
    return found


def redact(text: str, categories: set[str] | None = None) -> str:
    """Redact detected values from text. Injection is intentionally not rewritten here."""
    categories = categories or {"secrets", "pii", "business"}
    output = text
    for cat, label, pattern, _score, _version in DETECTORS:
        if cat not in categories:
            continue
        output = re.sub(pattern, lambda m: m.group() if label == "Payment card number" and not luhn(m.group()) else f"[REDACTED:{cat}]", output)
    return output


def gate(text: str) -> tuple[str, str, list[dict[str, Any]]]:
    """Return (action, safe_text, findings); Block outranks Redact, which outranks Allow."""
    findings = scan(text)
    categories = {item["cat"] for item in findings}
    if categories & BLOCK_CATEGORIES:
        return "Block", "", findings
    if categories & {"secrets", "pii", "business"}:
        return "Redact", redact(text, categories), findings
    return "Allow", text, findings


