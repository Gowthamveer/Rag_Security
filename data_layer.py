"""Secure data access layer for structured company data.

This is the only code that reads the employees table. The gateway asks a repository for data
on behalf of a signed-in user; the repository decides which columns and rows that user may
receive *before* anything is fetched. Fields a role is not cleared for are never selected, so
they cannot reach the model and do not depend on output redaction.

The table ships with synthetic sample data for demos (SEED_DEMO_DATA=true). Point the
repository at a real read-only view in production and review FIELD_POLICY with the data owner.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any

from sqlalchemy import Column, Integer, MetaData, String, Table, func, or_, select
from sqlalchemy.engine import Engine

metadata = MetaData()
employees = Table(
    "employees", metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String(120), nullable=False),
    Column("department", String(60), nullable=False),
    Column("designation", String(80), nullable=False),
    Column("location", String(60), nullable=False),
    Column("manager", String(120), nullable=False),
    Column("annual_salary", Integer, nullable=False),
    Column("performance_rating", String(20), nullable=False),
)

# Column-level policy per role. Anything not listed is never selected for that role.
FIELD_POLICY: dict[str, tuple[str, ...]] = {
    "viewer": ("name", "department", "designation", "location"),
    "analyst": ("name", "department", "designation", "location", "manager"),
    "hr": ("name", "department", "designation", "location", "manager", "annual_salary", "performance_rating"),
    "admin": ("name", "department", "designation", "location", "manager", "annual_salary", "performance_rating"),
}
ALL_FIELDS = FIELD_POLICY["admin"]
# Output-gate categories a role is cleared to receive because the repository already
# authorised those fields. Everyone else still gets salary figures redacted at the output gate.
CLEARED_CATEGORIES: dict[str, set[str]] = {"hr": {"business"}, "admin": {"business"}}
MAX_ROWS = 25

FIELD_WORDS = {
    "annual_salary": ("salary", "salaries", "pay", "paid", "ctc", "compensation", "earn", "earns", "package"),
    "performance_rating": ("performance", "rating", "ratings", "appraisal", "review"),
    "manager": ("manager", "reports to", "reporting", "boss"),
}
TOPIC_WORDS = ("employee", "employees", "staff", "team", "who works", "people in", "headcount",
               "department", "designation", "colleague", "works in", "engineer", "engineers")

SAMPLE_EMPLOYEES = [
    ("Aarav Mehta", "Engineering", "Senior Software Engineer", "Bengaluru", "Kavita Rao", 2850000, "Exceeds"),
    ("Priya Nair", "Engineering", "Software Engineer", "Chennai", "Kavita Rao", 1650000, "Meets"),
    ("Kavita Rao", "Engineering", "Engineering Manager", "Bengaluru", "Rohan Gupta", 4200000, "Exceeds"),
    ("Rohan Gupta", "Leadership", "Chief Technology Officer", "Mumbai", "Board", 9800000, "Exceeds"),
    ("Sneha Iyer", "Human Resources", "HR Business Partner", "Pune", "Anil Kapoor", 1900000, "Meets"),
    ("Anil Kapoor", "Human Resources", "Head of HR", "Mumbai", "Rohan Gupta", 5200000, "Meets"),
    ("Farhan Qureshi", "Finance", "Financial Analyst", "Hyderabad", "Meera Joshi", 1450000, "Below"),
    ("Meera Joshi", "Finance", "Finance Controller", "Mumbai", "Rohan Gupta", 4700000, "Exceeds"),
    ("Daniel Fernandes", "Sales", "Account Executive", "Goa", "Ritu Sharma", 1300000, "Meets"),
    ("Ritu Sharma", "Sales", "Regional Sales Manager", "Delhi", "Rohan Gupta", 3600000, "Meets"),
    ("Arjun Reddy", "Security", "Security Engineer", "Hyderabad", "Kavita Rao", 2400000, "Exceeds"),
    ("Neha Verma", "Support", "Customer Support Lead", "Kolkata", "Ritu Sharma", 1100000, "Meets"),
]


def init(engine: Engine) -> None:
    metadata.create_all(engine)
    if os.getenv("SEED_DEMO_DATA", "true").lower() not in {"1", "true", "yes"}:
        return
    with engine.begin() as conn:
        if conn.execute(select(func.count()).select_from(employees)).scalar_one():
            return
        conn.execute(employees.insert(), [
            dict(zip(("name", "department", "designation", "location", "manager", "annual_salary", "performance_rating"), row))
            for row in SAMPLE_EMPLOYEES
        ])


def wants_employee_data(question: str) -> bool:
    q = question.lower()
    words = [w for words in FIELD_WORDS.values() for w in words]
    return any(re.search(rf"\b{re.escape(w)}\b", q) for w in (*TOPIC_WORDS, *words))


class EmployeeRepository:
    """Policy-enforcing reads of the employees table on behalf of one signed-in user."""

    def __init__(self, engine: Engine):
        self.engine = engine

    def requested_fields(self, question: str) -> set[str]:
        q = question.lower()
        return {field for field, words in FIELD_WORDS.items()
                if any(re.search(rf"\b{re.escape(w)}\b", q) for w in words)}

    def search(self, user: dict[str, str], question: str) -> dict[str, Any]:
        role = user.get("role", "viewer")
        allowed = FIELD_POLICY.get(role, ())
        requested = self.requested_fields(question)
        denied = sorted(f for f in requested if f not in allowed)
        if not allowed:
            return {"rows": [], "fields": [], "denied_fields": sorted(requested), "role": role}

        # Row filter: match names, departments or designations mentioned in the question.
        terms = [t for t in re.findall(r"[a-z]{3,}", question.lower())
                 if t not in {"the", "and", "who", "what", "are", "all", "how", "much", "does", "for", "with", "list",
                              "show", "tell", "about", "their", "salary", "salaries", "employees", "employee",
                              "works", "work", "team", "staff", "department", "rating", "performance", "manager", "many"}]
        query = select(*[employees.c[f] for f in allowed])
        if terms:
            clauses = []
            for term in terms[:8]:
                like = f"%{term}%"
                clauses += [employees.c.name.ilike(like), employees.c.department.ilike(like),
                            employees.c.designation.ilike(like), employees.c.location.ilike(like)]
            query = query.where(or_(*clauses))
        with self.engine.connect() as conn:
            rows = [dict(r) for r in conn.execute(query.order_by(employees.c.name).limit(MAX_ROWS)).mappings()]
        return {"rows": rows, "fields": list(allowed), "denied_fields": denied, "role": role}


def as_context(result: dict[str, Any]) -> str:
    rows = result["rows"]
    lines = [f"[AUTHORISED DATA: employees | role={result['role']} | fields={', '.join(result['fields'])}]"]
    if result["denied_fields"]:
        lines.append("Fields withheld by access policy (do not guess them): " + ", ".join(result["denied_fields"]))
    if not rows:
        lines.append("No matching employee records.")
    for row in rows:
        lines.append("; ".join(f"{k}: {v:,}" if isinstance(v, int) else f"{k}: {v}" for k, v in row.items()))
    return "\n".join(lines)


def fingerprint(result: dict[str, Any]) -> str:
    """Short hash of what was released, for the audit trail (rows themselves are not logged)."""
    return hashlib.sha256(json.dumps(result["rows"], sort_keys=True, default=str).encode()).hexdigest()[:16]
