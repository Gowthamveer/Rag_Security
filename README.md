# RAG Security Gateway

A defensive starter project for scanning documents and placing policy gates around a Retrieval-Augmented Generation (RAG) or OpenAI-compatible chat endpoint. FastAPI serves the dashboard (`index.html`) and its API from the same origin. The dashboard keeps its detailed workspace encrypted in the browser, and uploads scanned documents to the backend for redacted, persistent retrieval.

## What is included

- Regex-based detectors for prompt-injection patterns, common credentials/tokens, PII, payment-card candidates (Luhn validation), and sensitive business data.
- Allow/redact/block policy gate and bounded Base64 decoding for detection (decoded content is never executed).
- FastAPI authentication using Argon2 password hashes and expiring JWTs, first-admin bootstrap, login throttling, and optional TOTP MFA setup.
- Upload size/type/extraction limits; sensitive-data redaction before document text is persisted; risk-scored documents are excluded from retrieval at risk >= 70.
- RAG retrieval with a server-side instruction to treat retrieved documents as untrusted data.
- OpenAI-compatible `POST /v1/chat/completions`, document listing/deletion, trace lookup, health endpoint, and hash-linked audit verification.
- Gateway Test includes a browser-local regression suite with fake injection, credential, PII, and benign-control cases; results include expected/actual decisions, detections, and elapsed time.
- Red Team includes built-in and mutated defensive tests, custom local cases, gate-by-gate outcomes, bypass filtering/reruns, false-alarm counts, and downloadable reports that omit prompts and response contents.
- Regression tests in the root-level `test_*.py` files.

## New in this version

### Public sign-up switch
Set `ALLOW_PUBLIC_SIGNUP=false` on any public deployment. The very first sign-up still creates the admin; after that only an admin can create accounts (Account tab → add user). The sign-in screen hides the Sign up button automatically.

### Secure data layer (structured company data)
`data_layer.py` is the only code that reads the `employees` table. When a question is about employees, the gateway asks `EmployeeRepository` for data on behalf of the signed-in user, and the repository selects only the columns that user's role is cleared for:

| Role | Fields released |
|---|---|
| viewer | name, department, designation, location |
| analyst | + manager |
| hr, admin | + annual_salary, performance_rating |

Fields a role is not cleared for are never queried, so they never reach the model. Salary figures in answers are only let through the output gate when the data layer released them to a cleared role for that question; otherwise normal redaction applies. Every read is written to the audit log (`data_layer_read`) with the fields released and a hash of the rows. Synthetic sample data is seeded on first start; set `SEED_DEMO_DATA=false` to disable. In production, point the repository at a read-only view and review `FIELD_POLICY` with the data owner.

Demo: create an `hr` user and a `viewer` user, then ask both "What is Aarav Mehta's salary?" in Gateway test.

### Proxy mode: poisoned passages are removed, not fatal
`POST /v1/chat/completions` now gates content passage by passage (split on blank lines or `---`). A retrieved passage containing injection is replaced with a removal notice and the request continues; `gateway.passages_removed` reports how many. Injection in the final passage of the last user message (the question) still blocks the request. The calling app's own system/developer messages are not blocked for injection phrasing such as "never reveal the system prompt", but secrets and personal data in them are still redacted.

### End-user identity (`X-End-User`)
Create a `service` account for the company's RAG app. Requests from that account may send `X-End-User: priya@corp.com`; traces record `service-account for priya@corp.com` and rate limits apply per end user. Other roles get 403 if they send the header. The header labels activity; it does not grant access.

### Other fixes in this version
- Viewers (and other non-admin/analyst roles) only retrieve documents they uploaded.
- `response_override` (test responses) is limited to analyst and admin.
- Base64-encoded secrets are removed from text, not just flagged.
- Broader detection of common injection phrasings ("ignore all the instructions…", "output your system message…").
- Docker image runs uvicorn with `--proxy-headers` so throttling sees real client IPs behind a hosting proxy.

## Run locally (Python)

Python 3.11+ is recommended. Install Tesseract OCR separately if you need image scanning.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

For tests, install the development dependency set with `pip install -r requirements-dev.txt`.

Copy `.env.example` to `.env`, then set `GROQ_API_KEY` (or `UPSTREAM_API_KEY` / `API_KEY`) to your real provider key and update `MODEL` / `UPSTREAM_URL` if needed. Replace the sample `POSTGRES_PASSWORD` with a strong random value. Set `JWT_SECRET` to a random secret of at least 32 bytes; this workspace's `.env` has a generated value. The `.env` file is ignored by Git. The backend adds browser security headers, avoids logging raw gateway prompts/responses, and limits gateway requests by `GATEWAY_RATE_LIMIT` per `GATEWAY_RATE_WINDOW_SECONDS` per account. The in-memory limit is per process; use a shared limiter for multi-worker production. Set the limit to `0` only for a trusted development setup. From the project folder, start with:

```powershell
python -m pip install -r requirements.txt
python -m uvicorn main:app --env-file .env --reload --port 8000
```

Open the dashboard at `http://127.0.0.1:8000/` and the API explorer at `http://127.0.0.1:8000/docs`. The first sign-up creates the admin; subsequent public sign-ups create viewer-only accounts. Passwords must be at least 8 characters. The browser workspace is encrypted locally and is not synchronized to the backend.

On macOS/Linux:

```bash
python -m pip install -r requirements.txt
python -m uvicorn main:app --env-file .env --reload --port 8000
```

The first sign-up creates the admin; subsequent public sign-ups create viewer-only accounts. Passwords must be at least 8 characters. To use local Ollama instead of Groq, update `UPSTREAM_URL` and `MODEL` in `.env`, then ensure Ollama is running and the model is downloaded.

To use a hosted OpenAI-compatible provider, set `UPSTREAM_URL`, `MODEL`, and the provider key environment variable expected by your deployment (`GROQ_API_KEY` for the default Groq URL). For local Ollama, set `UPSTREAM_URL=http://localhost:11434/v1` and `MODEL=llama3.1`; ensure Ollama is running and the model is downloaded.

## Docker Compose

Replace the placeholder API key and both passwords in `.env`, then run:

```bash
docker compose up -d --build
```

The default configuration uses the hosted provider settings in `.env`. If using Ollama, set `UPSTREAM_URL=http://ollama:11434/v1` and the matching `MODEL`, then pull that model into the `ollama` container. The API binds to `127.0.0.1:8000` by default. Put it behind an authenticated TLS reverse proxy before exposing it to a network. Do not commit `.env` or real credentials.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

## Important limitations / production checklist

- Regex rules are heuristic and can have false positives and false negatives. They are not a proof against prompt injection or data exfiltration.
- Login throttling is process-local. Use a shared limiter (for example Redis) for multi-worker/multi-instance deployments.
- Audit hash chaining detects some tampering but is not immutable storage; forward audit events to a separately controlled logging service.
- The starter uses additive schema migration for compatibility. Use Alembic or another reviewed migration process for production schema changes.
- TOTP secrets are stored in the database; encrypt them at rest and provide a secure recovery process before production use.
- OCR requires the Tesseract system binary. PDFs/DOCX and image parsing should be run with resource limits in a sandbox for hostile uploads.
- Retrieval uses simple SQL substring matching, not a vector database or document-level ACL system. Add tenant/permission filtering before use with real confidential corpora.
- There is no SSO, production key rotation, comprehensive admin user-management UI, distributed rate limiting, or full penetration-test coverage yet.
- The dashboard's detailed analytics, review controls, and encrypted workspace remain browser-local; backend documents and gateway requests are server-side. Do not treat browser-side controls as server-side security enforcement.
- Gateway Test's local suite and Red Team panel exercise the browser's heuristic policies; they do not prove the backend or an upstream model is secure. Test cases use synthetic data, and generated cases may be authored with Claude when connected but are evaluated locally. Reports contain case labels, decisions, detections, and timings, but omit case prompts and sample replies.
