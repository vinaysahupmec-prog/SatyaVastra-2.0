# SatyaVastra — Handloom Craft Passport

SatyaVastra is a prototype digital passport for handloom sarees. It pairs an HMAC-signed QR code with an artisan story, encrypted profile/media records, and a scan-state dashboard.

## Requirements and setup

Use Python 3.11 or newer. From the repository root, create a virtual environment if desired, install dependencies, and seed the SQLite database:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r backend/requirements.txt
python -m backend.app.seed
```

The app generates `.env` on first run, with independent 32-byte hex `ENC_KEY`, `JWT_SECRET`, and `QR_HMAC_SECRET` values, and gives the file owner-only permissions. The committed `.env.example` contains placeholders only. Keep `.env` and the SQLite database private; `.gitignore` excludes them. The demo usernames/passwords listed below are intentionally public sample credentials, not production accounts.

Start the requested API and website process from the project root:

```bash
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

Open the entry hub at `/`, interfaces at `/weaver`, `/scan`, `/design`, `/admin`, API documentation at `/docs`, and health at `/_app/health`. The OpenAPI schema is at `/openapi.json`. The route manifest is served as JSON at `/manus-routes.json`.

## Demo access

| Role | Username | Password |
| --- | --- | --- |
| Admin | `admin_demo` | `AdminPass@123` |
| Weaver | `weaver_demo` | `WeaverPass@123` |
| Customer | `customer_demo` | `CustomerPass@123` |

The scan page offers three seeded codes: a live verified Sambalpuri Ikat tag, an expired Bomkai tag, and a Kotpad sample whose deterministic demo scan history demonstrates the suspicious state. Suspicious means more than five scans in a 60-second window.

## Privacy and security notes

AES-256-GCM sensitive fields use `nonce:tag:ciphertext` standard-base64 components. Weaver name, phone, full address and story, voice transcript/audio, saree story, custom-order brief, and uploaded image/audio blobs are encrypted before being stored in SQLite. Admin raw-table inspection returns ciphertext. The admin-only encryption proof endpoint demonstrates controlled decryption. QR signatures use HMAC-SHA256 with a separate server-held key. User passwords are Argon2 hashes. Authenticated API access is a bearer JWT with a role claim and database-backed user check. This prototype never asks for or stores Aadhaar or identity-card numbers; the attestation record contains only a boolean, officer/cooperative name and date.

The QR suspicious sample is explicitly marked as a demo fixture so its recent-scan history can be recreated after the 60-second window; ordinary tags rely only on actual scan events. Seed operations are idempotent and test cases use separate temporary databases.

## Test suite

```bash
pytest -q
```

The current 11-test suite checks AES-GCM roundtrip and wrong-key failure, all four scan states, HTTP 403 role protection, private voice and image encryption, tag creation and 120-day renewal, QR PNG delivery, customer design requests and quotes, consent, CSV export, and deletion approval. It uses an isolated temporary SQLite database and writes each result to `tests/results/test_output.csv`.
