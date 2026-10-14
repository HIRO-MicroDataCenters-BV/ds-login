# ds-login — server

FastAPI service that verifies a BYOK AID + ACDC credential against the DKMS
witness/watcher network and issues a short-lived JWT.

## Run locally

```bash
poetry install
poetry run uvicorn app.main:app --reload --port 8080
```

Set the backend URLs via env (or edit `.env`):

```
DS__WATCHER_URL=http://localhost:3235
DS__WITNESS_URLS=["http://localhost:3232","http://localhost:3233","http://localhost:3234"]
DS__KEL_DISK_FALLBACK_DIR=/path/to/wallet/data/exports    # dev only
```

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health-check/` | Liveness |
| GET | `/.well-known/jwks.json` | RS256 public key for JWT verification |
| POST | `/login/challenge` | Issue a one-time nonce for an AID |
| POST | `/login/verify` | Verify signature + credential, issue JWT |

## Config

See `app/settings.py` for the full list. All `DS__*` env vars.

## Tests

```bash
poetry run pytest -v
```
