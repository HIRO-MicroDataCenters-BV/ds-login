# ds-login

**Login + credential verification for the Hiro dataspace.** Accepts a user's
BYOK AID, verifies the signature against the DKMS witness/watcher network,
verifies the ACDC credential presented by the user, and issues a short-lived
JWT that every ds-* service verifies via [`ds-auth`](https://github.com/HIRO-MicroDataCenters-BV/ds-auth).

## Where it sits

```
   USER (holds AID + private key + ACDC credential)
     │
     ▼
   ds-login  ──────────────► DKMS watcher ────► DKMS witnesses
     │        (verify sig against KEL;
     │         verify ACDC credential chain)
     │
     ▼
   JWT (RS256, 15-min TTL, carries role + institute from the ACDC)
     │
     ▼
   every ds-* service checks the JWT via ds-auth, calls ds-policy-engine
   for the per-request permission decision
```

## Repository layout

| Directory | Purpose |
|-----------|---------|
| `server/` | FastAPI service, Dockerfile, Helm chart, tests |
| `server/app/` | Application code |
| `server/charts/server/` | Helm chart |
| `server/tests/` | Pytest suite |

## Status

**Phase 1 — initial scaffold.** Signature verification + JWT issuance work.
ACDC envelope parsing works. The hardening checks (issuer-signature
verification against issuer KEL, TEL revocation checks, trust-list enforcement)
are **stubs with clear TODOs** — see [ROADMAP.md](./ROADMAP.md).

Local development runs today against the Phase 0 `byok-local` stack
(keriox witnesses on `:3232-3234`, watcher on `:3235`).

## Where ds-login talks to DKMS

The watcher and witness URLs are **fully configurable** via Helm values.
Partner-node deployments override them per node:

```yaml
dkms:
  watcherUrl: "http://keriox-watcher.hus-services.svc.cluster.local:3235"
  witnessUrls:
    - "http://keriox-witness1.hus-services.svc.cluster.local:3232"
```

DKMS deployment onto Hiro infrastructure is a parallel workstream — tracked in
`ds-gitops` under each partner's services directory.

## Why this exists (and what it replaces)

The Phase 0 `byok-local/verify/verify.py` prototype proved the login flow
end-to-end against a local docker-compose stack. ds-login promotes that
prototype into a production `ds-*` service with the structure, Helm chart,
GitOps, and CI the rest of the family uses.

See [PROMOTION.md](./PROMOTION.md) for the migration history.

## Quick start

```bash
cd server
poetry install
poetry run uvicorn app.main:app --reload --port 8080
```

Then:

```bash
curl -s http://localhost:8080/health-check/
curl -s http://localhost:8080/.well-known/jwks.json
```

For a real login flow, use the `byok-local/wallet` CLI to create an AID and
sign a challenge; see the `byok-local` README for the end-to-end script.

## License

Apache-2.0
