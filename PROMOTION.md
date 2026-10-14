# Migration note: promotion from byok-local/verify

This repository started as a promotion of the Phase 0 prototype at
`C:\sai\byok-local\verify\verify.py` into a production-shape `ds-*` service.

## What was copied over

The verification pipeline from the Phase 0 service:

- Challenge issuance (POST `/login/challenge`)
- Signature verification against the AID's current public key
- JWT issuance (RS256, 15-min TTL)
- JWKs publication (GET `/.well-known/jwks.json`)
- KEL loading (now via watcher primarily; disk fallback for dev)

## What was added (not in Phase 0)

- Proper Poetry packaging + pyproject.toml
- `Settings` with env-var layering (`DS__*`)
- Dockerfile matching the ds-* convention
- Helm chart (deployment, service, ingress, serviceaccount)
- CI workflow (lint, type-check, tests, build)
- ACDC credential acceptance in `/login/verify` (envelope parsing + binding
  check in Phase 1; cryptographic chain in Phase 2 per ROADMAP.md)
- Signing-key loading from Kubernetes secret (Phase 0 generated a transient
  key on startup — not production-safe)
- Watcher URL configurable (Phase 0 read KELs from disk only)

## What is deliberately deferred

- Full ACDC chain verification (issuer signature via issuer KEL; TEL
  revocation; schema SAID verification). Phase 2 — see ROADMAP.md.
- Watcher-side signed `qry` message construction. Phase 1b — the thin
  helper in `KelResolver._resolve_via_watcher` is a stub today.
- CF (Cognitive Framework) Dex federation. Separate workstream.

The Phase 0 service in `byok-local/verify/` remains in the repository until
ds-login is deployed and verified against partner infrastructure. After that
the Phase 0 directory becomes archival.
