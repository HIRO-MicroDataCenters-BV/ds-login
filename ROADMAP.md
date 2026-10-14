# ds-login — roadmap

Tracked explicitly because this service holds the "trust me, this user is who
they claim to be" invariant for the whole dataspace. Each item below is one
PR, with the hardening order chosen so the service stays usable at every
step.

## Phase 1 (initial scaffold — this commit)

- [x] FastAPI service, Poetry packaging, settings via env
- [x] Challenge issuance + signature verification
- [x] JWT issuance (RS256) with JWKs publication
- [x] ACDC envelope parsing + subject-binding check
- [x] Disk fallback for KEL resolution (dev-only)
- [x] Dockerfile + Helm chart
- [x] CI workflow (lint, type-check, tests)
- [x] Tests for health, JWKs, ACDC parser, challenge store

## Phase 1b (short follow-ups, open PRs)

- [ ] Watcher-side `qry` message construction (`core/kel_resolver.py`)
- [ ] Signing-key secret loading hardened (test the Kubernetes secret mount path)
- [ ] `/login/revoke` + token-revocation list consulted by `ds-auth`

## Phase 2 (ACDC hardening — the credential chain)

- [ ] **Issuer signature verification**  
      Verify the ACDC envelope's signature against the issuer AID's KEL.
      Requires the KelResolver to be able to resolve ANY AID (not just the
      user's), which means the watcher must be subscribed to the issuer's
      witnesses too (or trust-list the issuer's witness URLs).
- [ ] **TEL (Transaction Event Log) revocation check**  
      Query the issuer's registry TEL for the credential SAID. If revoked
      → reject.
- [ ] **Schema SAID verification**  
      Verify the credential's `s` field points to a known schema (prevents
      claim-shape forgery).
- [ ] **Trust-list enforcement**  
      Credentials from issuers not on the configured trust list are
      rejected. Currently a soft-warn.

## Phase 3 (operational hardening)

- [ ] Metrics (Prometheus) — login success/failure counts, latency,
      watcher health
- [ ] Audit stream — every successful login + failure reason emitted as an
      event to `ds-clearing-house`
- [ ] Rate limiting per AID + per IP
- [ ] Signing-key rotation flow (publish both old + new in JWKs during
      transition window)

## Phase 4 (federation + cross-stack)

- [ ] Cross-partner trust-list sharing — HUS trusts KI's ds-login signing
      key via published JWKs
- [ ] CF (Cognitive Framework) Dex bridge — ds-login's JWT federated to CF's
      Dex so a single login covers both stacks
- [ ] HCF DID-creation UI integration — when HCF's end-user DID UI ships,
      ds-login accepts the AIDs it produces natively

## Non-goals

- **Password-based login.** ds-login is BYOK-only by design.
- **Issuing credentials.** That's the issuer side (consortium, each
  partner's own org); ds-login verifies, does not issue.
- **Session storage.** JWTs are stateless by design; no server-side session.
