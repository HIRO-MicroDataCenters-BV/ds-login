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

## Phase 1b — direct witness KEL + IPEX grant verify (LANDED)

The verifier accepts credentials from **any DKMS-anchored issuer**: witness
URLs are extracted from the OOBIs embedded in each incoming IPEX grant and
queried directly. Open-federation model, no Hiro-side watcher required on
the verify path.

- [x] `witness_client.py` — HTTP client for OOBI + TEL endpoints
- [x] `ipex_grant.py` — parse grant envelope, extract issuer OOBIs
- [x] `kel_resolver.resolve_from_oobis` — direct witness query, in-process
      KERIpy CESR parse via a transient `Baser` + `Kevery`
- [x] `acdc_verifier.verify_grant` — subject binding + issuer sig against
      issuer's live KEL
- [x] API: `VerifyRequest.credential_grant` field alongside the legacy
      `credential` field (bare ACDC kept for Phase 0 wallets during migration)

## Phase 1c — remaining hardening (open PRs)

- [ ] **TEL revocation check** — the Phase 1b stub returns True iff a
      witness responded with any TEL body for the credential SAID; replace
      with full event-stream parse so revocation decisions are real.
      Requires pinning the keriox 0.18.0 TEL endpoint shape upstream.
- [ ] **Signed `qry` to witness** — the Phase 1b path uses the unsigned
      OOBI GET, which returns a point-in-time KEL snapshot. A signed `qry`
      lets us ask for "latest state since seq N" and get authenticated
      receipts. Needs ds-login to possess its own KERI AID + Habery.
- [ ] **Schema SAID verification** — resolve `credential.s` against a
      trusted-schema registry (prevents claim-shape forgery).
- [ ] **Signing-key secret loading** — exercise the Kubernetes secret mount
      path in staging; current code works but the Helm wiring is untested
      end-to-end.
- [ ] **`/login/revoke`** + token-revocation list consulted by `ds-auth`.

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
