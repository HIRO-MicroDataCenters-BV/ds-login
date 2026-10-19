# ADR 0001 — Why ds-login, not DauthZ

**Status:** Accepted
**Date:** 2026-10-19
**Deciders:** Sai Kireeti (DKMS/identity owner, Hiro), HCF (adoption preference stated, not mandated)
**Scope:** Identity + verification layer for the NextGen EU dataspace at HIRO sites (HUS, KI, UVA) for M36 and the near term beyond.

## Context

HCF prefers [DauthZ](https://github.com/THCLab/DauthZ) as the common KERI-based identification + authorization layer across NextGen participants. The preference is not a mandate — each site is free to run its own identity service as long as it speaks KERI + ACDC on the wire.

HIRO already runs [`ds-login`](https://github.com/HIRO-MicroDataCenters-BV/ds-login) + [`ds-policy-engine`](https://github.com/HIRO-MicroDataCenters-BV/ds-policy-engine) with [`ds-auth`](https://github.com/HIRO-MicroDataCenters-BV/ds-auth) as service middleware across every `ds-*` service. This ADR records why we keep our own stack rather than adopt DauthZ.

## Comparison

|  | DauthZ (THCLab) | ds-login (HIRO) |
|---|---|---|
| **Crypto backend** | Shells out to the `dkms` CLI binary | In-process KERIpy |
| **Known-bug exposure** | Inherits all four `dkms-bin v0.8.2` verify bugs we reproduced (tampered-ACDC-accepted, revoked-returns-ok, no claim+proof binding, identifier-export-leaks-seed) | None — in-process KERIpy was chosen specifically to avoid them |
| **Token format** | Opaque session token | Standard RS256 JWT with `/.well-known/jwks.json` discovery |
| **Authorization model** | Account-based (login maps AID → account id → coarse permissions) | Claims → OPA/Rego via `ds-policy-engine` (per-request, fine-grained) |
| **ACDC verify** | Mentioned only as "consortium-issued credential" at the gate layer; verify path not documented | Full IPEX grant parse + issuer-signature verify against the issuer's live KEL (open-federation model) |
| **Trust model** | Service-registered accounts | Any DKMS-anchored issuer accepted; trust anchored in KERI's own cryptography |
| **Language / integration** | Rust SDK + nginx `auth_request` sidecar | FastAPI + reusable Python `ds-auth` middleware (shared across every `ds-*` service) |
| **Login UI** | Ships `dauthz-login-ui` as a drop-in page | Not yet; see "Where DauthZ might still slip in" below |

## Decision

Keep `ds-login` as the HIRO identity service. Do not adopt DauthZ for HUS, KI, or UVA.

## Rationale

1. **DauthZ would re-introduce the `dkms-bin` verify bugs we deliberately avoided.** The DauthZ server delegates every cryptographic verify to the `dkms` CLI, which is the exact binary carrying the four bugs reproduced in `C:\sai\repro\dkms_repro.sh`. Choosing in-process KERIpy for `ds-login` was a conscious hardening decision; switching to DauthZ reverses it.
2. **Authorization model mismatch.** `ds-policy-engine` + OPA/Rego already give us per-request decisions on `role`, `institute`, and arbitrary attributes. DauthZ's account-based model would either kill that flexibility or force us to run both (two sources of truth, divergence inevitable).
3. **Token-format compatibility.** RS256 JWTs with JWKs discovery are consumable by any standards-based JWT library — a prerequisite for cross-site federation and external partner integration. DauthZ's opaque session tokens require every consumer to speak DauthZ.
4. **Done cost + ongoing cost.** `ds-login` is deployed, tested end-to-end locally, and in production at HUS. Switching to DauthZ would mean replacing a working service with one we don't own, written in a language we don't operate (Rust), with a different ops profile.

## Where DauthZ might still slip in (and when to re-evaluate)

- **`dauthz-login-ui`** as a drop-in UX page sitting in front of `ds-login`. Pure UI, no backend lock-in. Worth considering when we need a login page and don't want to write our own.
- **"DKMS login" replacing the colossi.network password** (announced for the week of 2026-10-20). If HCF's rollout turns out to be DauthZ-based and expects a compatible server endpoint, we'll add a thin DauthZ-shape compatibility layer to `ds-login` without switching the verify path. Watch and decide when the rollout lands.
- **An NextGen-wide mandate for DauthZ-compatible endpoints.** HCF stated this is not current intent, but if it changes, revisit this ADR.

## Follow-up triggers (events that force a re-evaluation of this ADR)

- HCF mandates DauthZ as the common NextGen identity layer (today it's preference, not mandate).
- Cross-site federation requires DauthZ-shape tokens at ingress boundaries.
- The four `dkms-bin` v0.8.2 verify bugs are fixed upstream AND the DauthZ account model gains per-request policy support (both would need to happen before DauthZ catches up to `ds-login` + `ds-policy-engine`).
- A security review finds in-process KERIpy to be the weaker link (unlikely given the dkms-bin bug record, but worth stating).

## References

- `ds-login` — https://github.com/HIRO-MicroDataCenters-BV/ds-login
- `ds-policy-engine` — https://github.com/HIRO-MicroDataCenters-BV/ds-policy-engine
- `ds-auth` — https://github.com/HIRO-MicroDataCenters-BV/ds-auth
- DauthZ — https://github.com/THCLab/DauthZ
- dkms-bin v0.8.2 bug repro — `C:\sai\repro\dkms_repro.sh` + `C:\sai\repro\DKMS_repro_*.pdf`
- NextGen hosted docs — https://nextgen.colossi.network (login nextgen / password rotates to DKMS login week of 2026-10-20)
