# ADR 0002 — Delegate KERI protocol I/O to HCF's `dkms-bin`; keep KERIpy for verify

**Status:** Accepted
**Date:** 2026-10-26
**Deciders:** Sai Kireeti (DKMS / identity owner, Hiro), Rahul (end-to-end audit)
**Scope:** The on-the-wire KERI protocol flow — identifier enrolment, witness receipting, watcher subscription, OOBI publication, mesagkesto delivery, ACDC minting — in `ds-credential-issuer` and (follow-up PR) the holder-side wallet. The **verify** path in `ds-login` is explicitly outside this ADR's scope.

## Context

ADR 0001 (May–October 2026) chose to build Hiro's own identity + credential stack (`ds-login`, `ds-credential-issuer`, `ds-auth`, `ds-policy-engine`) on top of **KERIpy as a Python library**, specifically to avoid shelling out to HCF's `dkms-bin v0.8.2` — a binary we had reproduced four security-relevant verify bugs in (tampered-ACDC-accepted, revoked-returns-ok, no claim+proof binding, identifier-export-leaks-seed). The ADR's four stated reasons were:

1. **Avoid the dkms-bin verify bugs** — operational and security-posture argument.
2. **OPA/Rego per-request authorization** — richer than DAuthZ's account-based model.
3. **Standards-based RS256 JWT with JWKs discovery** — enables cross-site federation and third-party library integration; opaque session tokens do not.
4. **Done cost / ongoing cost** — we had the stack working at HUS; switching felt wasteful.

Points 1, 2 and 3 remain true today. Point 4 collapsed under contact with reality.

### What we learned deploying to HUS

Across October 2026 we deployed the full stack to the HUS cluster and had Rahul run an end-to-end audit. His twelve findings fell cleanly into two groups:

- **Our own code bugs** — the claims-path mismatch (`acdc.a.a` vs `acdc.a`), the chart `fsGroup` nil-pointer, missing OCA/schema registry wiring, a few workflow issues. Those are fixable in-house.
- **Protocol-level gaps that KERIpy as a library does not actually fill.** This is the finding this ADR is about.

Specifically, the HCF-prescribed KERI protocol flow has four pieces that we did not — and probably cannot cheaply — replicate on top of KERIpy alone:

1. **Active witness submission after inception.** `KERIpy.makeHab(wits=[WITNESS_AID])` only puts the witness in the inception event's `b` field. It does *not* POST the inception event over the wire to the witness, wait for the receipt, retry on failure, or persist the receipt. HCF's `dkms identifier init --witness-url ...` does all of that atomically. Without it, no witness ever stores the issuer's KEL, and every verifier downstream fails to resolve the issuer's OOBI. We observed this exact failure: the issuer AID was minted, listed its witness in `b`, and the witness returned 0 bytes on `/oobi/<issuer-AID>` for days.
2. **Watchers serve third-party OOBIs; witnesses do not.** The keriox witness implementation serves `/oobi/<AID>` only for its own AID. OOBI resolution for arbitrary third-party AIDs is a *watcher* responsibility. HCF's `dkms-bin` knows this — `dkms identifier oobi get` returns watcher-served URLs. Our chart's `witnessOobiBases` concept pointed at the wrong service and would have been architecturally wrong even if witness submission had worked.
3. **Mesagkesto `/resolve` pre-registration.** HCF's mesagkesto expects both the sender's and the recipient's OOBIs to be POSTed to its `/resolve` endpoint *before* an exchange message is delivered. We did not know this; our mesagkesto integration would have silently failed on the first grant delivery.
4. **ACDC claims nesting.** HCF's `dkms-bin` and the published test vectors write ACDC claims under `.a.a` (with `.a.d` being the SAID of the attributes block). KERIpy's `SerderACDC` writes claims flat under `.a`. The two formats are not interoperable, and we were on the KERIpy side without realising HCF ran on the dkms-bin side.

Rahul's audit surfaced some of these; the `dkms-demo` repo's `test-vectors/test_issue.sh` file documented the rest explicitly. The point is: KERIpy is a library, not a protocol implementation. The protocol flow — the sequencing, the retries, the receipts, the OOBI publication — lives in `dkms-bin`.

We could reimplement all four pieces on top of KERIpy. That is a 2–3 week of engineering project, during which we would be re-deriving behaviour that already exists, is tested, and is HCF-maintained. The sunk-cost argument in ADR 0001 point 4 cuts the other way now: continuing to reinvent is more expensive than switching.

## Decision

**We adopt a facade pattern: our Python services (`ds-credential-issuer`, follow-up `ds-login` holder-side helpers) keep their HTTP surface, their JWT issuance, their OPA integration — but delegate all on-the-wire KERI protocol operations to HCF's `dkms-bin` as a baked-in subprocess.**

Concretely for Phase 1 (this PR):

- `ds-credential-issuer`'s image bakes `dkms-bin v0.8.2` at `/usr/local/bin/dkms`.
- `issuer_habery.init_handle()` shells `dkms identifier init --witness-url ... --watcher-url ...` instead of calling KERIpy's `hby.makeHab(wits=[])`.
- `acdc_issuer.issue()` shells `dkms data issue -a <alias> -m <ACDC> -b <OCA bundle SAID> -o` and parses the ACDC body + signature out of the returned CESR stream, instead of calling KERIpy's `proving.credential()` + `hab.sign()`.
- The IPEX grant now carries the watcher-served OOBI URLs returned by `dkms identifier oobi get`, which actually resolve.

Explicitly out of scope — and intentionally retained in Python / KERIpy:

- **ACDC verify** in `ds-login` (`acdc_verifier.py`). This is where ADR 0001's four verify bugs would land if we delegated. The verifier continues to parse CESR with KERIpy's `Kevery` and verify the issuer signature against the issuer's live KEL in-process. The only change on the verify side is that it will accept both the flat `.a` claim shape (KERIpy issuers) and the nested `.a.a` shape (dkms-bin issuers) — a one-line change that unlocks cross-compat without changing the verify algorithm.
- **JWT issuance** in `ds-login`. We continue to mint RS256 JWTs with `/.well-known/jwks.json` discovery. DAuthZ's session-cookie + nginx `auth_request` model is not adopted.
- **Policy evaluation** in `ds-policy-engine`. OPA / Rego per-request decisions remain our authorization model.
- **The ds-auth middleware pattern** across every ds-* service. Downstream services still verify Bearer JWTs via JWKs discovery and consult `ds-policy-engine`.
- **DAuthZ as a dependency.** `DAuthZ` is a HTTP + session-cookie wrapper around `dkms-bin`. Since we keep our own HTTP + JWT layer, importing DAuthZ would add a layer with no benefit. We adopt only the subprocess calls to `dkms-bin` itself.

## Rationale

### Why delegate protocol I/O to `dkms-bin`

- **Correctness.** `dkms-bin` is HCF's reference implementation. It is tested against keriox witnesses + watchers in the `dkms-demo` suite. It handles the submission, receipting, OOBI publication, mesagkesto `/resolve` registration and ACDC envelope that we would otherwise re-derive from protocol documents.
- **Interoperability.** Any other NextGen participant running on HCF's reference stack can resolve our issuer's OOBIs, verify our grants, and ingest our ACDCs because we produce the exact byte shapes they expect. The `.a.a` claims nesting alone would have taken a round of cross-site debugging to find without this.
- **Shrinks our maintenance surface.** The protocol flow is roughly 500–1000 lines of code we no longer own. We own the FastAPI handlers, the JWT path, the policy layer — the parts that differentiate us.

### Why keep `KERIpy` for verify

- **ADR 0001 point 1 still applies.** `dkms-bin v0.8.2` is still the latest release as of this ADR's date (February 2026 release, no v0.9.x). The four verify bugs we reproduced in `C:\sai\repro\dkms_repro.sh` are still live, unpatched, and have no corresponding tracked issues on `THCLab/dkms-bin`. Delegating verify to `dkms-bin` ships four known security holes to production. Keeping verify in `KERIpy` keeps our risk posture where it was.
- **Verify is architecturally separable.** `ds-login`'s verifier takes an ACDC + the issuer's OOBI, resolves the KEL, extracts the current signing key, and checks the signature. None of that benefits from `dkms-bin`'s protocol-flow strengths — it is a pure cryptographic computation, which `KERIpy` does correctly.
- **One-line cost of cross-compat.** `KERIpy`'s verifier can be taught to accept both `.a` and `.a.a` claim shapes with a two-key fallback. That cost is trivially small compared to inheriting the verify bugs.

### Why not full DAuthZ

- DAuthZ is a session-cookie + nginx `auth_request` service. Downstream integration means every `ds-*` service drops `Bearer`-JWT verification and reads nginx-provided headers instead.
- No `.well-known/jwks.json` endpoint means no standards-based third-party integration.
- No per-request OPA hook; DAuthZ is account-based.
- Adopting DAuthZ would reverse ADR 0001 points 2 and 3 as well, which this ADR does not want to do. The scope of the pivot is deliberately narrow.

### Why not keep inventing on `KERIpy` alone

- Estimated 2–3 weeks of engineering to replicate the protocol-flow pieces (witness submission with retry, watcher subscription, mesagkesto `/resolve`, OOBI publication) in Python. During that time, every end-to-end integration test fails. HUS cannot host the credential-issuer convincingly for the M36 review in December 2026. KI and UVA rollouts are blocked behind that.
- Replicates behaviour that is already free. The only argument for doing so was "pride of ownership", which is not a legitimate engineering reason.

## Consequences

### Positives

- End-to-end flow becomes testable within days: issuer AID actually anchored at the witness, OOBI actually resolves, grant actually verifies, JWT actually issues, policy actually fires.
- We benefit from any future `dkms-bin` fix for protocol-flow bugs automatically, by bumping the binary.
- Our image size grows by ~7 MB (one static binary). Startup time grows by one subprocess per boot. Both are negligible.
- Cross-site interop with any other HCF-reference-stack participant works by construction.

### Negatives / trade-offs we accept

- A new runtime dependency (one static Rust binary) on `ds-credential-issuer`'s image. Operational: we must track upstream `dkms-bin` releases and bump the pin on security advisories.
- `dkms-bin` state lives on the PVC under `$HOME/.dkms-dev-cli/`. This mingles with KERIpy's own LMDB files during the migration — tolerable while legacy fields remain, must be cleaned up when we delete the legacy path.
- OCA bundle SAIDs become a required input to `data issue`. Until the schema registry lands, a per-site `default_oca_bundle_said` is a configuration burden.
- The subprocess invocation surface is a security boundary we must own: no shell interpolation of user input (`shell=False`, args list, explicit timeouts). This is reflected in the `DkmsBridge` implementation.
- Debugging a failure in the subprocess layer means reading `dkms`' CLI stderr, which is less convenient than tracing in-process Python. We accept this.

## Where ADR 0001's reasoning still stands

ADR 0001 argued four things. After this pivot:

1. **Avoid the dkms-bin verify bugs** — still true. We do not call `dkms data verify`.
2. **OPA/Rego per-request authorization** — still true. `ds-policy-engine` + `ds-auth` middleware unchanged.
3. **Standards-based JWT + JWKs discovery** — still true. `ds-login` still mints and publishes JWTs.
4. **Done cost / ongoing cost** — this one shifted. ADR 0001 said rewrites were expensive; today we are rewriting *less* than we would be if we tried to replicate the HCF protocol flow in-house.

So this ADR partially reverses ADR 0001 point 4 and amends the implementation details, but does not touch points 1, 2 or 3. ADR 0001 remains in force for the verify path.

## Follow-up triggers (events that force a re-evaluation of this ADR)

- `THCLab/dkms-bin` releases `v0.9.x` with the four verify bugs fixed and documented. At that point delegating verify to `dkms-bin` becomes attractive and ADR 0001 point 1 narrows. Re-open this ADR to extend the facade to the verify path.
- `KERIpy` releases a version that natively implements the protocol-flow pieces (witness submission with retry, OOBI publication, mesagkesto `/resolve`). At that point the subprocess facade becomes net cost. Re-open this ADR to roll back.
- An alternative KERI reference stack (not HCF-maintained) becomes dominant in the EU dataspace landscape. Re-open to compare.
- `dkms-bin`'s binary distribution becomes unavailable (THCLab removes releases, licensing change, etc.). Re-open to decide between vendoring and reverting.

## Non-triggers (events that do NOT force a re-evaluation)

- HCF publicly recommending DAuthZ as the consortium's identity stack. We have already explained in ADR 0001 why we do not adopt it; that reasoning is unchanged.
- New verify bugs discovered in `dkms-bin`. Our verify path doesn't use it; impact is zero.
- Protocol-flow bugs discovered in `dkms-bin`. Fix comes free with the next pin bump.

## References

- `ds-credential-issuer` PR #19 — the Phase 1 implementation of this facade.
- `C:\sai\repro\dkms_repro.sh` + `DKMS_repro_*.pdf` — the four verify-bug reproducers that still gate the verify-path decision in ADR 0001.
- `THCLab/dkms-demo` repo, specifically `test-vectors/test_issue.sh` — the HCF-prescribed protocol flow, which this ADR mirrors.
- `THCLab/dkms-bin` v0.8.2 — the binary we delegate to.
- `THCLab/DauthZ` — the HCF HTTP+cookie service, deliberately not adopted.
- ADR 0001 — the earlier decision this ADR partially amends.
