"""ACDC credential verifier.

Verifies a presented IPEX grant end-to-end:

1. **Parse** the grant envelope (``ipex_grant.parse``). Extract the ACDC, the
   issuer AID, the subject AID, the issuer's signature over the ACDC, and the
   OOBIs needed to reach the issuer's witnesses.
2. **Trust gate** — the issuer AID must be on the server's trusted-issuer
   allowlist (``DS__TRUSTED_ISSUER_AIDS``). Without this check, any AID can
   self-issue role=admin, bind it to itself, sign it with its own key, and
   present a grant whose KEL it also controls. The chain is cryptographically
   valid; only policy stops it. Fail-safe default: empty list rejects every
   grant.
3. **Subject binding** — the ACDC's ``a.i`` field must equal the AID that
   just signed the login challenge. Prevents a presented credential from
   being bound to someone else.
4. **Resolve the issuer's KEL** directly from the OOBIs in the grant
   (``KelResolver.resolve_from_oobis``) or inline (``iss_kel_cesr``). The
   verifier does NOT consult a pre-configured watcher — any trusted issuer
   supplies the location of its own witnesses. This is the open-federation
   model, gated by step 2.
5. **Verify the issuer signature** against the issuer's **current** signing
   key as recorded in the KEL we just resolved. This is the step that
   rejects a forged credential and a credential signed with a rotated-away
   key.
6. **TEL revocation check** — query one of the issuer's witnesses for the
   current state of the credential's TEL entry (stubbed in Phase 1b; the
   interface is wired, the keriox TEL endpoint is called out as a Phase 1c
   follow-up because the exact witness route is still in flux upstream).

Phase 1b leaves these for Phase 1c:

* Schema SAID resolution against a trusted-schema registry
* Signed ``qry`` to query a live KEL (unsigned OOBI GET is sufficient for
  the demo — gives a point-in-time snapshot)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from . import ipex_grant
from .kel_resolver import KelResolutionError, KelResolver
from .signature_verifier import SignatureVerificationError, SignatureVerifier
from .witness_client import WitnessClient, WitnessUnreachableError

log = logging.getLogger(__name__)


class CredentialVerificationError(Exception):
    """Credential rejected for any reason — binding, authenticity, revocation."""


@dataclass
class VerifiedCredential:
    """Result of a successful credential verification."""

    said: str
    subject_aid: str
    issuer_aid: str
    attributes: dict[str, Any]
    issuer_pub_key_qb64: str
    revocation_checked: bool  # Phase 1c flips this to always-True once TEL lands


class AcdcVerifier:
    """Open-federation ACDC verifier.

    Accepts credentials from ANY DKMS-anchored issuer. The trust model is
    anchored in the issuer's KEL: a credential is valid iff the issuer
    actually signed it with their current signing key, and the issuer's
    identity (AID) is self-asserted via KERI's own cryptographic chain.
    """

    def __init__(
        self,
        kel_resolver: KelResolver,
        signature_verifier: SignatureVerifier | None = None,
        witness_client: WitnessClient | None = None,
        trusted_issuer_aids: list[str] | None = None,
    ) -> None:
        self.kel_resolver = kel_resolver
        self.sig_verifier = signature_verifier or SignatureVerifier()
        self.witness = witness_client or WitnessClient()
        # Normalise to a set for O(1) lookup. None → empty set →
        # reject-all (fail-safe default when the caller forgot to pass).
        self.trusted_issuer_aids: frozenset[str] = frozenset(trusted_issuer_aids or ())

    # ─── Primary entry point (new in Phase 1b) ──────────────────────────

    def verify_grant(
        self,
        grant: dict[str, Any],
        subject_aid: str,
    ) -> VerifiedCredential:
        """Verify an IPEX grant presented for ``subject_aid``.

        This is the end-to-end path for the open-federation demo. See the
        module docstring for the full step list.
        """
        # 1. Parse envelope ---------------------------------------------
        try:
            parsed = ipex_grant.parse(grant)
        except ipex_grant.GrantParseError as e:
            raise CredentialVerificationError(f"grant malformed: {e}") from e

        # 2. Trust gate — issuer MUST be on the allowlist ---------------
        # Without this check, a stranger with a laptop can mint a KERI
        # AID, self-sign an ACDC claiming role=admin bound to themselves,
        # and present a grant carrying their own KEL. The chain checks
        # out cryptographically (self-addressing SAID, self-signed) and
        # the server would issue a JWT with admin claims.
        #
        # This runs BEFORE KEL resolution so an attacker's grant can't
        # even cause us to parse a malicious inline KEL via KERIpy.
        # Empty allowlist = reject-all (fail-safe default).
        if parsed.issuer_aid not in self.trusted_issuer_aids:
            raise CredentialVerificationError(
                f"credential issuer {parsed.issuer_aid!r} is not on this "
                "verifier's trusted-issuer allowlist. Set "
                "DS__TRUSTED_ISSUER_AIDS to include it if this is a known "
                "issuer, otherwise the grant is rejected."
            )

        # 3. Subject binding --------------------------------------------
        if parsed.subject_aid != subject_aid:
            raise CredentialVerificationError(
                f"credential subject {parsed.subject_aid!r} does not match "
                f"login AID {subject_aid!r}"
            )

        # 4. Resolve issuer KEL ------------------------------------------
        # Prefer the inline KEL (dkms-bin facade grants carry it directly
        # in iss_kel_cesr — see ADR 0002). The resolver parses the CESR
        # stream in-process with KERIpy, keeping ADR 0001's verify path
        # intact and sidestepping the keriox watcher's limitation of not
        # serving third-party KELs over plain HTTP.
        try:
            if parsed.issuer_kel_cesr:
                issuer_kel = self.kel_resolver.resolve_from_cesr_stream(
                    parsed.issuer_aid, parsed.issuer_kel_cesr,
                )
            else:
                issuer_kel = self.kel_resolver.resolve_from_oobis(
                    parsed.issuer_aid, parsed.issuer_oobi_urls
                )
        except KelResolutionError as e:
            raise CredentialVerificationError(
                f"issuer {parsed.issuer_aid!r} KEL unresolvable: {e}"
            ) from e

        current_keys = issuer_kel.get("current_public_keys") or []
        if not current_keys:
            raise CredentialVerificationError(
                f"issuer {parsed.issuer_aid!r} KEL has no current signing key"
            )

        # 5. Verify issuer signature ------------------------------------
        serialized_acdc = _canonical_acdc_bytes(parsed.acdc)
        sig_valid = False
        last_sig_error: Exception | None = None
        for key_qb64 in current_keys:
            try:
                if self.sig_verifier.verify(
                    public_key_qb64=key_qb64,
                    data=serialized_acdc,
                    signature_qb64=parsed.issuer_signature_qb64,
                ):
                    sig_valid = True
                    issuer_pub_key = key_qb64
                    break
            except SignatureVerificationError as e:
                last_sig_error = e

        if not sig_valid:
            raise CredentialVerificationError(
                f"issuer signature invalid against KEL current key(s) "
                f"{current_keys} ({last_sig_error})"
            )

        # 6. TEL revocation check ---------------------------------------
        revocation_checked = self._check_not_revoked(parsed)

        # Claims live in one of two shapes depending on the issuer:
        #   * HCF (dkms-bin) nests them under `acdc.a.a.*` — the caller
        #     passes an attribute dict and dkms-bin wraps it in `a.a`.
        #     Subject binding and user-facing claims sit side-by-side.
        #   * KERIpy flat shape: claims flat at `acdc.a.*` alongside the
        #     KERI metadata `d`/`i`/`dt`. This is what unit tests use.
        # The parser already picked the shape — mirror its choice here.
        outer = parsed.acdc.get("a") or {}
        if not isinstance(outer, dict):
            raise CredentialVerificationError(
                "credential attribute block (`a`) is not a JSON object"
            )
        inner = outer.get("a")
        if isinstance(inner, dict) and isinstance(inner.get("i"), str) and inner.get("i"):
            attributes = inner
        else:
            attributes = outer

        log.info(
            "credential verified: issuer=%s subject=%s said=%s "
            "revocation_checked=%s",
            parsed.issuer_aid, parsed.subject_aid, parsed.credential_said,
            revocation_checked,
        )

        return VerifiedCredential(
            said=parsed.credential_said,
            subject_aid=subject_aid,
            issuer_aid=parsed.issuer_aid,
            attributes=attributes,
            issuer_pub_key_qb64=issuer_pub_key,
            revocation_checked=revocation_checked,
        )

    # ─── Legacy path (bare ACDC, no sig check — Phase 0 wallets) ────────

    def verify(
        self,
        credential: dict[str, Any],
        subject_aid: str,
    ) -> VerifiedCredential:
        """Backward-compat path: parse a bare ACDC, do subject binding only.

        Kept so Phase 0 wallets that don't produce IPEX grants yet continue
        to work during the migration. Does **not** verify the issuer's
        signature — that only becomes possible with the OOBIs embedded in a
        grant. Logs a prominent warning.
        """
        if not isinstance(credential, dict):
            raise CredentialVerificationError("credential must be a JSON object")

        said = credential.get("d")
        if not said:
            raise CredentialVerificationError("credential missing SAID (`d` field)")

        issuer_aid = credential.get("i")
        if not issuer_aid:
            raise CredentialVerificationError("credential missing issuer (`i` field)")

        outer = credential.get("a") or {}
        if not isinstance(outer, dict):
            raise CredentialVerificationError(
                "credential attribute block (`a`) is not a JSON object"
            )
        # Same two-shape handling as the grant path: HCF nests at a.a,
        # KERIpy fixtures are flat at a.
        inner = outer.get("a")
        if isinstance(inner, dict) and isinstance(inner.get("i"), str) and inner.get("i"):
            attributes = inner
        else:
            attributes = outer

        actual_subject = attributes.get("i")
        if actual_subject != subject_aid:
            raise CredentialVerificationError(
                f"credential subject {actual_subject!r} does not match "
                f"login AID {subject_aid!r}"
            )

        log.warning(
            "bare ACDC accepted without issuer-signature check (Phase 0 "
            "compat); upgrade wallet to send IPEX grant for issuer=%s",
            issuer_aid,
        )

        return VerifiedCredential(
            said=said,
            subject_aid=subject_aid,
            issuer_aid=issuer_aid,
            attributes=attributes,
            issuer_pub_key_qb64="",
            revocation_checked=False,
        )

    # ─── TEL check (stub for Phase 1b; interface wired) ─────────────────

    def _check_not_revoked(self, parsed: ipex_grant.ParsedGrant) -> bool:
        """Query the issuer's TEL state for this credential SAID.

        **Phase 1b scope:** if the grant carries registry metadata and a
        witness URL, we probe it and log the raw response. We do NOT yet
        parse the TEL event stream to decide iss/rev — that's Phase 1c once
        the keriox 0.18 TEL route is pinned down.

        Returns True iff a TEL query was successfully made (not whether the
        credential is actually revoked). Phase 1c returns True iff the TEL
        is actually in state ``issued``.
        """
        if not parsed.registry_said or not parsed.tel_witness_urls:
            log.info(
                "grant did not include registry_said / tel_witness_urls; "
                "skipping TEL check (Phase 1b)"
            )
            return False

        for witness_url in parsed.tel_witness_urls:
            try:
                tel = self.witness.fetch_tel_event(
                    witness_url=witness_url,
                    registry_said=parsed.registry_said,
                    credential_said=parsed.credential_said,
                )
            except WitnessUnreachableError as e:
                log.warning("TEL witness %s unreachable: %s", witness_url, e)
                continue

            # Phase 1c: parse `tel.body` with KERIpy's VDR verifier and
            # decide iss/rev. For now the mere fact that the witness
            # responded with ANY body for this SAID is a sanity signal.
            if tel.body:
                log.info(
                    "TEL query ok (bytes=%d) — full state parsing deferred "
                    "to Phase 1c", len(tel.body),
                )
                return True

        return False


def _canonical_acdc_bytes(acdc: dict[str, Any]) -> bytes:
    """Serialize an ACDC body for signature verification.

    KERI/ACDC uses a specific canonical form for signing (CESR-wrapped JSON
    with a version string). The reference implementation moved from the
    legacy ``keri.core.coring.Serder`` (removed in current KERIpy) to
    ``keri.core.serdering.SerderACDC``. We go through it so the bytes we
    hash match what the issuer signed.

    Verified byte-identical against a dkms-bin v0.8.2 issue+sign cycle:
    SerderACDC(sad=acdc).raw matches the exact bytes dkms-bin emits in
    its ACDC body, so an issuer that signs those raw bytes (as
    ds-credential-issuer PR #25 does) round-trips cleanly here.
    """
    try:
        from keri.core.serdering import SerderACDC
    except Exception as e:  # pysodium can raise TypeError on Windows
        raise CredentialVerificationError(
            f"KERIpy unavailable; cannot canonicalize ACDC for sig verify: {e}"
        ) from e

    # ``SerderACDC(sad=...)`` runs the ACDC-specific validation and emits
    # the canonical serialization. The input dict is already in canonical
    # shape (as emitted by ds-credential-issuer / dkms-bin), so this is a
    # byte-stable round-trip rather than a re-SAID.
    try:
        return bytes(SerderACDC(sad=acdc).raw)
    except Exception as e:  # KERIpy ad-hoc exception taxonomy
        raise CredentialVerificationError(
            f"could not canonicalize ACDC for signature verification: {e}"
        ) from e
