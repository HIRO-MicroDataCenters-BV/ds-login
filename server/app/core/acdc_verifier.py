"""ACDC credential verifier.

**Status:** PLACEHOLDER — accepts an ACDC payload, parses it, and extracts
identity claims (role, institute, name, email). Does NOT currently verify
the issuer signature or TEL revocation. See ROADMAP.md.

The verifier is written so the public API won't change when the real
cryptographic checks land — services calling `verify(credential_dict)` get
the same return shape today and after the hardening PR.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any


log = logging.getLogger(__name__)


class CredentialVerificationError(Exception):
    """Credential rejected for any reason — binding, authenticity, revocation."""


@dataclass
class VerifiedCredential:
    """Result of a successful credential verification."""

    said: str                # ACDC envelope SAID (`d` field)
    subject_aid: str         # the AID this credential was issued to (`a.i`)
    issuer_aid: str          # the AID that issued the credential (`i`)
    attributes: dict[str, Any]  # the `a.a` block — role, institute, name, email, ...


class AcdcVerifier:
    """Verifies an ACDC credential.

    Phase 1 (current):
      * SAID present
      * subject_aid matches the user's AID
      * attributes are extractable

    Phase 2 (hardening — tracked in ROADMAP.md):
      * verify envelope signature using issuer's current KEL (via KelResolver)
      * check TEL registry for revocation
      * verify schema SAID
      * verify issuer is on the trust list
    """

    def __init__(self, trusted_issuers: set[str] | None = None):
        self.trusted_issuers = trusted_issuers or set()

    def verify(
        self,
        credential: dict[str, Any],
        subject_aid: str,
    ) -> VerifiedCredential:
        """Verify a credential presented for `subject_aid`."""
        if not isinstance(credential, dict):
            raise CredentialVerificationError("credential must be a JSON object")

        said = credential.get("d")
        if not said:
            raise CredentialVerificationError("credential missing SAID (`d` field)")

        issuer_aid = credential.get("i")
        if not issuer_aid:
            raise CredentialVerificationError("credential missing issuer (`i` field)")

        attributes_block = credential.get("a") or {}
        actual_subject = attributes_block.get("i")
        if actual_subject != subject_aid:
            raise CredentialVerificationError(
                f"credential subject {actual_subject!r} does not match login AID {subject_aid!r}"
            )

        attributes = attributes_block.get("a") or {}
        if not isinstance(attributes, dict):
            raise CredentialVerificationError(
                "credential attribute block (`a.a`) is not a JSON object"
            )

        # ───── Hardening checks go here (not yet implemented) ─────
        # 1. Verify envelope signature against issuer's current KEL
        # 2. Verify issuer is on the trust list
        # 3. Check TEL for revocation
        # 4. Verify schema SAID matches a known schema
        # See ROADMAP.md for the implementation plan.
        if self.trusted_issuers and issuer_aid not in self.trusted_issuers:
            # Soft-warn until the full chain is wired — don't reject in Phase 1
            log.warning(
                "credential issuer %s not in configured trust list — accepting "
                "in Phase 1 (hardening deferred)", issuer_aid,
            )

        return VerifiedCredential(
            said=said,
            subject_aid=subject_aid,
            issuer_aid=issuer_aid,
            attributes=attributes,
        )
