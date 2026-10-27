"""Request / response schemas for the login API."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ChallengeRequest(BaseModel):
    aid: str = Field(..., description="The AID the user is claiming to be")
    oobi_urls: list[str] | None = Field(
        default=None,
        description=(
            "Optional holder OOBI URLs. Passed to the KEL resolver so a "
            "fresh wallet whose KEL isn't yet in any Hiro-side watcher "
            "can still be challenged. Omit when the KEL is already "
            "published to the configured watcher."
        ),
    )
    holder_kel_cesr: str | None = Field(
        default=None,
        description=(
            "Inline holder KEL as a CESR stream (icp + receipts). "
            "Preferred over oobi_urls in the Phase 1 facade: keriox 0.17 "
            "watchers do not serve third-party KELs over plain HTTP, so "
            "inline is the only path that reliably works today. See ADR "
            "0002 in the ds-login repo."
        ),
    )


class ChallengeResponse(BaseModel):
    aid: str
    nonce_hex: str
    expires_at: float
    signing_hint: str = Field(
        default=(
            'Sign the canonical JSON envelope {"nonce":"<nonce_hex>"} '
            '(separators=(",",":"), sort_keys=true) with your AID\'s '
            "current signing key. The server also accepts a signature "
            "over the raw hex-decoded nonce bytes for KERIpy-native "
            "clients, but dkms-bin's data-sign only accepts JSON input "
            "so the envelope is the recommended interop path."
        ),
    )


class VerifyRequest(BaseModel):
    aid: str
    nonce_hex: str
    signature_qb64: str = Field(..., description="CESR-encoded signature (qb64)")
    oobi_urls: list[str] | None = Field(
        default=None,
        description=(
            "Same meaning as ChallengeRequest.oobi_urls. Repeat here so "
            "verify works even if the challenge-time cache was lost "
            "(pod restart, different replica)."
        ),
    )
    holder_kel_cesr: str | None = Field(
        default=None,
        description=(
            "Inline holder KEL (same shape as ChallengeRequest). When "
            "present, resolution skips OOBI fetch entirely."
        ),
    )

    # Phase 1b path — any DKMS-anchored issuer. Verifier resolves the
    # issuer's KEL from the OOBIs inside the grant and verifies the issuer's
    # signature over the ACDC. This is the open-federation model.
    credential_grant: dict[str, Any] | None = Field(
        default=None,
        description=(
            "An IPEX grant from the issuer. Must include: acdc, iss_sig, "
            "iss_oobis.witness_urls. Fully verified: subject binding, issuer "
            "signature against the issuer's live KEL, (optional) TEL "
            "revocation check."
        ),
    )

    # Phase 0 / backward-compat path — bare ACDC with no OOBIs. The server
    # does subject binding only and logs a warning; the full chain cannot
    # be verified. Reject this in production once all wallets emit grants.
    credential: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Deprecated. Bare ACDC envelope used by Phase 0 wallets. Subject "
            "binding only — issuer signature NOT verified. Prefer "
            "credential_grant."
        ),
    )


class VerifyResponse(BaseModel):
    aid: str
    verified: bool
    reason: str
    jwt: str | None = None
    jwt_claims: dict[str, Any] | None = None
