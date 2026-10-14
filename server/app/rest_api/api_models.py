"""Request / response schemas for the login API."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ChallengeRequest(BaseModel):
    aid: str = Field(..., description="The AID the user is claiming to be")


class ChallengeResponse(BaseModel):
    aid: str
    nonce_hex: str
    expires_at: float
    signing_hint: str = Field(
        default="Sign these bytes (nonce, decoded from hex) with your AID's current signing key.",
    )


class VerifyRequest(BaseModel):
    aid: str
    nonce_hex: str
    signature_qb64: str = Field(..., description="CESR-encoded signature (qb64)")

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
