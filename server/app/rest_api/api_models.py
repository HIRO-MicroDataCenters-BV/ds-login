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
    credential: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Optional ACDC credential binding role, institute, name, email to this AID. "
            "If omitted, the server falls back to the AID's KEL-attached profile for "
            "development; production requires a credential."
        ),
    )


class VerifyResponse(BaseModel):
    aid: str
    verified: bool
    reason: str
    jwt: str | None = None
    jwt_claims: dict[str, Any] | None = None
