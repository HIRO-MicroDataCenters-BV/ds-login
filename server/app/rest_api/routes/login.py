"""The core login endpoints: challenge issuance + signature/credential verification."""
from __future__ import annotations

import binascii
import logging
import time

from fastapi import APIRouter, Depends, HTTPException

from ...core.acdc_verifier import AcdcVerifier, CredentialVerificationError
from ...core.challenge_store import ChallengeStore
from ...core.jwt_signer import JwtSigner
from ...core.kel_resolver import KelResolutionError, KelResolver
from ...core.signature_verifier import SignatureVerifier, SignatureVerificationError
from ...settings import Settings
from ..api_models import (
    ChallengeRequest,
    ChallengeResponse,
    VerifyRequest,
    VerifyResponse,
)
from ..depends import (
    acdc_verifier_dep,
    challenge_store_dep,
    jwt_signer_dep,
    kel_resolver_dep,
    settings_dep,
    signature_verifier_dep,
)


log = logging.getLogger(__name__)
router = APIRouter(prefix="/login", tags=["login"])


@router.post("/challenge", response_model=ChallengeResponse)
def login_challenge(
    body: ChallengeRequest,
    settings: Settings = Depends(settings_dep),
    resolver: KelResolver = Depends(kel_resolver_dep),
    store: ChallengeStore = Depends(challenge_store_dep),
) -> ChallengeResponse:
    """Issue a one-time nonce for the given AID."""
    # Confirm the KEL is resolvable before issuing a challenge; otherwise
    # the user would sign a nonce we'd then reject at verify time.
    try:
        resolver.resolve(body.aid)
    except KelResolutionError as e:
        raise HTTPException(
            status_code=404,
            detail=f"KEL for AID {body.aid} not resolvable: {e}",
        )

    challenge = store.issue(body.aid)
    return ChallengeResponse(
        aid=body.aid,
        nonce_hex=challenge.nonce.hex(),
        expires_at=challenge.issued_at + settings.challenge_ttl_seconds,
    )


@router.post("/verify", response_model=VerifyResponse)
def login_verify(
    body: VerifyRequest,
    settings: Settings = Depends(settings_dep),
    resolver: KelResolver = Depends(kel_resolver_dep),
    store: ChallengeStore = Depends(challenge_store_dep),
    sig_verifier: SignatureVerifier = Depends(signature_verifier_dep),
    cred_verifier: AcdcVerifier = Depends(acdc_verifier_dep),
    signer: JwtSigner = Depends(jwt_signer_dep),
) -> VerifyResponse:
    """Verify a signed nonce + credential and issue a session JWT."""
    # 1. Challenge check
    try:
        provided_nonce = binascii.unhexlify(body.nonce_hex)
    except binascii.Error:
        return VerifyResponse(aid=body.aid, verified=False, reason="nonce hex invalid")

    challenge = store.consume(body.aid, provided_nonce)
    if challenge is None:
        return VerifyResponse(
            aid=body.aid,
            verified=False,
            reason="no active challenge, nonce mismatch, or challenge expired",
        )

    # 2. KEL lookup — the whole point of KERI is we resolve the public key
    # from the AID's own committed key state, not from client input
    try:
        kel = resolver.resolve(body.aid)
    except KelResolutionError as e:
        return VerifyResponse(aid=body.aid, verified=False, reason=f"KEL unavailable: {e}")

    public_keys = kel.get("current_public_keys") or []
    if not public_keys:
        return VerifyResponse(aid=body.aid, verified=False, reason="KEL has no current signing key")

    # 3. Signature verification
    try:
        sig_ok = sig_verifier.verify(
            public_key_qb64=public_keys[0],
            data=provided_nonce,
            signature_qb64=body.signature_qb64,
        )
    except SignatureVerificationError as e:
        return VerifyResponse(aid=body.aid, verified=False, reason=str(e))

    if not sig_ok:
        return VerifyResponse(aid=body.aid, verified=False, reason="Ed25519 signature invalid")

    # 4. Credential verification → extract identity claims
    role: str | None = None
    institute: str | None = None
    name: str | None = None
    email: str | None = None
    credential_said: str | None = None

    if body.credential is not None:
        try:
            verified_cred = cred_verifier.verify(body.credential, subject_aid=body.aid)
        except CredentialVerificationError as e:
            return VerifyResponse(aid=body.aid, verified=False, reason=f"credential rejected: {e}")

        role = verified_cred.attributes.get("role")
        institute = verified_cred.attributes.get("institute")
        name = verified_cred.attributes.get("name")
        email = verified_cred.attributes.get("email")
        credential_said = verified_cred.said

    # Dev-mode fallback — the KEL export may carry a user_profile embedded.
    # Permitted only outside production so new deployments force credentials.
    if role is None and settings.environment != "production":
        profile = (kel.get("user_profile") or {}) if isinstance(kel, dict) else {}
        role = profile.get("role")
        institute = profile.get("institute")
        name = profile.get("name")
        email = profile.get("email")

    if not (role and institute and name and email):
        return VerifyResponse(
            aid=body.aid,
            verified=False,
            reason=(
                "no credential supplied and no profile available — "
                "required claims (role, institute, name, email) are missing"
            ),
        )

    # 5. Issue JWT
    claims = signer.build_claims(
        sub=body.aid,
        role=role,
        institute=institute,
        name=name,
        email=email,
        credential_said=credential_said,
    )
    token = signer.sign(claims)

    log.info(
        "login success: aid=%s role=%s institute=%s credential=%s",
        body.aid, role, institute, credential_said or "<none>",
    )

    return VerifyResponse(
        aid=body.aid,
        verified=True,
        reason="signature valid; JWT issued",
        jwt=token,
        jwt_claims=claims,
    )
