"""Publishes the service's RS256 public key so every ds-* service that imports
ds-auth can verify JWTs locally."""
from fastapi import APIRouter, Depends

from ..depends import jwt_signer_dep
from ...core.jwt_signer import JwtSigner


router = APIRouter(tags=["jwks"])


@router.get("/.well-known/jwks.json")
def jwks(signer: JwtSigner = Depends(jwt_signer_dep)):
    return signer.jwks()
