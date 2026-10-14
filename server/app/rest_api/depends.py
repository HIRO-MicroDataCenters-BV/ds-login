"""FastAPI dependency providers — one place to wire the service's singletons
into request handlers."""
from __future__ import annotations

from functools import lru_cache

from fastapi import Request

from ..core.acdc_verifier import AcdcVerifier
from ..core.challenge_store import ChallengeStore
from ..core.jwt_signer import JwtSigner
from ..core.kel_resolver import KelResolver
from ..core.signature_verifier import SignatureVerifier
from ..settings import Settings, get_settings


def settings_dep() -> Settings:
    return get_settings()


def jwt_signer_dep(request: Request) -> JwtSigner:
    return request.app.state.jwt_signer  # type: ignore[no-any-return]


def kel_resolver_dep(request: Request) -> KelResolver:
    return request.app.state.kel_resolver  # type: ignore[no-any-return]


def challenge_store_dep(request: Request) -> ChallengeStore:
    return request.app.state.challenge_store  # type: ignore[no-any-return]


def acdc_verifier_dep(request: Request) -> AcdcVerifier:
    return request.app.state.acdc_verifier  # type: ignore[no-any-return]


@lru_cache(maxsize=1)
def signature_verifier_dep() -> SignatureVerifier:
    return SignatureVerifier()
