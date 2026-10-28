"""ds-login — FastAPI entrypoint."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .core.acdc_verifier import AcdcVerifier
from .core.revocation_client import RevocationClient
from .core.challenge_store import ChallengeStore
from .core.jwt_signer import JwtSigner
from .core.kel_resolver import KelResolver
from .rest_api.routes.health_check import router as health_router
from .rest_api.routes.jwks import router as jwks_router
from .rest_api.routes.login import router as login_router
from .settings import get_settings

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logging.basicConfig(level=settings.log_level)

    log.info("ds-login starting · env=%s watcher=%s", settings.environment, settings.watcher_url)

    # Build singletons once, store on app.state for dependency injection.
    # Order matters: the ACDC verifier depends on the KEL resolver.
    app.state.jwt_signer = JwtSigner(settings)
    app.state.kel_resolver = KelResolver(settings)
    app.state.challenge_store = ChallengeStore(
        ttl_seconds=settings.challenge_ttl_seconds,
        nonce_bytes=settings.challenge_bytes,
    )
    app.state.acdc_verifier = AcdcVerifier(
        kel_resolver=app.state.kel_resolver,
        trusted_issuer_aids=settings.trusted_issuer_aids,
        revocation_client=RevocationClient(settings.issuer_status_urls),
    )
    missing_status = [a for a in settings.trusted_issuer_aids
                      if a not in settings.issuer_status_urls]
    if missing_status:
        if settings.environment == "production":
            raise RuntimeError(
                "DS__ISSUER_STATUS_URLS has no entry for trusted issuer(s) "
                f"{missing_status}. Every credential from them would be "
                "rejected (revocation check fails closed)."
            )
        log.warning("no revocation status URL for trusted issuer(s) %s — "
                    "their credentials will be rejected", missing_status)
    if not settings.trusted_issuer_aids:
        if settings.environment == "production":
            raise RuntimeError(
                "DS__TRUSTED_ISSUER_AIDS is empty in production. The verifier "
                "would reject every grant. Set it to the list of issuer AIDs "
                "this login service recognises (e.g. the HUS "
                "ds-credential-issuer AID)."
            )
        log.warning(
            "DS__TRUSTED_ISSUER_AIDS empty — the verifier will reject every "
            "grant. OK outside production for the challenge-only login path; "
            "credential-based login will not work until this is populated."
        )

    yield

    log.info("ds-login shutting down")


app = FastAPI(
    title="ds-login",
    description=(
        "Login + credential verification for the Hiro dataspace. Accepts a "
        "BYOK AID, verifies the signature against DKMS witnesses via the "
        "watcher, verifies the ACDC credential, and issues a short-lived JWT "
        "that every ds-* service can validate with ds-auth."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(health_router)
app.include_router(jwks_router)
app.include_router(login_router)
