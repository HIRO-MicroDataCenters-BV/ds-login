"""Signs login JWTs with the service's RSA key. Supports loading from a PEM
file or from an inline PEM string; falls back to generating a transient key
for local development only."""
from __future__ import annotations

import base64
import logging
import time
import uuid
from pathlib import Path
from typing import Any

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

from ..settings import Settings


log = logging.getLogger(__name__)


class JwtSigner:
    """One signer per service instance. Loads or generates a key at startup;
    publishes the public key as a JWKs document."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._kid = uuid.uuid4().hex[:16]
        self._private_pem = self._load_or_generate_key(settings)

    # ─── key loading ─────────────────────────────────────────────────
    @staticmethod
    def _load_or_generate_key(settings: Settings) -> bytes:
        if settings.jwt_private_key_pem_path:
            path = Path(settings.jwt_private_key_pem_path)
            if not path.exists():
                raise FileNotFoundError(f"JWT key file not found at {path}")
            log.info("Loaded JWT signing key from %s", path)
            return path.read_bytes()

        if settings.jwt_private_key_pem_inline:
            return settings.jwt_private_key_pem_inline.encode("utf-8")

        if settings.environment == "production":
            raise RuntimeError(
                "No JWT signing key configured in production. Set "
                "DS__JWT_PRIVATE_KEY_PEM_PATH or DS__JWT_PRIVATE_KEY_PEM_INLINE."
            )

        # Local dev convenience — transient key regenerated per restart
        log.warning(
            "No JWT signing key configured — generating a transient one. "
            "Only use this in local dev; set DS__JWT_PRIVATE_KEY_PEM_PATH "
            "in staging and production so JWTs survive pod restarts."
        )
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    # ─── signing ─────────────────────────────────────────────────────
    def sign(self, claims: dict[str, Any]) -> str:
        return pyjwt.encode(
            claims,
            self._private_pem,
            algorithm="RS256",
            headers={"kid": self._kid},
        )

    def build_claims(
        self,
        sub: str,
        role: str,
        institute: str,
        name: str,
        email: str,
        credential_said: str | None = None,
        **extras: Any,
    ) -> dict[str, Any]:
        """Build the JWT claim set from identity + credential data."""
        now = int(time.time())
        claims: dict[str, Any] = {
            "sub": sub,
            "iss": self.settings.jwt_issuer,
            "aud": self.settings.jwt_audience,
            "iat": now,
            "exp": now + self.settings.jwt_ttl_seconds,
            "role": role,
            "institute": institute,
            "name": name,
            "email": email,
            "auth_method": "keri-byok",
        }
        if credential_said:
            claims["credential_said"] = credential_said
        claims.update(extras)
        return claims

    # ─── JWKs publication ────────────────────────────────────────────
    def jwks(self) -> dict[str, Any]:
        private_key = serialization.load_pem_private_key(self._private_pem, password=None)
        pub_numbers: RSAPublicNumbers = private_key.public_key().public_numbers()  # type: ignore[attr-defined]

        def _b64u(n: int) -> str:
            b = n.to_bytes((n.bit_length() + 7) // 8, "big")
            return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": self._kid,
                    "n": _b64u(pub_numbers.n),
                    "e": _b64u(pub_numbers.e),
                }
            ]
        }
