"""Signs login JWTs with the service's RSA key. Supports loading from a PEM
file or from an inline PEM string; falls back to generating a transient key
for local development only."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
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
        self._private_pem = self._load_or_generate_key(settings)
        self._public_jwk = self._rsa_public_jwk(self._private_pem)
        # The kid is the key's RFC 7638 thumbprint, not a random value: the
        # same key gets the same kid after a restart and on every replica, so
        # verifiers looking keys up by kid keep accepting earlier tokens.
        self._kid = self._thumbprint(self._public_jwk)

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
    @staticmethod
    def _rsa_public_jwk(private_pem: bytes) -> dict[str, str]:
        """The public key's required JWK members (`e`, `kty`, `n`)."""
        private_key = serialization.load_pem_private_key(private_pem, password=None)
        # load_pem_private_key returns a union of every private-key type
        # the cryptography library knows about; this service only ever
        # signs with RSA so narrow the type explicitly rather than
        # suppress the whole union-attr family. Fails loudly if a non-
        # RSA key file is ever handed to the service.
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise TypeError(
                f"ds-login signing key must be RSA, got {type(private_key).__name__}"
            )
        pub_numbers: RSAPublicNumbers = private_key.public_key().public_numbers()

        def _b64u(n: int) -> str:
            b = n.to_bytes((n.bit_length() + 7) // 8, "big")
            return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

        return {"e": _b64u(pub_numbers.e), "kty": "RSA", "n": _b64u(pub_numbers.n)}

    @staticmethod
    def _thumbprint(public_jwk: dict[str, str]) -> str:
        """RFC 7638 JWK thumbprint: SHA-256 over the required members,
        sorted, no whitespace, base64url without padding."""
        canonical = json.dumps(public_jwk, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    def jwks(self) -> dict[str, Any]:
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": self._kid,
                    "n": self._public_jwk["n"],
                    "e": self._public_jwk["e"],
                }
            ]
        }
