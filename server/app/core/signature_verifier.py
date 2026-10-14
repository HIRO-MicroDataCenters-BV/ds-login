"""Verifies a KERI Ed25519 signature against the public key in an AID's KEL."""
from __future__ import annotations

import logging


log = logging.getLogger(__name__)


class SignatureVerificationError(Exception):
    pass


class SignatureVerifier:
    """Thin wrapper around KERIpy's coring/indexing primitives.

    The import is lazy so the service can start even if KERIpy's native deps
    are missing — the error only surfaces when verification is actually
    attempted (which gives a clearer production diagnostic than an import-time
    failure).
    """

    @staticmethod
    def verify(public_key_qb64: str, data: bytes, signature_qb64: str) -> bool:
        try:
            from keri.core import coring, indexing  # type: ignore[import-not-found]
        except Exception as e:
            raise SignatureVerificationError(
                f"KERIpy unavailable at verification time: {e}"
            ) from e

        verfer = coring.Verfer(qb64=public_key_qb64)

        # Signature can be indexed (0B...) or non-indexed (0C...).
        # Try the indexed form first because that's what KERIpy's hab.sign()
        # produces by default.
        try:
            sig_raw = indexing.Siger(qb64=signature_qb64).raw
        except Exception:
            try:
                sig_raw = coring.Cigar(qb64=signature_qb64).raw
            except Exception as e:
                raise SignatureVerificationError(
                    f"signature format invalid: {e}"
                ) from e

        return bool(verfer.verify(sig=sig_raw, ser=data))
