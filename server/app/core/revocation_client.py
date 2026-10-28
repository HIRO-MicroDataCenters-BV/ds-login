"""Asks a credential's issuer whether it was revoked.

HCF's TEL can't be read back yet, so each ds-credential-issuer serves its
own revocation list at ``GET {base}/credential-status?said=…``. ds-login
asks before every credential login and **fails closed**: no status URL for
the issuer, an unreachable issuer or an unexpected answer all reject the
login, the same as a revoked credential.
"""
from __future__ import annotations

import logging

import httpx

log = logging.getLogger(__name__)


class RevocationCheckError(Exception):
    """The credential is revoked, or its status could not be established."""


class RevocationClient:
    def __init__(self, status_urls: dict[str, str], timeout_seconds: float = 5.0) -> None:
        # issuer AID -> issuer base URL, e.g. http://ds-credential-issuer:8080
        self.status_urls = {aid: url.rstrip("/") for aid, url in status_urls.items()}
        self.timeout_seconds = timeout_seconds

    def ensure_not_revoked(self, issuer_aid: str, credential_said: str) -> None:
        base = self.status_urls.get(issuer_aid)
        if not base:
            raise RevocationCheckError(
                f"no revocation status URL configured for issuer {issuer_aid!r} "
                "(DS__ISSUER_STATUS_URLS); refusing (fail closed)"
            )
        try:
            r = httpx.get(
                f"{base}/credential-status",
                params={"said": credential_said},
                timeout=self.timeout_seconds,
            )
            r.raise_for_status()
            status = r.json().get("status")
        except (httpx.HTTPError, ValueError, AttributeError) as e:
            raise RevocationCheckError(
                f"revocation status unavailable from {base}: {e}; refusing (fail closed)"
            ) from e

        if status == "revoked":
            raise RevocationCheckError(f"credential {credential_said} is revoked")
        if status != "not_revoked":
            raise RevocationCheckError(
                f"unexpected revocation status {status!r} from {base}; refusing (fail closed)"
            )
        log.info("revocation check ok: issuer=%s said=%s", issuer_aid, credential_said)
