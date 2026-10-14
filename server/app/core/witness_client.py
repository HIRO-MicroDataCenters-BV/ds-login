"""HTTP client for KERI witness endpoints.

A witness exposes a handful of HTTP routes for OOBI (Out-of-Band Introduction)
and KEL / TEL retrieval. ds-login only needs the read side: given an OOBI URL
embedded in an incoming IPEX grant, fetch the KEL state of the AID that OOBI
points to, and query the issuer's registry TEL for a credential's revocation
state.

The client is deliberately small — it does **not** build KERI messages or
parse CESR. Callers (``ipex_grant`` for parsing, ``kel_resolver`` for KEL
reconstruction) do the CESR / KERIpy work. This separation keeps the HTTP
layer testable with ``respx`` without pulling KERIpy into every test.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import httpx

log = logging.getLogger(__name__)


class WitnessUnreachableError(Exception):
    """A witness URL did not respond (or responded with an error status)."""


@dataclass(frozen=True)
class OobiResult:
    """Raw bytes returned by a witness for an OOBI lookup.

    KERI OOBI responses are CESR streams — a concatenation of a key event
    (``icp``/``rot``/``ixn``) and attached witness receipts. The resolver
    parses this stream into a KERIpy ``Kever`` to extract the current
    signing key, witness set and sequence number.
    """

    url: str
    content_type: str
    body: bytes


class WitnessClient:
    """Thin, synchronous HTTP wrapper. One instance per request is fine;
    the underlying ``httpx.Client`` is cheap to construct."""

    def __init__(self, timeout_seconds: float = 5.0) -> None:
        self._timeout = timeout_seconds

    # ─── OOBI / KEL ──────────────────────────────────────────────────────

    def fetch_oobi(self, oobi_url: str) -> OobiResult:
        """Fetch the CESR stream at an OOBI URL.

        Raises ``WitnessUnreachableError`` on transport failure or non-2xx
        status so the caller can try the next OOBI in the list.
        """
        try:
            with httpx.Client(timeout=self._timeout, follow_redirects=True) as c:
                r = c.get(oobi_url)
        except httpx.HTTPError as e:
            raise WitnessUnreachableError(
                f"OOBI {oobi_url!r} unreachable: {e}"
            ) from e

        if r.status_code // 100 != 2:
            raise WitnessUnreachableError(
                f"OOBI {oobi_url!r} returned HTTP {r.status_code}"
            )

        return OobiResult(
            url=oobi_url,
            content_type=r.headers.get("content-type", ""),
            body=r.content,
        )

    # ─── TEL ────────────────────────────────────────────────────────────

    def fetch_tel_event(
        self,
        witness_url: str,
        registry_said: str,
        credential_said: str,
    ) -> OobiResult:
        """Fetch the latest TEL event for a credential SAID from a witness.

        keriox exposes TEL state at:
          ``GET {witness}/tel/{registry_said}/{credential_said}``
        The response is a CESR stream of registry events (iss/rev/...) that
        the caller walks to decide the credential's current status.
        """
        url = f"{witness_url.rstrip('/')}/tel/{registry_said}/{credential_said}"
        try:
            with httpx.Client(timeout=self._timeout, follow_redirects=True) as c:
                r = c.get(url)
        except httpx.HTTPError as e:
            raise WitnessUnreachableError(
                f"TEL endpoint {url!r} unreachable: {e}"
            ) from e

        if r.status_code // 100 != 2:
            raise WitnessUnreachableError(
                f"TEL endpoint {url!r} returned HTTP {r.status_code}"
            )

        return OobiResult(
            url=url,
            content_type=r.headers.get("content-type", ""),
            body=r.content,
        )

    # ─── diagnostics ────────────────────────────────────────────────────

    def info(self, witness_url: str) -> dict[str, Any]:
        """GET /info — liveness probe for the witness. Returns the JSON
        payload keriox emits, or raises WitnessUnreachableError.
        """
        url = f"{witness_url.rstrip('/')}/info"
        try:
            with httpx.Client(timeout=self._timeout) as c:
                r = c.get(url)
            r.raise_for_status()
            return r.json()  # type: ignore[no-any-return]
        except httpx.HTTPError as e:
            raise WitnessUnreachableError(
                f"info {url!r} unreachable: {e}"
            ) from e
