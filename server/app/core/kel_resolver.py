"""Resolves an AID → its KEL + current public key.

Primary path (Phase 1b): hit the OOBI URL(s) the caller supplies (usually
pulled off an inbound IPEX grant). The witness returns a CESR stream of the
AID's KEL events; we parse it with KERIpy to a transient in-memory ``Kever``
and extract the current signing key, witness set and sequence number.

Legacy paths (still available, used only when enabled):

* **Watcher**: configured Hiro-side watcher. Useful once we deploy a watcher
  per site and want it to cache KEL state across requests.
* **Disk**: pre-exported JSON KELs. Dev-only; forbidden when
  ``environment == "production"``.

The resolver returns a flat dict rather than a KERIpy object so callers
don't need KERIpy on their import path.
"""
from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from typing import Any

import httpx

from ..settings import Settings
from .witness_client import OobiResult, WitnessClient, WitnessUnreachableError

log = logging.getLogger(__name__)


class KelResolutionError(Exception):
    """Could not resolve the KEL for an AID through any configured path."""


class KelResolver:
    def __init__(
        self,
        settings: Settings,
        witness_client: WitnessClient | None = None,
    ) -> None:
        self.settings = settings
        self.witness = witness_client or WitnessClient()

    # ─── public API ─────────────────────────────────────────────────────

    def resolve(self, aid: str) -> dict[str, Any]:
        """Legacy single-AID resolve (watcher-first, disk fallback).

        Preserved so the challenge endpoint — which only knows the user's AID
        and has no OOBIs for them yet — can still do a liveness check against
        a locally-configured watcher. New callers verifying inbound grants
        should use ``resolve_from_oobis`` instead.
        """
        if self.settings.watcher_url:
            try:
                return self._resolve_via_watcher(aid)
            except (KelResolutionError, httpx.HTTPError) as e:
                log.warning("watcher resolution failed for %s: %s", aid, e)

        if self.settings.kel_disk_fallback_dir and self.settings.environment != "production":
            try:
                return self._resolve_via_disk(aid)
            except (KelResolutionError, OSError) as e:
                log.warning("disk-fallback resolution failed for %s: %s", aid, e)

        raise KelResolutionError(
            f"could not resolve KEL for AID {aid!r} — watcher unreachable "
            f"and no usable fallback"
        )

    def resolve_from_oobis(
        self,
        aid: str,
        oobi_urls: list[str],
    ) -> dict[str, Any]:
        """Resolve ``aid``'s KEL by hitting its OOBI URLs directly.

        Tries each URL in order; returns the first KEL that parses cleanly
        and whose state names ``aid``. Raises ``KelResolutionError`` if
        every URL fails.
        """
        if not oobi_urls:
            raise KelResolutionError(
                f"no OOBI URLs supplied for {aid!r}; cannot resolve KEL"
            )

        last_error: Exception | None = None
        for url in oobi_urls:
            try:
                oobi = self.witness.fetch_oobi(url)
            except WitnessUnreachableError as e:
                log.warning("OOBI unreachable: %s", e)
                last_error = e
                continue

            try:
                state = _kel_state_from_oobi(oobi, aid)
            except KelResolutionError as e:
                log.warning("OOBI %s returned un-parseable KEL: %s", url, e)
                last_error = e
                continue

            state["source"] = "oobi"
            state["oobi_url"] = url
            return state

        raise KelResolutionError(
            f"all {len(oobi_urls)} OOBI URL(s) failed for {aid!r}; "
            f"last error: {last_error}"
        )

    # ─── watcher path ──────────────────────────────────────────────────

    def _resolve_via_watcher(self, aid: str) -> dict[str, Any]:
        """Query the configured watcher for ``aid``'s KEL.

        keriox watcher exposes ``GET /oobi/<AID>`` returning the CESR
        stream of the AID's KEL (empty body + 200 if the watcher doesn't
        know the AID). We parse that stream the same way we parse an
        inbound issuer OOBI and extract current key / witnesses / sn.

        Pre-check: ``GET /info`` so a bad base URL fails fast with a
        connection error rather than looking like "AID unknown".
        """
        base = self.settings.watcher_url.rstrip("/")

        info = httpx.get(f"{base}/info", timeout=3.0)
        info.raise_for_status()

        oobi_resp = httpx.get(f"{base}/oobi/{aid}", timeout=5.0)
        if oobi_resp.status_code != 200:
            raise KelResolutionError(
                f"watcher {base} returned HTTP {oobi_resp.status_code} "
                f"for /oobi/{aid}"
            )
        if not oobi_resp.content:
            raise KelResolutionError(
                f"watcher {base} does not have a KEL for AID {aid!r} "
                "(empty OOBI response — caller must present an OOBI URL "
                "that resolves to the AID's KEL)"
            )

        state = _kel_state_from_oobi(
            OobiResult(
                url=f"{base}/oobi/{aid}",
                content_type=oobi_resp.headers.get("content-type", "application/cesr"),
                body=oobi_resp.content,
            ),
            aid,
        )
        state["source"] = "watcher"
        state["watcher_url"] = base
        return state

    # ─── disk fallback (dev only) ───────────────────────────────────────

    def _resolve_via_disk(self, aid: str) -> dict[str, Any]:
        """Read a JSON KEL export from the fallback directory.

        File naming: ``<alias>.json`` with ``{"aid": ..., "current_public_keys": [...], ...}``.
        """
        if self.settings.kel_disk_fallback_dir is None:
            raise KelResolutionError("disk fallback not configured")

        root = Path(self.settings.kel_disk_fallback_dir)
        if not root.exists():
            raise KelResolutionError(f"disk fallback dir does not exist: {root}")

        for meta in root.glob("*.json"):
            try:
                data = json.loads(meta.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            if data.get("aid") == aid:
                data["source"] = "disk"
                return data  # type: ignore[no-any-return]

        raise KelResolutionError(
            f"no KEL export in {root} matches AID {aid!r}"
        )


# ─── KERIpy-backed CESR parse ───────────────────────────────────────────


def _kel_state_from_oobi(oobi: OobiResult, aid: str) -> dict[str, Any]:
    """Parse an OOBI CESR response into a flat KEL state dict.

    Uses KERIpy's ``Kevery`` + a transient in-memory ``Baser`` so no
    persistent state leaks between requests. Raises on any parse failure or
    if the resulting state doesn't name ``aid``.
    """
    try:
        from keri.core import eventing, parsing
        from keri.db import basing
    except Exception as e:  # pysodium can raise TypeError on Windows
        raise KelResolutionError(
            f"KERIpy unavailable; cannot parse OOBI stream: {e}"
        ) from e

    if not oobi.body:
        raise KelResolutionError(f"OOBI {oobi.url} returned empty body")

    # Transient LMDB: name scopes the files, temp=True wipes on close,
    # headDirPath keeps them out of the user's HOME in dev.
    with (
        tempfile.TemporaryDirectory(prefix="ds-login-kel-") as tmp,
        basing.openDB(name="ds-login-kel", temp=True, headDirPath=tmp) as db,
    ):
        kvy = eventing.Kevery(db=db, lax=True)
        parser = parsing.Parser(kvy=kvy)
        try:
            parser.parse(ims=bytearray(oobi.body))
        except Exception as e:  # KERIpy raises many ad-hoc exception types
            raise KelResolutionError(
                f"KERIpy failed to parse OOBI {oobi.url}: {e}"
            ) from e

        kever = kvy.kevers.get(aid)
        if kever is None:
            raise KelResolutionError(
                f"OOBI {oobi.url} did not include a KEL for {aid!r}; "
                f"got {sorted(kvy.kevers.keys())}"
            )

        return {
            "aid": aid,
            "current_public_keys": [v.qb64 for v in kever.verfers],
            "witnesses": list(kever.wits),
            "sequence_number": kever.sn,
        }
