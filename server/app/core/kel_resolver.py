"""Resolves an AID → its KEL + current public key.

Primary path: query the keriox watcher. The watcher is already subscribed to
the known witnesses, caches KELs locally, and shields this service from
witness unreachability.

Fallback path (dev / early-stage deployment): read pre-exported KEL metadata
from disk. Fallback is permitted only when `kel_disk_fallback_dir` is set and
`environment != "production"`.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import httpx

from ..settings import Settings


log = logging.getLogger(__name__)


class KelResolutionError(Exception):
    """Could not resolve the KEL for an AID through any configured path."""


class KelResolver:
    def __init__(self, settings: Settings):
        self.settings = settings

    # ─── public API ─────────────────────────────────────────────────
    def resolve(self, aid: str) -> dict[str, Any]:
        """Return a dict describing the current state of the AID's KEL.

        Shape:
            {
              "aid": "<AID>",
              "current_public_keys": ["Dxxx..."],
              "witnesses": ["Bxxx...", ...],
              "sequence_number": 0,
              "source": "watcher" | "disk",
              # optional user_profile from the dev-mode disk export
              "user_profile": {...}?
            }
        """
        # Try watcher first
        try:
            return self._resolve_via_watcher(aid)
        except Exception as e:
            log.warning("watcher resolution failed for %s: %s", aid, e)

        # Fallback — only if explicitly enabled and not in production
        if self.settings.kel_disk_fallback_dir and self.settings.environment != "production":
            try:
                return self._resolve_via_disk(aid)
            except Exception as e:
                log.warning("disk-fallback resolution failed for %s: %s", aid, e)

        raise KelResolutionError(
            f"could not resolve KEL for AID {aid!r} — watcher unreachable "
            f"and no usable fallback"
        )

    # ─── watcher path ───────────────────────────────────────────────
    def _resolve_via_watcher(self, aid: str) -> dict[str, Any]:
        """Query the watcher for the AID's KEL.

        NOTE: keriox's HTTP `/query` endpoint takes a signed KERI `qry`
        message; constructing one requires access to the service's own AID
        key. For the first ds-login commit we hit the watcher's cache
        indirectly through a thin query helper endpoint that the watcher
        exposes locally. If the watcher doesn't support the simple GET
        shape we fall out of this method via the exception handler above
        and the caller tries the disk fallback.

        TODO (Phase 1 proper): construct a signed `qry` event and POST it to
        the watcher's /query endpoint; parse the KEL out of the CESR
        response and extract the current signing key.
        """
        # Minimal probe — ping watcher is up at all
        base = self.settings.watcher_url.rstrip("/")
        r = httpx.get(f"{base}/info", timeout=3.0)
        r.raise_for_status()

        # TODO: real KEL query goes here. Until then signal to the caller
        # that the watcher is reachable but the query path isn't wired yet.
        raise NotImplementedError(
            "watcher-side KEL query not yet implemented — use disk fallback "
            "or set up a dedicated query service."
        )

    # ─── disk fallback (dev only) ───────────────────────────────────
    def _resolve_via_disk(self, aid: str) -> dict[str, Any]:
        """Read a JSON KEL export from the fallback directory.

        File naming: `<alias>.json` with `{"aid": "...", "current_public_keys": [...], ...}`.
        The resolver iterates the directory until it finds one with the
        matching AID.
        """
        root = Path(self.settings.kel_disk_fallback_dir)  # type: ignore[arg-type]
        if not root.exists():
            raise KelResolutionError(f"disk fallback dir does not exist: {root}")

        for meta in root.glob("*.json"):
            try:
                data = json.loads(meta.read_text(encoding="utf-8"))
            except Exception:
                continue
            if data.get("aid") == aid:
                data["source"] = "disk"
                return data

        raise KelResolutionError(
            f"no KEL export in {root} matches AID {aid!r}"
        )
