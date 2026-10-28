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
import re
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

    def resolve_from_cesr_stream(
        self,
        aid: str,
        cesr_stream: str | bytes,
    ) -> dict[str, Any]:
        """Parse an inline CESR stream (icp + receipts) into a KEL state.

        Phase 1 facade (ADR 0002): dkms-bin-issued grants carry the
        issuer's own KEL as a CESR stream alongside the ACDC, so a
        verifier can parse it in-process without hitting any watcher
        or witness. Same KERIpy parse code path as the OOBI route.
        """
        body = cesr_stream.encode("utf-8") if isinstance(cesr_stream, str) else bytes(cesr_stream)
        if not body:
            raise KelResolutionError(
                f"inline CESR stream for {aid!r} is empty"
            )
        oobi = OobiResult(
            url=f"inline:cesr/{aid}",
            content_type="application/cesr",
            body=body,
        )
        state = _kel_state_from_oobi(oobi, aid)
        state["source"] = "inline-cesr"
        return state

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


# Matches ``"v":"<proto><major><minor>JSON<size>_"`` in a KERI event body;
# ``size`` is hex and gives us the exact byte count of the serialised body.
_VERSION_RE = re.compile(
    rb'"v":"KERI1[0-9]JSON(?P<size>[0-9a-f]{6})_"'
)


def _kel_state_from_oobi(oobi: OobiResult, aid: str) -> dict[str, Any]:
    """Parse an OOBI CESR response into a flat KEL state dict.

    Reads the first KERI event in the stream (the inception) via
    ``SerderKERI`` and builds the state dict directly from its fields.
    Deliberately bypasses ``Kevery`` because dkms-bin inlines witness
    receipts as ``-CAB`` attachments right after the icp's ``-AAB`` sig,
    which Kevery doesn't accept as a ``rct`` event and so refuses to
    construct a Kever with ``MissingWitnessSignatureError`` (toad=1,
    witness sigs []).

    Trust model: the icp event is self-addressing — its ``d`` SAID is a
    digest of the serialised body, and ``i`` equals ``d`` for the icp.
    If ``d == i == aid`` then the key material in ``k`` is cryptographically
    bound to the identifier. Verifying the ``-AAB`` sig against ``k[0]``
    further confirms the controller signed this exact inception. These
    together are sufficient for the login use case: the subsequent nonce
    signature from the user proves control of the same key.

    What we DON'T do: witness-receipt verification. For the login flow,
    the holder's possession of the signing key is the authority — witness
    receipts matter for ACDCs anchored in a TEL, which is a separate path
    on the credential verification side.
    """
    try:
        from keri.core.indexing import Siger
        from keri.core.serdering import SerderKERI
    except Exception as e:  # pysodium can raise TypeError on Windows
        raise KelResolutionError(
            f"KERIpy unavailable; cannot parse OOBI stream: {e}"
        ) from e

    if not oobi.body:
        raise KelResolutionError(f"OOBI {oobi.url} returned empty body")

    body = bytes(oobi.body)
    # Locate the first KERI event's version header, then read exactly
    # the declared size for its serialised body.
    m = _VERSION_RE.search(body)
    if m is None:
        raise KelResolutionError(
            f"OOBI {oobi.url} CESR stream has no KERI event version header"
        )
    size = int(m.group("size"), 16)
    event_start = body.rfind(b"{", 0, m.start())
    if event_start < 0:
        event_start = m.start()
    event_body = body[event_start:event_start + size]
    if len(event_body) < size:
        raise KelResolutionError(
            f"OOBI {oobi.url} truncated: declared size {size}, "
            f"only {len(event_body)} bytes available"
        )

    try:
        serder = SerderKERI(raw=event_body)
    except Exception as e:
        raise KelResolutionError(
            f"KERIpy could not parse icp from OOBI {oobi.url}: {e}"
        ) from e

    if serder.ked.get("t") != "icp":
        raise KelResolutionError(
            f"OOBI {oobi.url} first event is {serder.ked.get('t')!r}, "
            "expected 'icp' (direct inline-KEL resolution handles the "
            "inception event only; rotations arrive on later logins)"
        )
    if serder.said != aid or serder.pre != aid:
        raise KelResolutionError(
            f"icp SAID binding mismatch: event said={serder.said!r} i={serder.pre!r} "
            f"but AID={aid!r} — refusing to trust key material not bound to the AID"
        )

    keys = list(serder.ked.get("k") or [])
    if not keys:
        raise KelResolutionError(
            f"icp from OOBI {oobi.url} carries no signing keys (k=[])"
        )

    # Verify the controller signature over the icp body — MANDATORY.
    #
    # The attachment immediately follows the body: ``-AAB`` (counter:
    # 1 indexed sig) + 88 chars of qb64 (code 'A' + index + Ed25519
    # body). An icp with no attached controller sig is suspicious: the
    # SAID binds the keys to the AID but nothing confirms the controller
    # actually produced this event. Reject.
    #
    # Rahul audit #5 — the previous version put signature_verified in
    # the state dict and left it for callers to check. No caller did,
    # so the check was effectively absent. Enforced here is the single
    # choke-point every KEL-resolve route goes through.
    tail = body[event_start + size:]
    siger_qb64: str | None = None
    cnt_marker = tail.find(b"-A")
    if cnt_marker >= 0:
        after_counter = tail[cnt_marker + 4:]
        if len(after_counter) >= 88:
            candidate = after_counter[:88].decode("utf-8", errors="replace")
            # a well-formed indexed Ed25519 sig starts with the 'A' code
            if candidate.startswith("A"):
                siger_qb64 = candidate
    if siger_qb64 is None:
        raise KelResolutionError(
            f"icp from OOBI {oobi.url} has no controller signature "
            "attachment (-AAB…) — refusing to trust an unsigned "
            "inception event"
        )
    try:
        from keri.core.coring import Verfer
        siger = Siger(qb64=siger_qb64)
        verfer = Verfer(qb64=keys[0])
    except Exception as e:
        raise KelResolutionError(
            f"icp from OOBI {oobi.url} sig attachment malformed: "
            f"{type(e).__name__}: {e}"
        ) from e
    if not verfer.verify(sig=siger.raw, ser=event_body):
        raise KelResolutionError(
            f"icp from OOBI {oobi.url} controller signature does not "
            f"verify against k[0]={keys[0]!r} — refusing to trust key "
            "material whose owner cannot prove possession"
        )

    return {
        "aid": aid,
        "current_public_keys": keys,
        "witnesses": list(serder.ked.get("b") or []),
        "sequence_number": int(serder.ked.get("s", "0"), 16),
        "signature_verified": True,
    }
