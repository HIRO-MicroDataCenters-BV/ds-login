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
    """Walk the full KEL and return the FINAL key state.

    Processes each KERI event (icp, rot, ixn) in order, verifies the
    controller signature on each one, and checks that every rotation's
    new keys match the digest commitment ``n`` from the previous event.
    The final ``current_public_keys`` reflects every rotation applied —
    an old key that's been rotated out will not log in. Rahul audit #2.

    Why we don't just use Kevery:
      dkms-bin inlines witness receipts as ``-CAB`` attachments right
      after each event's ``-AAB`` controller sig instead of emitting them
      as standalone ``rct`` events. Kevery expects the standalone form,
      refuses to construct a Kever with ``MissingWitnessSignatureError``
      (toad=1, witness sigs []), and the whole stream silently escrows
      to kvy.kevers = {}. Walking the KEL manually sidesteps the
      inline-receipt pitfall AND processes rotations end-to-end — the
      previous icp-only resolver dropped them entirely.

    Trust model (per event):
      * icp — self-addressing; serder.said == serder.pre == aid.
        Sig verifies against the icp's own k[0] (threshold "1"
        required; threshold != "1" rejected since login key-usage is
        single-sig here). The commitment ``n`` is recorded for the
        next rotation's verification.
      * rot — new keys. For each new k[i], its digest must match
        the previous event's n[i] (pre-committed next-key digest).
        Sig verifies against the NEW k[0]. New ``n`` is recorded.
      * ixn — no key change. Sig verifies against the still-current
        k[0]. Doesn't advance key state.

    What we DON'T verify:
      * witness threshold — handled on the TEL verifier side where
        witness attestation of ACDC anchoring matters. For login the
        controller sig IS the authority.
      * out-of-order events — events here are expected in sequence
        matching ``s``. Gaps or regressions reject.
      * multi-sig / weighted thresholds — threshold != "1" rejected.
    """
    try:
        from keri.core.coring import Diger, Verfer
        from keri.core.indexing import Siger
        from keri.core.serdering import SerderKERI
    except Exception as e:  # pysodium can raise TypeError on Windows
        raise KelResolutionError(
            f"KERIpy unavailable; cannot parse OOBI stream: {e}"
        ) from e

    if not oobi.body:
        raise KelResolutionError(f"OOBI {oobi.url} returned empty body")

    body = bytes(oobi.body)
    events = _split_kel_events(body, oobi.url)
    if not events:
        raise KelResolutionError(
            f"OOBI {oobi.url} CESR stream has no KERI event version header"
        )

    # Walk the sequence.
    current_keys: list[str] = []
    next_digests: list[str] = []
    current_sn = -1
    witnesses: list[str] = []

    for idx, (event_body, attachment) in enumerate(events):
        try:
            serder = SerderKERI(raw=event_body)
        except Exception as e:
            raise KelResolutionError(
                f"OOBI {oobi.url}: event #{idx} unparseable: {e}"
            ) from e

        t = serder.ked.get("t")
        sn = int(serder.ked.get("s", "0"), 16)

        if idx == 0:
            # Must be an icp (or dip, out of scope here).
            if t != "icp":
                raise KelResolutionError(
                    f"OOBI {oobi.url} first event is {t!r}, expected 'icp' "
                    "(delegated inceptions / rotations as the first event "
                    "aren't supported on this login path yet)"
                )
            if serder.said != aid or serder.pre != aid:
                raise KelResolutionError(
                    f"icp SAID binding mismatch: event said={serder.said!r} "
                    f"i={serder.pre!r} but AID={aid!r} — refusing to trust key "
                    "material not bound to the AID"
                )
            if sn != 0:
                raise KelResolutionError(
                    f"icp has s={sn}, expected 0"
                )
        else:
            # Later events — same identifier, strictly increasing s.
            if serder.pre != aid:
                raise KelResolutionError(
                    f"event #{idx} binds to {serder.pre!r}, not {aid!r}"
                )
            if sn != current_sn + 1:
                raise KelResolutionError(
                    f"event #{idx} has s={sn}, expected {current_sn + 1}"
                )

        # Pull the controller signature out of the attachment group.
        siger_qb64 = _extract_controller_sig(attachment)
        if siger_qb64 is None:
            raise KelResolutionError(
                f"event #{idx} ({t}) at s={sn} has no controller sig "
                "attachment (-AAB…) — refusing to trust an unsigned event"
            )

        if t == "icp":
            kt = serder.ked.get("kt")
            if kt != "1":
                raise KelResolutionError(
                    f"icp has kt={kt!r}; this verifier only supports kt='1' "
                    "(single-sig threshold)"
                )
            keys = list(serder.ked.get("k") or [])
            if not keys:
                raise KelResolutionError(
                    f"icp from OOBI {oobi.url} carries no signing keys (k=[])"
                )
            # Self-signed with its own k[0].
            _verify_sig(siger_qb64, keys[0], event_body, "icp", oobi.url,
                        Siger, Verfer)
            current_keys = keys
            next_digests = list(serder.ked.get("n") or [])
            witnesses = list(serder.ked.get("b") or [])

        elif t == "rot":
            kt = serder.ked.get("kt")
            if kt != "1":
                raise KelResolutionError(
                    f"rot at s={sn} has kt={kt!r}; only kt='1' is supported"
                )
            new_keys = list(serder.ked.get("k") or [])
            if not new_keys:
                raise KelResolutionError(
                    f"rot at s={sn} declares no new keys (k=[])"
                )
            # Pre-rotation commitment check: digest of each new key
            # MUST equal the previous event's n[i]. This is the whole
            # point of KERI's rotation security.
            for i, new_k in enumerate(new_keys):
                if i >= len(next_digests):
                    raise KelResolutionError(
                        f"rot at s={sn} adds key beyond committed count "
                        f"({len(next_digests)}) — pre-rotation forgery"
                    )
                expected_digest = next_digests[i]
                actual_digest = Diger(ser=new_k.encode("utf-8")).qb64
                if actual_digest != expected_digest:
                    raise KelResolutionError(
                        f"rot at s={sn} new key {new_k!r} does not match "
                        f"the previous n[{i}] commitment {expected_digest!r}"
                    )
            # Sig over the rot body comes from the NEW k (what the rot
            # authorises).
            _verify_sig(siger_qb64, new_keys[0], event_body, f"rot@s={sn}",
                        oobi.url, Siger, Verfer)
            current_keys = new_keys
            next_digests = list(serder.ked.get("n") or [])
            # Witnesses can change via ba/br fields on rot; recompute.
            # Simple implementation: apply ba (add) and br (remove).
            ba = serder.ked.get("ba") or []
            br = serder.ked.get("br") or []
            witnesses = [w for w in witnesses if w not in br] + list(ba)

        elif t == "ixn":
            # Interaction event — same current_keys, same current_n.
            _verify_sig(siger_qb64, current_keys[0], event_body,
                        f"ixn@s={sn}", oobi.url, Siger, Verfer)

        else:
            # drt, dip, etc. — out of scope on this verifier path.
            raise KelResolutionError(
                f"event #{idx} at s={sn} has unsupported type {t!r}"
            )

        current_sn = sn

    # Walked the full KEL successfully. The state reflects every
    # rotation applied — a rotated-out key will NOT appear in
    # current_public_keys any more. Rahul audit #2.
    return {
        "aid": aid,
        "current_public_keys": current_keys,
        "witnesses": witnesses,
        "sequence_number": current_sn,
        "signature_verified": True,
    }


def _split_kel_events(body: bytes, oobi_url: str) -> list[tuple[bytes, bytes]]:
    """Split a CESR stream into (event_body, attachment_bytes) pairs.

    Each event's version header declares its serialised byte length; the
    bytes that follow until the next event's ``{"v":"KERI`` marker (or
    end-of-stream) are the attachment group — controller sig, witness
    receipts, etc. Returned in document order.
    """
    event_offsets: list[tuple[int, int]] = []  # (start, size)
    for m in _VERSION_RE.finditer(body):
        size = int(m.group("size"), 16)
        start = body.rfind(b"{", 0, m.start())
        if start < 0:
            start = m.start()
        if start + size > len(body):
            raise KelResolutionError(
                f"OOBI {oobi_url} truncated: event at {start} declares "
                f"size {size} but only {len(body) - start} bytes remain"
            )
        event_offsets.append((start, size))

    out: list[tuple[bytes, bytes]] = []
    for i, (start, size) in enumerate(event_offsets):
        event_body = body[start:start + size]
        attach_start = start + size
        attach_end = event_offsets[i + 1][0] if i + 1 < len(event_offsets) else len(body)
        attachment = body[attach_start:attach_end]
        out.append((event_body, attachment))
    return out


def _extract_controller_sig(attachment: bytes) -> str | None:
    """Pull the first qb64 controller sig body from a CESR attachment.

    ``-AAB`` / ``-AAC`` counter + 88-char qb64 sig body. Returns just
    the sig body (what KERIpy's ``Siger(qb64=...)`` accepts); the
    counter prefix would trip the Siger constructor's Matter parser.
    """
    for marker in (b"-AAB", b"-AAC"):
        i = attachment.find(marker)
        if i >= 0:
            body = attachment[i + 4 : i + 4 + 88]
            if len(body) == 88:
                return body.decode("utf-8", errors="replace")
    return None


def _verify_sig(
    siger_qb64: str,
    key_qb64: str,
    event_body: bytes,
    label: str,
    oobi_url: str,
    Siger: Any,
    Verfer: Any,
) -> None:
    """Verify a controller sig against a key; raise ``KelResolutionError``
    with a specific label on mismatch. Separate from the walker so the
    sig-verify branch stays readable."""
    try:
        siger = Siger(qb64=siger_qb64)
        verfer = Verfer(qb64=key_qb64)
    except Exception as e:
        raise KelResolutionError(
            f"OOBI {oobi_url} {label}: sig attachment malformed: "
            f"{type(e).__name__}: {e}"
        ) from e
    if not verfer.verify(sig=siger.raw, ser=event_body):
        raise KelResolutionError(
            f"OOBI {oobi_url} {label}: controller signature does not "
            f"verify against expected key {key_qb64!r}"
        )
