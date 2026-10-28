"""KelResolver integration tests.

These exercise the real KERIpy CESR parse path by booting a transient
in-memory habitat, letting it emit an inception event, serialising it as a
CESR stream, and feeding that stream to the resolver via a stubbed
WitnessClient. Verifies the resolver reconstructs the KEL state correctly
and that the returned public key matches what KERIpy actually produced.

KERIpy depends on libsodium via pysodium / ctypes. On Linux CI it's picked
up from the OS; on Windows developer machines it's often missing and the
whole ``keri`` import tree breaks. Guard with importorskip so tests that
can run under the plain-Python code paths still exercise locally while the
KERIpy-backed ones only run where libsodium is available.
"""
from unittest.mock import MagicMock

import pytest

# Skip the whole module unless libsodium is loadable — the KEL parse path
# needs ``keri.core.eventing`` which transitively loads libsodium. pysodium
# raises TypeError (not ImportError) when ctypes can't find the lib on
# Windows, so importorskip isn't enough; catch broad.
try:
    from keri.core import eventing  # noqa: F401
except Exception as _e:  # noqa: BLE001
    pytest.skip(
        f"libsodium not loadable ({_e}); keri-dependent tests skipped",
        allow_module_level=True,
    )

from app.core.kel_resolver import (
    KelResolutionError,
    KelResolver,
    _kel_state_from_oobi,
)
from app.core.witness_client import (
    OobiResult,
    WitnessClient,
    WitnessUnreachableError,
)
from app.settings import Settings

# ─── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def issuer_cesr_stream():
    """Spin up a transient KERIpy habitat and return (aid, cesr_bytes).

    Keeps the setup in one place so individual tests stay focused on
    the resolver's behaviour."""
    from keri.app import habbing

    with habbing.openHby(name="test-issuer", temp=True) as hby:
        hab = hby.makeHab(name="issuer", transferable=True)
        # The habitat's event message bytes already carry the inception
        # event in CESR framing — exactly what a witness would stream
        # back from an /oobi/<aid> GET.
        cesr = bytes(hab.makeOwnEvent(sn=0))
        yield hab.pre, cesr


# ─── Direct helper tests ────────────────────────────────────────────────


def test_kel_state_from_oobi_extracts_current_key(issuer_cesr_stream):
    aid, cesr = issuer_cesr_stream
    oobi = OobiResult(
        url=f"https://w1.example/oobi/{aid}",
        content_type="application/cesr",
        body=cesr,
    )

    state = _kel_state_from_oobi(oobi, aid)

    assert state["aid"] == aid
    assert state["sequence_number"] == 0
    assert len(state["current_public_keys"]) == 1
    # KERI qb64 verfers start with a known type code — just confirm shape
    assert state["current_public_keys"][0].startswith(("D", "B"))


def test_kel_state_from_oobi_rejects_empty_body():
    oobi = OobiResult(
        url="https://w1.example/oobi/E",
        content_type="application/cesr",
        body=b"",
    )
    with pytest.raises(KelResolutionError, match="empty body"):
        _kel_state_from_oobi(oobi, "EAnyAid")


def test_kel_state_from_oobi_rejects_stream_for_other_aid(issuer_cesr_stream):
    aid, cesr = issuer_cesr_stream
    oobi = OobiResult(
        url=f"https://w1.example/oobi/{aid}",
        content_type="application/cesr",
        body=cesr,
    )
    with pytest.raises(KelResolutionError, match="binding mismatch"):
        _kel_state_from_oobi(oobi, "EDefinitelyNotTheIssuer")


def test_kel_state_from_oobi_accepts_dkms_bin_inline_receipt_shape():
    """Regression: dkms-bin's ``log kel find`` emits the icp body followed
    by ``-AAB`` controller sig + ``-CAB`` non-transferable witness receipt
    attached INLINE (not as a separate ``rct`` event). KERIpy's Kevery
    rejects this with ``MissingWitnessSignatureError (toad=1, witness
    sigs [])`` because it expects receipts as standalone events. The
    SerderKERI-direct resolver must tolerate the inline-receipt shape.

    Byte-for-byte stream captured from a real dkms-bin v0.8.2 ``log kel
    find`` run inside the HUS cluster against an operator identifier
    minted at witness ``BJq7...yxCC`` with witness threshold 1.
    """
    aid = "EN8anzGOndcAGirqHkhYQvbt5-6s4ITjd62uqnDbg0VW"
    cesr = (
        b'{"v":"KERI10JSON000159_","t":"icp",'
        b'"d":"EN8anzGOndcAGirqHkhYQvbt5-6s4ITjd62uqnDbg0VW",'
        b'"i":"EN8anzGOndcAGirqHkhYQvbt5-6s4ITjd62uqnDbg0VW","s":"0",'
        b'"kt":"1","k":["DAz6dsiOU4pbfvp0OB7TqnDXPdhlj_r9cjPJKAmw_9Vq"],'
        b'"nt":"1","n":["EPs1wLvzDz-KpTjNFyv_DUB3HrkAqn3JNY7JY2yvNTCA"],'
        b'"bt":"1","b":["BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC"],'
        b'"c":[],"a":[]}'
        b'-AABAABw-7kkfKsOLaBxcgJBPuuMlET3-vPHsdU6_nJpAp8KQE32vH5KMNZkCK75PAPNvPMHueQINID_TYrsUf0JHrkE'
        b'-CABBJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC0BCP9VRErSllLzR5xw8mQnIr0FSDknKQaBSoT16lQ3LYv__ZHfpBuZXJIhiL4gHtZd4K3mLex1uHqCk6YFMrqAsD'
    )
    assert len(cesr) == 573

    oobi = OobiResult(
        url=f"inline:cesr/{aid}",
        content_type="application/cesr",
        body=cesr,
    )
    state = _kel_state_from_oobi(oobi, aid)
    assert state["aid"] == aid
    assert state["sequence_number"] == 0
    assert state["current_public_keys"] == [
        "DAz6dsiOU4pbfvp0OB7TqnDXPdhlj_r9cjPJKAmw_9Vq"
    ]
    assert state["witnesses"] == [
        "BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC"
    ]
    # The controller sig attached to the icp should verify against k[0].
    assert state["signature_verified"] is True


def test_kel_state_from_oobi_processes_rotation(issuer_cesr_stream):
    """Rahul audit #2: an old (rotated-out) key must stop working. The
    resolver walks the full KEL and returns the keys FROM THE LAST
    event, not from the icp."""
    from keri.app import habbing

    with habbing.openHby(name="test-rot-issuer", temp=True) as hby:
        hab = hby.makeHab(name="issuer", transferable=True)
        icp_bytes = bytes(hab.makeOwnEvent(sn=0))
        icp_key = hab.kever.verfers[0].qb64

        # Rotate once; makeOwnEvent now serialises the rot too.
        hab.rotate()
        rot_bytes = bytes(hab.makeOwnEvent(sn=1))
        new_key = hab.kever.verfers[0].qb64

        full_kel = icp_bytes + rot_bytes

    assert icp_key != new_key  # sanity

    oobi = OobiResult(
        url=f"https://w1.example/oobi/{hab.pre}",
        content_type="application/cesr",
        body=full_kel,
    )
    state = _kel_state_from_oobi(oobi, hab.pre)

    assert state["sequence_number"] == 1
    # The CURRENT key is the rotated-in one — the icp key does not
    # appear in current_public_keys.
    assert new_key in state["current_public_keys"]
    assert icp_key not in state["current_public_keys"]


def test_kel_state_from_oobi_rejects_rotation_that_breaks_commitment(issuer_cesr_stream):
    """Attacker takes a valid icp, appends a forged rot whose k[0] is a
    key the attacker controls (not the one icp.n committed to). The
    pre-rotation digest check must reject."""
    import json as _json
    from keri.app import habbing
    from keri.core.serdering import SerderKERI

    with habbing.openHby(name="test-forgery", temp=True) as hby:
        hab = hby.makeHab(name="issuer", transferable=True)
        icp_bytes = bytes(hab.makeOwnEvent(sn=0))
        hab.rotate()
        legit_rot = bytes(hab.makeOwnEvent(sn=1))

    # Keep the legit rot's structure, substitute k with an attacker-chosen
    # key. The pre-rotation `n` commitment on the icp won't match the
    # digest of the attacker's new key.
    icp = SerderKERI(raw=icp_bytes)
    _ = icp  # noqa: F841 (just confirming parse)
    legit_rot_body_end = legit_rot.find(b"}") + 1
    rot_ked = _json.loads(legit_rot[:legit_rot_body_end])
    rot_ked["k"] = ["DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]  # bogus
    forged_body = _json.dumps(rot_ked, separators=(",", ":")).encode()
    # size won't match the version header — stream becomes malformed —
    # the walker rejects either on parse or on digest check. Either way,
    # the attacker's key never ends up in current_public_keys.

    oobi = OobiResult(
        url="https://w1.example/forged",
        content_type="application/cesr",
        body=icp_bytes + forged_body,
    )
    with pytest.raises(KelResolutionError):
        _kel_state_from_oobi(oobi, SerderKERI(raw=icp_bytes).pre)


def test_kel_state_from_oobi_rejects_rotation_with_wrong_prefix(issuer_cesr_stream):
    """A rot event bound to a different AID than the icp must reject —
    an attacker can't splice someone else's rot into our KEL."""
    from keri.app import habbing

    with habbing.openHby(name="a", temp=True) as hby_a, \
         habbing.openHby(name="b", temp=True) as hby_b:
        hab_a = hby_a.makeHab(name="a", transferable=True)
        hab_b = hby_b.makeHab(name="b", transferable=True)
        icp_a = bytes(hab_a.makeOwnEvent(sn=0))
        hab_b.rotate()
        rot_b = bytes(hab_b.makeOwnEvent(sn=1))

    oobi = OobiResult(
        url="https://w1.example/splice",
        content_type="application/cesr",
        body=icp_a + rot_b,
    )
    with pytest.raises(KelResolutionError, match="not"):
        _kel_state_from_oobi(oobi, hab_a.pre)


def test_kel_state_from_oobi_rejects_non_icp_first_event():
    """The resolver reads only the inception; a rotation event as the
    first thing in the stream is a malformed OOBI response."""
    aid = "EN8anzGOndcAGirqHkhYQvbt5-6s4ITjd62uqnDbg0VW"
    # Build a well-formed rot body (we don't care if it's cryptographically
    # valid, only that its JSON parses and the version header's size
    # matches the actual byte count).
    rot_payload = (
        b'"t":"rot","d":"EN8anzGOndcAGirqHkhYQvbt5-6s4ITjd62uqnDbg0VW",'
        b'"i":"EN8anzGOndcAGirqHkhYQvbt5-6s4ITjd62uqnDbg0VW","s":"1",'
        b'"kt":"1","k":["DAz6dsiOU4pbfvp0OB7TqnDXPdhlj_r9cjPJKAmw_9Vq"],'
        b'"nt":"1","n":["EPs1wLvzDz-KpTjNFyv_DUB3HrkAqn3JNY7JY2yvNTCA"],'
        b'"bt":"1","br":[],"ba":[],"a":[]}'
    )
    # Header is `{"v":"KERI10JSON<6-hex>_",` → size includes the whole
    # body including the version string. Pre-compute: header length is 24
    # chars + 6 for the hex size, then rot_payload.
    head_prefix = b'{"v":"KERI10JSON'
    tail_hex_underscore = b'_",'
    # Try sizes 1..100000 — the correct one is where the serialized
    # body length equals the declared size.
    for size in range(len(rot_payload) + len(head_prefix) + len(tail_hex_underscore) + 6,
                      len(rot_payload) + len(head_prefix) + len(tail_hex_underscore) + 20):
        body = head_prefix + f"{size:06x}".encode() + tail_hex_underscore + rot_payload
        if len(body) == size:
            break
    else:
        raise AssertionError("failed to compute self-consistent rot body")

    oobi = OobiResult(
        url=f"inline:cesr/{aid}",
        content_type="application/cesr",
        body=body,
    )
    with pytest.raises(KelResolutionError, match="'rot'"):
        _kel_state_from_oobi(oobi, aid)


# ─── Full resolver tests ────────────────────────────────────────────────


def _settings():
    # Build a Settings instance without hitting a .env; the resolver only
    # reads watcher_url + kel_disk_fallback_dir + environment, all of which
    # default to safe values.
    return Settings(environment="local")


def test_resolve_from_oobis_tries_each_url_in_order(issuer_cesr_stream):
    """First URL fails, second succeeds, third isn't called."""
    aid, cesr = issuer_cesr_stream
    good_oobi = OobiResult(
        url="https://w2.example/oobi",
        content_type="application/cesr",
        body=cesr,
    )

    client = MagicMock(spec=WitnessClient)
    client.fetch_oobi.side_effect = [
        WitnessUnreachableError("w1 down"),
        good_oobi,
        # third never invoked
    ]

    r = KelResolver(_settings(), witness_client=client)
    state = r.resolve_from_oobis(
        aid, ["https://w1.example/oobi", "https://w2.example/oobi", "https://w3.example/oobi"]
    )

    assert state["aid"] == aid
    assert state["source"] == "oobi"
    assert state["oobi_url"] == "https://w2.example/oobi"
    assert client.fetch_oobi.call_count == 2


def test_resolve_from_oobis_fails_when_all_urls_fail():
    client = MagicMock(spec=WitnessClient)
    client.fetch_oobi.side_effect = WitnessUnreachableError("down")

    r = KelResolver(_settings(), witness_client=client)
    with pytest.raises(KelResolutionError, match="all 2 OOBI URL"):
        r.resolve_from_oobis("EIssuer", ["https://w1.example/oobi", "https://w2.example/oobi"])


def test_resolve_from_oobis_requires_at_least_one_url():
    r = KelResolver(_settings())
    with pytest.raises(KelResolutionError, match="no OOBI URLs supplied"):
        r.resolve_from_oobis("EIssuer", [])


def test_legacy_resolve_fails_cleanly_without_watcher_or_disk():
    r = KelResolver(_settings())
    with pytest.raises(KelResolutionError, match="watcher unreachable"):
        r.resolve("EIssuer")


# ─── watcher-path tests (fix for Rahul audit #7) ───────────────────────


def test_resolve_via_watcher_parses_oobi_stream(issuer_cesr_stream, monkeypatch):
    """Happy path: /info OK, /oobi/<aid> returns the KEL CESR stream."""
    import httpx

    aid, cesr = issuer_cesr_stream

    def fake_get(url, *, timeout=None):  # noqa: ARG001
        req = httpx.Request("GET", url)
        if url.endswith("/info"):
            return httpx.Response(200, text='{"version":"0.17.13"}', request=req)
        if url.endswith(f"/oobi/{aid}"):
            return httpx.Response(200, content=cesr, request=req)
        raise AssertionError(f"unexpected GET {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    settings = Settings(environment="local", watcher_url="http://watcher.test:3235")
    r = KelResolver(settings)
    state = r.resolve(aid)

    assert state["aid"] == aid
    assert state["source"] == "watcher"
    assert state["watcher_url"] == "http://watcher.test:3235"
    assert len(state["current_public_keys"]) == 1


def test_resolve_via_watcher_raises_when_watcher_lacks_the_aid(monkeypatch):
    """keriox watcher returns 200 + empty body for unknown AIDs.

    Asserts against ``_resolve_via_watcher`` directly: the outer
    ``resolve()`` wrapper catches our KelResolutionError and rewraps it
    as 'watcher unreachable and no usable fallback', which hides the
    specific reason the watcher-side lookup failed.
    """
    import httpx

    def fake_get(url, *, timeout=None):  # noqa: ARG001
        req = httpx.Request("GET", url)
        if url.endswith("/info"):
            return httpx.Response(200, text='{"version":"0.17.13"}', request=req)
        return httpx.Response(200, content=b"", request=req)

    monkeypatch.setattr(httpx, "get", fake_get)

    settings = Settings(environment="local", watcher_url="http://watcher.test:3235")
    r = KelResolver(settings)
    with pytest.raises(KelResolutionError, match="empty OOBI response"):
        r._resolve_via_watcher("EUnknown")
