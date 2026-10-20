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
    with pytest.raises(KelResolutionError, match="did not include a KEL"):
        _kel_state_from_oobi(oobi, "EDefinitelyNotTheIssuer")


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
    """keriox watcher returns 200 + empty body for unknown AIDs."""
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
        r.resolve("EUnknown")
