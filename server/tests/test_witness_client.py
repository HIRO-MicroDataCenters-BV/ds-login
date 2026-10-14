"""HTTP boundary tests for ``WitnessClient``.

Uses ``respx`` to stub httpx calls so no real network. The client is a thin
wrapper, but these tests pin down the two behaviours that matter upstream:

* 2xx + a body → ``OobiResult`` with the body intact (no decoding)
* non-2xx or transport error → ``WitnessUnreachableError`` so the resolver
  can try the next OOBI
"""
import httpx
import pytest
import respx

from app.core.witness_client import (
    OobiResult,
    WitnessClient,
    WitnessUnreachableError,
)


@respx.mock
def test_fetch_oobi_returns_body_on_200():
    respx.get("https://w1.example/oobi/EIssuer").mock(
        return_value=httpx.Response(
            200,
            content=b"<CESR-ish-bytes>",
            headers={"content-type": "application/cesr"},
        )
    )
    c = WitnessClient()
    r = c.fetch_oobi("https://w1.example/oobi/EIssuer")
    assert isinstance(r, OobiResult)
    assert r.body == b"<CESR-ish-bytes>"
    assert r.content_type == "application/cesr"


@respx.mock
def test_fetch_oobi_raises_on_404():
    respx.get("https://w1.example/oobi/EUnknown").mock(
        return_value=httpx.Response(404)
    )
    c = WitnessClient()
    with pytest.raises(WitnessUnreachableError, match="404"):
        c.fetch_oobi("https://w1.example/oobi/EUnknown")


@respx.mock
def test_fetch_oobi_raises_on_connect_error():
    respx.get("https://unreachable.example/oobi/E").mock(
        side_effect=httpx.ConnectError("dns fail")
    )
    c = WitnessClient()
    with pytest.raises(WitnessUnreachableError, match="unreachable"):
        c.fetch_oobi("https://unreachable.example/oobi/E")


@respx.mock
def test_fetch_tel_event_hits_canonical_path():
    """The TEL route must be /tel/<registry>/<credential> — witnesses other
    than keriox would mismatch, so pin the shape."""
    route = respx.get(
        "https://w1.example/tel/ERegistry/ECred"
    ).mock(return_value=httpx.Response(200, content=b"iss"))

    c = WitnessClient()
    r = c.fetch_tel_event(
        witness_url="https://w1.example",
        registry_said="ERegistry",
        credential_said="ECred",
    )
    assert route.called
    assert r.body == b"iss"


@respx.mock
def test_info_returns_json():
    respx.get("https://w1.example/info").mock(
        return_value=httpx.Response(200, json={"version": "0.18.0"})
    )
    c = WitnessClient()
    assert c.info("https://w1.example") == {"version": "0.18.0"}


@respx.mock
def test_info_raises_on_error():
    respx.get("https://w1.example/info").mock(
        return_value=httpx.Response(500)
    )
    c = WitnessClient()
    with pytest.raises(WitnessUnreachableError):
        c.info("https://w1.example")
