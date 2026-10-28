"""RevocationClient: asks the issuer's /credential-status and fails closed."""
from __future__ import annotations

import httpx
import pytest

from app.core.revocation_client import RevocationCheckError, RevocationClient

ISSUER = "EIssuerAID456"
SAID = "ECredSAID123"


class _Resp:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self._body = body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("bad", request=None, response=None)  # type: ignore[arg-type]

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


def _client(monkeypatch, answer):
    calls = []

    def fake_get(url, params, timeout):
        calls.append((url, params))
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(httpx, "get", fake_get)
    return RevocationClient({ISSUER: "http://issuer:8080/"}), calls


def test_not_revoked_passes(monkeypatch):
    c, calls = _client(monkeypatch, _Resp(body={"said": SAID, "status": "not_revoked"}))
    c.ensure_not_revoked(ISSUER, SAID)
    assert calls == [("http://issuer:8080/credential-status", {"said": SAID})]


def test_revoked_is_rejected(monkeypatch):
    c, _ = _client(monkeypatch, _Resp(body={"said": SAID, "status": "revoked"}))
    with pytest.raises(RevocationCheckError, match="is revoked"):
        c.ensure_not_revoked(ISSUER, SAID)


@pytest.mark.parametrize("answer", [
    httpx.ConnectError("refused"),                     # issuer down
    _Resp(status_code=503),                            # issuer error
    _Resp(body=ValueError("not json")),                # garbage
    _Resp(body={"status": "maybe"}),                   # unknown status
    _Resp(body=["not", "an", "object"]),               # wrong shape
])
def test_fails_closed_when_status_unknown(monkeypatch, answer):
    c, _ = _client(monkeypatch, answer)
    with pytest.raises(RevocationCheckError):
        c.ensure_not_revoked(ISSUER, SAID)


def test_issuer_without_status_url_is_rejected(monkeypatch):
    c, calls = _client(monkeypatch, _Resp(body={"status": "not_revoked"}))
    with pytest.raises(RevocationCheckError, match="no revocation status URL"):
        c.ensure_not_revoked("EOtherIssuer", SAID)
    assert calls == []
