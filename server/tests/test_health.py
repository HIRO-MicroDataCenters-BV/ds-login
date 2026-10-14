from fastapi.testclient import TestClient

from app.main import app


def test_health_check():
    # Health is public and doesn't need lifespan initialisation
    with TestClient(app) as client:
        r = client.get("/health-check/")
    assert r.status_code == 200
    assert r.json() == {"status": "OK"}


def test_jwks_published():
    # The JWKs route reads from app.state.jwt_signer which lifespan builds —
    # use TestClient as a context manager so startup runs
    with TestClient(app) as client:
        r = client.get("/.well-known/jwks.json")
    assert r.status_code == 200
    body = r.json()
    assert "keys" in body
    assert len(body["keys"]) >= 1
    k = body["keys"][0]
    assert k["kty"] == "RSA"
    assert k["alg"] == "RS256"
    assert k["use"] == "sig"
    assert "n" in k and "e" in k
    assert "kid" in k
