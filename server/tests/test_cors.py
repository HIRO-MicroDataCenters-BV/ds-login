"""CORS: only the configured website origins may call ds-login from a browser."""
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.main import add_cors
from app.settings import Settings

SITE = "https://dev.nextgen.hiro-develop.nl"


def _app(origins: list[str]) -> FastAPI:
    app = FastAPI()

    @app.post("/login/challenge")
    def challenge() -> dict[str, str]:
        return {"ok": "yes"}

    add_cors(app, origins)
    return app


def _preflight(client: TestClient, origin: str):
    return client.options("/login/challenge", headers={
        "Origin": origin,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type",
    })


def test_allowed_origin_passes_preflight_and_call():
    client = TestClient(_app([SITE]))
    r = _preflight(client, SITE)
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == SITE
    assert "access-control-allow-credentials" not in r.headers
    r = client.post("/login/challenge", headers={"Origin": SITE})
    assert r.headers["access-control-allow-origin"] == SITE


def test_other_origin_is_refused():
    client = TestClient(_app([SITE]))
    r = _preflight(client, "https://evil.example")
    assert r.status_code == 400
    assert "access-control-allow-origin" not in r.headers
    r = client.post("/login/challenge", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in r.headers


def test_no_origins_means_no_cors():
    client = TestClient(_app([]))
    assert _preflight(client, SITE).status_code == 405


def test_wildcard_allows_every_website():
    client = TestClient(_app(["*"]))
    for origin in (SITE, "http://localhost:3300", "https://any.example"):
        r = _preflight(client, origin)
        assert r.status_code == 200
        assert r.headers["access-control-allow-origin"] == "*"
        assert "access-control-allow-credentials" not in r.headers


def test_setting_reads_a_json_list(monkeypatch):
    monkeypatch.setenv("DS__CORS_ALLOWED_ORIGINS", f'["{SITE}", "https://nextgen.hiro-develop.nl"]')
    assert Settings().cors_allowed_origins == [SITE, "https://nextgen.hiro-develop.nl"]  # type: ignore[call-arg]
