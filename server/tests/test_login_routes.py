"""Route-level tests for /login/challenge and /login/verify.

Focused on the signable-payload dual-shape invariant added in PR #31:
the verifier accepts a signature over EITHER the raw hex-decoded nonce
bytes (KERIpy-native path) OR the canonical JSON envelope
``{"nonce":"<hex>"}`` (dkms-bin path, since ``dkms data sign`` only
accepts JSON input).
"""
from __future__ import annotations

import binascii
import json
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from app.core.acdc_verifier import AcdcVerifier
from app.core.challenge_store import ChallengeStore
from app.core.kel_resolver import KelResolver
from app.core.signature_verifier import SignatureVerifier
from app.main import app
from app.rest_api.depends import (
    acdc_verifier_dep,
    challenge_store_dep,
    kel_resolver_dep,
    signature_verifier_dep,
)


_PUBKEY = "DAz6dsiOU4pbfvp0OB7TqnDXPdhlj_r9cjPJKAmw_9Vq"
_AID = "EN8anzGOndcAGirqHkhYQvbt5-6s4ITjd62uqnDbg0VW"
_HOLDER_KEL_CESR = (
    '{"v":"KERI10JSON000159_","t":"icp",'
    '"d":"EN8anzGOndcAGirqHkhYQvbt5-6s4ITjd62uqnDbg0VW",'
    '"i":"EN8anzGOndcAGirqHkhYQvbt5-6s4ITjd62uqnDbg0VW","s":"0",'
    '"kt":"1","k":["DAz6dsiOU4pbfvp0OB7TqnDXPdhlj_r9cjPJKAmw_9Vq"],'
    '"nt":"1","n":["EPs1wLvzDz-KpTjNFyv_DUB3HrkAqn3JNY7JY2yvNTCA"],'
    '"bt":"1","b":["BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC"],'
    '"c":[],"a":[]}'
)


def _resolver_stub():
    r = MagicMock(spec=KelResolver)
    r.resolve_trusted.return_value = {
        "aid": _AID,
        "current_public_keys": [_PUBKEY],
        "witnesses": ["BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC"],
        "sequence_number": 0,
    }
    return r


def _record_verifier():
    """SignatureVerifier that records what bytes it was asked to verify."""
    v = MagicMock(spec=SignatureVerifier)
    v.calls = []  # type: ignore[attr-defined]

    def _verify(public_key_qb64, data, signature_qb64):
        v.calls.append(bytes(data))  # type: ignore[attr-defined]
        # Return True iff the data matches whatever payload the test
        # expects the client's signature to cover.
        return bytes(data) == v.accept_payload  # type: ignore[attr-defined]

    v.verify.side_effect = _verify
    return v


def _acdc_stub():
    v = MagicMock(spec=AcdcVerifier)
    v.verify_grant.side_effect = RuntimeError("should not be called in these tests")
    v.verify.side_effect = RuntimeError("should not be called in these tests")
    return v


def _make_client(sig_verifier):
    """Build a TestClient with the externals mocked out."""
    resolver = _resolver_stub()
    store = ChallengeStore(ttl_seconds=60, nonce_bytes=32)
    app.dependency_overrides[kel_resolver_dep] = lambda: resolver
    app.dependency_overrides[challenge_store_dep] = lambda: store
    app.dependency_overrides[signature_verifier_dep] = lambda: sig_verifier
    app.dependency_overrides[acdc_verifier_dep] = lambda: _acdc_stub()
    return TestClient(app)


def _issue_challenge_and_get_nonce(client):
    r = client.post(
        "/login/challenge",
        json={"aid": _AID, "holder_kel_cesr": _HOLDER_KEL_CESR},
    )
    assert r.status_code == 200, r.text
    return r.json()["nonce_hex"]


def teardown_function(_):
    # Keep tests independent — clear overrides between runs
    app.dependency_overrides.clear()


# ─── signable-payload dual-shape invariant ────────────────────────────


def test_verify_accepts_signature_over_raw_hex_decoded_nonce():
    """KERIpy-native path: client signs the raw bytes of unhex(nonce_hex)."""
    sv = _record_verifier()
    with _make_client(sv) as client:
        nonce_hex = _issue_challenge_and_get_nonce(client)
        sv.accept_payload = binascii.unhexlify(nonce_hex)  # type: ignore[attr-defined]
        r = client.post("/login/verify", json={
            "aid": _AID,
            "nonce_hex": nonce_hex,
            "signature_qb64": "0B" + "A" * 86,  # opaque — mock verifies by payload
            "holder_kel_cesr": _HOLDER_KEL_CESR,
        })
    body = r.json()
    # No credential was supplied; verify returns verified=False with the
    # specific "no credential" reason — but the signature check must
    # have passed to reach that branch. Signature-check failure sets a
    # different reason.
    assert "no credential supplied" in body["reason"] or body.get("verified") is True, body
    # The raw-nonce payload was tried first and accepted.
    assert sv.calls[0] == binascii.unhexlify(nonce_hex)


def test_verify_accepts_signature_over_json_envelope():
    """dkms-bin path: client signs ``{"nonce":"<hex>"}`` because dkms
    data sign refuses non-JSON input."""
    sv = _record_verifier()
    with _make_client(sv) as client:
        nonce_hex = _issue_challenge_and_get_nonce(client)
        envelope = json.dumps({"nonce": nonce_hex},
                              separators=(",", ":"), sort_keys=True).encode()
        sv.accept_payload = envelope  # type: ignore[attr-defined]
        r = client.post("/login/verify", json={
            "aid": _AID,
            "nonce_hex": nonce_hex,
            "signature_qb64": "0B" + "A" * 86,
            "holder_kel_cesr": _HOLDER_KEL_CESR,
        })
    body = r.json()
    assert "no credential supplied" in body["reason"] or body.get("verified") is True, body
    # The verifier should have tried the raw-nonce payload first,
    # then fallen back to the JSON envelope and accepted it.
    assert sv.calls[0] == binascii.unhexlify(nonce_hex)
    assert sv.calls[1] == envelope


def test_verify_rejects_signature_over_neither_payload_shape():
    """Signatures over unrelated bytes stay rejected under both shapes."""
    sv = _record_verifier()
    with _make_client(sv) as client:
        nonce_hex = _issue_challenge_and_get_nonce(client)
        # accept_payload set to something the client never signs — both
        # tried shapes fail.
        sv.accept_payload = b"unrelated bytes nobody signed"  # type: ignore[attr-defined]
        r = client.post("/login/verify", json={
            "aid": _AID,
            "nonce_hex": nonce_hex,
            "signature_qb64": "0B" + "A" * 86,
            "holder_kel_cesr": _HOLDER_KEL_CESR,
        })
    body = r.json()
    assert body["verified"] is False
    assert "Ed25519 signature invalid" in body["reason"]
