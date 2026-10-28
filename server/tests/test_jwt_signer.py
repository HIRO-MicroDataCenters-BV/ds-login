"""JwtSigner: the kid is derived from the key, so it is stable across restarts
and replicas and changes only when the key changes."""
from __future__ import annotations

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.jwt_signer import JwtSigner
from app.settings import Settings


def _pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def _signer(pem: str) -> JwtSigner:
    settings = Settings()
    settings.jwt_private_key_pem_path = None
    settings.jwt_private_key_pem_inline = pem
    return JwtSigner(settings)


def test_same_key_same_kid_across_instances():
    pem = _pem()
    first, second = _signer(pem), _signer(pem)  # a restart, or two replicas
    assert first.jwks()["keys"][0]["kid"] == second.jwks()["keys"][0]["kid"]


def test_token_from_one_instance_verifies_with_the_others_jwks():
    pem = _pem()
    token = _signer(pem).sign({"sub": "EAid"})
    jwk = _signer(pem).jwks()["keys"][0]
    assert pyjwt.get_unverified_header(token)["kid"] == jwk["kid"]
    key = pyjwt.algorithms.RSAAlgorithm.from_jwk(jwk)
    assert pyjwt.decode(token, key, algorithms=["RS256"])["sub"] == "EAid"


def test_different_key_different_kid():
    assert _signer(_pem()).jwks()["keys"][0]["kid"] != _signer(_pem()).jwks()["keys"][0]["kid"]


def test_kid_is_rfc7638_thumbprint():
    # RFC 7638 section 3.1 example key and its published thumbprint.
    jwk = {
        "e": "AQAB",
        "kty": "RSA",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    }
    assert JwtSigner._thumbprint(jwk) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
