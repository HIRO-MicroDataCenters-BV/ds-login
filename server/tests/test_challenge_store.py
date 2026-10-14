import time

from app.core.challenge_store import ChallengeStore


def test_issue_and_consume_valid():
    store = ChallengeStore(ttl_seconds=60, nonce_bytes=16)
    c = store.issue("Eaid1")
    assert store.consume("Eaid1", c.nonce) is not None


def test_consume_wrong_nonce_rejects():
    store = ChallengeStore(ttl_seconds=60, nonce_bytes=16)
    store.issue("Eaid1")
    assert store.consume("Eaid1", b"\x00" * 16) is None


def test_nonce_single_use():
    store = ChallengeStore(ttl_seconds=60, nonce_bytes=16)
    c = store.issue("Eaid1")
    assert store.consume("Eaid1", c.nonce) is not None  # first use
    assert store.consume("Eaid1", c.nonce) is None       # replay rejected


def test_consume_unknown_aid():
    store = ChallengeStore(ttl_seconds=60, nonce_bytes=16)
    assert store.consume("Eaid-never-issued", b"anything") is None


def test_expired_nonce_rejected():
    store = ChallengeStore(ttl_seconds=0, nonce_bytes=16)
    c = store.issue("Eaid1")
    time.sleep(0.01)
    assert store.consume("Eaid1", c.nonce) is None
