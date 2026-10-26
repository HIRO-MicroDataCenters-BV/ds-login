from unittest.mock import MagicMock

import pytest

from app.core.acdc_verifier import AcdcVerifier, CredentialVerificationError
from app.core.kel_resolver import KelResolver


def _credential(subject_aid: str = "EUser123", **attrs):
    """Minimal ACDC envelope shape.

    KERIpy's SerderACDC writes claims flat under `.a`, alongside the KERI
    metadata fields `d` (SAID), `i` (subject AID), `dt` (datetime). Not
    nested under `.a.a`.
    """
    a_block = {
        "d": "EAttrsSAID",
        "i": subject_aid,
        "dt": "2026-10-26T00:00:00+00:00",
        "role": "researcher",
        "institute": "hiro",
        "name": "Alice",
        "email": "alice@hiro.test",
    }
    a_block.update(attrs)
    return {
        "v": "ACDC10JSON00018a_",
        "d": "ECredSAID123",
        "i": "EIssuerAID456",
        "s": "ESchemaSAID789",
        "a": a_block,
    }


def _resolver_stub():
    """Minimal KelResolver double — AcdcVerifier only needs its constructor
    to accept the dependency; the legacy ``verify()`` path never calls it."""
    return MagicMock(spec=KelResolver)


# ─── Legacy bare-ACDC path ─────────────────────────────────────────────


def test_valid_credential_extracts_attributes():
    v = AcdcVerifier(kel_resolver=_resolver_stub())
    result = v.verify(_credential(), subject_aid="EUser123")
    assert result.said == "ECredSAID123"
    assert result.subject_aid == "EUser123"
    assert result.issuer_aid == "EIssuerAID456"
    assert result.attributes["role"] == "researcher"
    assert result.attributes["institute"] == "hiro"
    # Legacy path doesn't verify issuer sig — pub key stays empty, revocation
    # not checked. Callers that need the full chain must send a grant.
    assert result.issuer_pub_key_qb64 == ""
    assert result.revocation_checked is False


def test_rejects_credential_for_wrong_subject():
    v = AcdcVerifier(kel_resolver=_resolver_stub())
    cred = _credential(subject_aid="ESomeoneElse")
    with pytest.raises(CredentialVerificationError, match="does not match"):
        v.verify(cred, subject_aid="EUser123")


def test_rejects_missing_said():
    v = AcdcVerifier(kel_resolver=_resolver_stub())
    cred = _credential()
    del cred["d"]
    with pytest.raises(CredentialVerificationError, match="SAID"):
        v.verify(cred, subject_aid="EUser123")


def test_rejects_missing_issuer():
    v = AcdcVerifier(kel_resolver=_resolver_stub())
    cred = _credential()
    del cred["i"]
    with pytest.raises(CredentialVerificationError, match="issuer"):
        v.verify(cred, subject_aid="EUser123")


def test_rejects_non_dict():
    v = AcdcVerifier(kel_resolver=_resolver_stub())
    with pytest.raises(CredentialVerificationError):
        v.verify("not a credential", subject_aid="EUser123")  # type: ignore[arg-type]


# ─── Phase 1b: IPEX grant path ─────────────────────────────────────────


def _grant(subject_aid="EUser123", **cred_overrides):
    """Minimal IPEX grant shape matching ipex_grant.parse's contract."""
    acdc = _credential(subject_aid=subject_aid, **cred_overrides)
    return {
        "acdc": acdc,
        "iss_sig": "0BABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwx",
        "iss_oobis": {
            "witness_urls": [
                "https://dkms-witness-1.hus.nextgen.hiro-develop.nl/oobi/EIssuerAID456"
            ],
            "witness_aids": ["BxxxWitness1"],
            "registry_said": "ERegistrySAID",
            "tel_witness_urls": [
                "https://dkms-witness-1.hus.nextgen.hiro-develop.nl"
            ],
        },
    }


def test_grant_rejected_when_subject_mismatch():
    """Subject binding runs before KEL resolution so a mismatch doesn't
    waste a witness round-trip."""
    v = AcdcVerifier(kel_resolver=_resolver_stub())
    bad = _grant(subject_aid="ESomeoneElse")
    with pytest.raises(CredentialVerificationError, match="does not match"):
        v.verify_grant(bad, subject_aid="EUser123")


def test_grant_rejected_when_missing_oobis():
    v = AcdcVerifier(kel_resolver=_resolver_stub())
    bad = _grant()
    bad["iss_oobis"]["witness_urls"] = []
    with pytest.raises(CredentialVerificationError, match="malformed"):
        v.verify_grant(bad, subject_aid="EUser123")


def test_grant_rejected_when_kel_unresolvable():
    """If every OOBI URL fails, we don't pretend the credential is good."""
    from app.core.kel_resolver import KelResolutionError

    resolver = MagicMock(spec=KelResolver)
    resolver.resolve_from_oobis.side_effect = KelResolutionError(
        "all 1 OOBI URL(s) failed"
    )
    v = AcdcVerifier(kel_resolver=resolver)
    with pytest.raises(CredentialVerificationError, match="KEL unresolvable"):
        v.verify_grant(_grant(), subject_aid="EUser123")


def test_grant_rejected_when_kel_has_no_current_key():
    """A KEL with no current signing key cannot verify any signature."""
    resolver = MagicMock(spec=KelResolver)
    resolver.resolve_from_oobis.return_value = {
        "aid": "EIssuerAID456",
        "current_public_keys": [],
        "witnesses": [],
        "sequence_number": 0,
        "source": "oobi",
    }
    v = AcdcVerifier(kel_resolver=resolver)
    with pytest.raises(CredentialVerificationError, match="no current signing key"):
        v.verify_grant(_grant(), subject_aid="EUser123")
