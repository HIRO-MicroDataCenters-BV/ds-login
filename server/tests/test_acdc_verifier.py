import pytest

from app.core.acdc_verifier import AcdcVerifier, CredentialVerificationError


def _credential(subject_aid: str = "EUser123", **attrs):
    """Minimal ACDC envelope shape."""
    attributes = {"role": "researcher", "institute": "hiro", "name": "Alice",
                  "email": "alice@hiro.test"}
    attributes.update(attrs)
    return {
        "v": "ACDC10JSON00018a_",
        "d": "ECredSAID123",
        "i": "EIssuerAID456",
        "s": "ESchemaSAID789",
        "a": {"d": "EAttrsSAID", "i": subject_aid, "a": attributes},
    }


def test_valid_credential_extracts_attributes():
    v = AcdcVerifier()
    result = v.verify(_credential(), subject_aid="EUser123")
    assert result.said == "ECredSAID123"
    assert result.subject_aid == "EUser123"
    assert result.issuer_aid == "EIssuerAID456"
    assert result.attributes["role"] == "researcher"
    assert result.attributes["institute"] == "hiro"


def test_rejects_credential_for_wrong_subject():
    v = AcdcVerifier()
    cred = _credential(subject_aid="ESomeoneElse")
    with pytest.raises(CredentialVerificationError, match="does not match"):
        v.verify(cred, subject_aid="EUser123")


def test_rejects_missing_said():
    v = AcdcVerifier()
    cred = _credential()
    del cred["d"]
    with pytest.raises(CredentialVerificationError, match="SAID"):
        v.verify(cred, subject_aid="EUser123")


def test_rejects_missing_issuer():
    v = AcdcVerifier()
    cred = _credential()
    del cred["i"]
    with pytest.raises(CredentialVerificationError, match="issuer"):
        v.verify(cred, subject_aid="EUser123")


def test_rejects_non_dict():
    v = AcdcVerifier()
    with pytest.raises(CredentialVerificationError):
        v.verify("not a credential", subject_aid="EUser123")  # type: ignore[arg-type]
