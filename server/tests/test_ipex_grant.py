"""Parser tests for the IPEX grant envelope.

The parser is pure — no witness I/O, no cryptography — so it's cheap to
exercise with lots of malformed input. Keeps the AcdcVerifier tests focused
on the verification pipeline rather than input validation.
"""
import copy

import pytest

from app.core.ipex_grant import GrantParseError, parse

_VALID_GRANT = {
    "acdc": {
        "v": "ACDC10JSON00018a_",
        "d": "ECredSAID",
        "i": "EIssuerAID",
        "s": "ESchemaSAID",
        "a": {
            "d": "EAttrsSAID",
            "i": "ESubjectAID",
            "a": {
                "role": "researcher",
                "institute": "hiro",
                "name": "Alice",
                "email": "alice@hiro.test",
            },
        },
    },
    "iss_sig": "0BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "iss_oobis": {
        "witness_urls": [
            "https://dkms-witness-1.hus.nextgen.hiro-develop.nl/oobi/EIssuerAID",
        ],
        "witness_aids": ["BxxxWitness1"],
        "registry_said": "ERegistrySAID",
        "tel_witness_urls": ["https://dkms-witness-1.hus.nextgen.hiro-develop.nl"],
    },
}


def _mutate(**changes):
    g = copy.deepcopy(_VALID_GRANT)
    for path, value in changes.items():
        keys = path.split(".")
        target = g
        for k in keys[:-1]:
            target = target[k]
        if value is None:
            target.pop(keys[-1], None)
        else:
            target[keys[-1]] = value
    return g


def test_parses_minimal_valid_grant():
    parsed = parse(_VALID_GRANT)
    assert parsed.credential_said == "ECredSAID"
    assert parsed.issuer_aid == "EIssuerAID"
    assert parsed.subject_aid == "ESubjectAID"
    assert parsed.issuer_signature_qb64.startswith("0B")
    assert parsed.issuer_oobi_urls == [
        "https://dkms-witness-1.hus.nextgen.hiro-develop.nl/oobi/EIssuerAID",
    ]
    assert parsed.registry_said == "ERegistrySAID"


@pytest.mark.parametrize(
    "field,expected",
    [
        ("acdc", "acdc missing or not a JSON object"),
        ("iss_sig", "iss_sig"),
        ("iss_oobis", "iss_oobis missing"),
    ],
)
def test_rejects_missing_top_level_field(field, expected):
    g = _mutate(**{field: None})
    with pytest.raises(GrantParseError, match=expected):
        parse(g)


def test_rejects_missing_acdc_said():
    g = _mutate(**{"acdc.d": None})
    with pytest.raises(GrantParseError, match="credential SAID"):
        parse(g)


def test_rejects_missing_issuer_aid():
    g = _mutate(**{"acdc.i": None})
    with pytest.raises(GrantParseError, match="issuer AID"):
        parse(g)


def test_rejects_missing_subject_aid():
    g = _mutate(**{"acdc.a.i": None})
    with pytest.raises(GrantParseError, match="subject AID"):
        parse(g)


def test_rejects_empty_witness_urls_list():
    g = _mutate(**{"iss_oobis.witness_urls": []})
    with pytest.raises(GrantParseError, match="non-empty list"):
        parse(g)


def test_rejects_non_http_witness_url():
    g = _mutate(**{"iss_oobis.witness_urls": ["ftp://sketchy.example/oobi"]})
    with pytest.raises(GrantParseError, match="non-http URL"):
        parse(g)


def test_rejects_non_dict_input():
    with pytest.raises(GrantParseError, match="must be a JSON object"):
        parse("not an object")  # type: ignore[arg-type]


def test_optional_fields_default_sensibly():
    """registry_said / tel_witness_urls / witness_aids / exn are all optional."""
    g = copy.deepcopy(_VALID_GRANT)
    g["iss_oobis"].pop("registry_said")
    g["iss_oobis"].pop("tel_witness_urls")
    g["iss_oobis"].pop("witness_aids")
    parsed = parse(g)
    assert parsed.registry_said is None
    assert parsed.tel_witness_urls == []
    assert parsed.issuer_witness_aids == []
    assert parsed.exn is None
