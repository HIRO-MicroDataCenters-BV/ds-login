"""IPEX grant parser.

An IPEX (Issue, Present, Exchange) grant is the KERI protocol-blessed way an
issuer hands a credential to a holder, who then presents it to a verifier.
Full KERI IPEX wraps the credential in an ``exn`` (exchange) message with
route ``/ipex/grant`` and attached CESR; keriox + signify handle serialisation.

For M36 we accept a pragmatic JSON shape that ds-credential-issuer emits and
any wallet can produce. The shape is a superset of the canonical ``exn``
payload — it drops nothing the full KERI protocol carries, and it adds a
small ``oobis`` block so the verifier can reach the issuer's witnesses
without first resolving them out-of-band.

Grant JSON shape (what ds-login expects on the wire)::

    {
      "exn":      <the KERI exn message as a dict>,
      "acdc":     <the full ACDC credential as a dict>,
      "iss_sig":  "0B...<CESR qb64 signature of the issuer over the ACDC body>",
      "iss_oobis": {
        # URL that returns the issuer AID's KEL. One or more; verifier tries
        # them in order and uses the first that returns a parseable KEL.
        "witness_urls": [
          "https://dkms-witness-1.hus.nextgen.hiro-develop.nl/oobi/<issuer-AID>"
        ],
        # The AIDs of those witnesses (for optional cross-check against the
        # KEL's committed witness set).
        "witness_aids": ["Bxxx..."],
        # Registry details for TEL revocation checks.
        "registry_said": "Exxx...<the ACDC registry SAID>",
        "tel_witness_urls": [
          "https://dkms-witness-1.hus.nextgen.hiro-develop.nl"
        ]
      }
    }

Only three fields are strictly required: ``acdc``, ``iss_sig`` and
``iss_oobis.witness_urls`` — everything else is additional context.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class GrantParseError(ValueError):
    """Grant payload rejected before any cryptographic check runs."""


@dataclass
class ParsedGrant:
    """A validated, structurally-sound IPEX grant.

    No cryptographic claim verified yet — this is just the parse step. The
    verifier (``AcdcVerifier``) consumes a ``ParsedGrant`` and runs the
    sig / KEL / TEL checks.
    """

    acdc: dict[str, Any]
    issuer_aid: str
    subject_aid: str
    credential_said: str
    issuer_signature_qb64: str
    issuer_oobi_urls: list[str]
    issuer_witness_aids: list[str] = field(default_factory=list)
    registry_said: str | None = None
    tel_witness_urls: list[str] = field(default_factory=list)
    exn: dict[str, Any] | None = None


def parse(grant: dict[str, Any]) -> ParsedGrant:
    """Parse a wire grant into a ``ParsedGrant``.

    Raises ``GrantParseError`` on any structural problem (missing field,
    wrong type). Does **not** verify signatures.
    """
    if not isinstance(grant, dict):
        raise GrantParseError("grant must be a JSON object")

    acdc = grant.get("acdc")
    if not isinstance(acdc, dict):
        raise GrantParseError("grant.acdc missing or not a JSON object")

    said = acdc.get("d")
    if not isinstance(said, str) or not said:
        raise GrantParseError("grant.acdc.d (credential SAID) missing")

    issuer_aid = acdc.get("i")
    if not isinstance(issuer_aid, str) or not issuer_aid:
        raise GrantParseError("grant.acdc.i (issuer AID) missing")

    attribute_block = acdc.get("a")
    if not isinstance(attribute_block, dict):
        raise GrantParseError("grant.acdc.a missing or not a JSON object")

    subject_aid = attribute_block.get("i")
    if not isinstance(subject_aid, str) or not subject_aid:
        raise GrantParseError("grant.acdc.a.i (subject AID) missing")

    issuer_sig = grant.get("iss_sig")
    if not isinstance(issuer_sig, str) or not issuer_sig:
        raise GrantParseError("grant.iss_sig (issuer signature) missing")

    oobis = grant.get("iss_oobis")
    if not isinstance(oobis, dict):
        raise GrantParseError("grant.iss_oobis missing or not a JSON object")

    witness_urls = oobis.get("witness_urls")
    if not isinstance(witness_urls, list) or not witness_urls:
        raise GrantParseError(
            "grant.iss_oobis.witness_urls must be a non-empty list — the "
            "verifier needs at least one URL to reach the issuer's witnesses"
        )
    for u in witness_urls:
        if not isinstance(u, str) or not u.startswith(("http://", "https://")):
            raise GrantParseError(
                f"grant.iss_oobis.witness_urls contains non-http URL: {u!r}"
            )

    witness_aids = oobis.get("witness_aids") or []
    if not isinstance(witness_aids, list):
        raise GrantParseError("grant.iss_oobis.witness_aids must be a list")

    registry_said = oobis.get("registry_said")
    if registry_said is not None and not isinstance(registry_said, str):
        raise GrantParseError("grant.iss_oobis.registry_said must be a string")

    tel_witness_urls = oobis.get("tel_witness_urls") or []
    if not isinstance(tel_witness_urls, list):
        raise GrantParseError("grant.iss_oobis.tel_witness_urls must be a list")

    exn = grant.get("exn")
    if exn is not None and not isinstance(exn, dict):
        raise GrantParseError("grant.exn must be a JSON object or absent")

    return ParsedGrant(
        acdc=acdc,
        issuer_aid=issuer_aid,
        subject_aid=subject_aid,
        credential_said=said,
        issuer_signature_qb64=issuer_sig,
        issuer_oobi_urls=list(witness_urls),
        issuer_witness_aids=list(witness_aids),
        registry_said=registry_said,
        tel_witness_urls=list(tel_witness_urls),
        exn=exn,
    )
