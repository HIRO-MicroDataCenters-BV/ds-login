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
    # Facade grants (Phase 1): dkms-bin-issued grants carry the issuer's
    # own KEL as a CESR stream, so a verifier can parse it in-process
    # without OOBI resolve (watchers don't serve third-party KELs over
    # plain HTTP in keriox 0.17). When present, verifiers prefer this
    # over witness_urls.
    issuer_kel_cesr: str = ""


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

    # Subject binding and user-facing claims can live in one of two
    # shapes depending on the issuer:
    #   * HCF (dkms-bin) nests them at acdc.a.a.*  — dkms-bin wraps the
    #     caller-supplied attribute dict one level deep, so a mint that
    #     binds `i: subject_aid` as an attribute lands at acdc.a.a.i.
    #   * KERIpy flat shape puts them at acdc.a.*  — this is what the
    #     verifier's unit tests use.
    # We prefer HCF nesting when `a.a` is a JSON object AND it carries
    # the subject binding; otherwise fall back to the flat shape. Both
    # paths must agree on the subject or we'd be reading claims from one
    # shape and the subject from another.
    inner = attribute_block.get("a")
    claim_block: dict[str, Any]
    if isinstance(inner, dict) and isinstance(inner.get("i"), str) and inner.get("i"):
        claim_block = inner
    else:
        claim_block = attribute_block

    subject_aid = claim_block.get("i")
    if not isinstance(subject_aid, str) or not subject_aid:
        raise GrantParseError(
            "grant.acdc.a.i or grant.acdc.a.a.i (subject AID) missing"
        )

    issuer_sig = grant.get("iss_sig")
    if not isinstance(issuer_sig, str) or not issuer_sig:
        raise GrantParseError("grant.iss_sig (issuer signature) missing")

    # Phase 1 facade shortcut: inline KEL, no OOBI resolution needed.
    iss_kel_cesr = grant.get("iss_kel_cesr") or ""
    if iss_kel_cesr and not isinstance(iss_kel_cesr, str):
        raise GrantParseError("grant.iss_kel_cesr must be a string if present")

    oobis = grant.get("iss_oobis")
    if not isinstance(oobis, dict):
        raise GrantParseError("grant.iss_oobis missing or not a JSON object")

    # When the grant carries an inline KEL, OOBI URLs become optional
    # (the verifier won't need to resolve). This is the dkms-bin-issued
    # shape; we keep the strict validation for legacy grants that still
    # depend on OOBI resolve.
    witness_urls = oobis.get("witness_urls") or []
    if not isinstance(witness_urls, list):
        raise GrantParseError("grant.iss_oobis.witness_urls must be a list")
    if not iss_kel_cesr and not witness_urls:
        raise GrantParseError(
            "grant.iss_oobis.witness_urls must be non-empty when "
            "grant.iss_kel_cesr is absent — the verifier needs at least "
            "one way to reach the issuer's KEL"
        )
    # Only validate URL shape for legacy string-URL entries; dkms-bin
    # emits stringified JSON objects here (object OOBIs, per the facade).
    for u in witness_urls:
        if not isinstance(u, str):
            raise GrantParseError(
                f"grant.iss_oobis.witness_urls entry is not a string: {u!r}"
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
        issuer_kel_cesr=iss_kel_cesr,
    )
