"""Service configuration — all backend URLs, cryptographic settings and TTLs
are injected via environment variables so Helm values drive everything in
production.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """ds-login configuration.

    Env var convention: `DS__<SECTION>__<FIELD>` (double underscore) to match
    the pattern used across the rest of the ds-* services.
    """

    model_config = SettingsConfigDict(
        env_prefix="DS__",
        env_nested_delimiter="__",
        env_file=".env",
        extra="ignore",
    )

    # ─── Service identity ─────────────────────────────────────────────
    service_name: str = Field("ds-login", description="Service identifier")
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    environment: Literal["local", "dev", "staging", "production"] = "local"

    # ─── JWT issuance ─────────────────────────────────────────────────
    jwt_issuer: str = Field(
        "ds-login",
        description="JWT iss claim — downstream services pin this.",
    )
    jwt_audience: str = Field(
        "hiro-services",
        description="JWT aud claim.",
    )
    jwt_ttl_seconds: int = Field(900, description="JWT lifetime (default 15 min).")

    # Signing key — ONE of the two must be set.
    #  Production: load a persistent RSA key from a Kubernetes secret so JWTs
    #  survive pod restarts without invalidating active sessions.
    #  Dev: leave both empty — a transient key is generated at startup.
    jwt_private_key_pem_path: Path | None = Field(
        default=None,
        description="Path to a PKCS8 PEM-encoded RSA private key.",
    )
    jwt_private_key_pem_inline: str | None = Field(
        default=None,
        description="Inline PKCS8 PEM-encoded RSA private key (useful for CI).",
    )

    # ─── DKMS / KERI backend ──────────────────────────────────────────
    # The verifier reaches witnesses through a watcher — the watcher caches
    # KELs and shields the verifier from witness unreachability.
    watcher_url: str = Field(
        "http://keriox-watcher:3235",
        description="URL of the keriox watcher this service talks to.",
    )
    witness_urls: list[str] = Field(
        default_factory=lambda: [
            "http://keriox-witness1:3232",
            "http://keriox-witness2:3233",
            "http://keriox-witness3:3234",
        ],
        description="Fallback witness URLs if the watcher is unreachable.",
    )

    # ─── Challenge / nonce ────────────────────────────────────────────
    challenge_ttl_seconds: int = Field(300, description="How long a login nonce is valid.")
    challenge_bytes: int = Field(32, description="Nonce entropy — 32 bytes is default.")

    # ─── Dev-only KEL fallback ────────────────────────────────────────
    # When the watcher is unreachable (local dev; initial rollout before
    # DKMS is deployed), fall back to reading pre-exported KEL JSON files.
    # Set DS__ENVIRONMENT=production to make this an error instead.
    kel_disk_fallback_dir: Path | None = Field(
        default=None,
        description="If set, verify can read KELs from here when watcher is unavailable.",
    )

    # ─── Credential trust ─────────────────────────────────────────────
    # Allowlist of AIDs this verifier will accept credentials FROM. The
    # IPEX grant carries an issuer-signed ACDC along with the issuer's
    # own KEL (inline or via OOBI); without this gate, *any* AID can
    # self-issue a credential — including role=admin — bind it to
    # itself, sign it with its own key, and present a grant whose KEL
    # it also controls. The whole chain cryptographically checks out
    # from a protocol standpoint, so the only thing that stops it is
    # a policy-level "do I trust this issuer at all" check.
    #
    # Fail-safe default: empty list rejects every grant. Deployers
    # MUST set DS__TRUSTED_ISSUER_AIDS to the list of issuer AIDs they
    # recognise. In HUS this is the ds-credential-issuer's own AID,
    # discovered at startup from the issuer's /health-check/.
    trusted_issuer_aids: list[str] = Field(
        default_factory=list,
        description=(
            "AIDs this verifier will accept IPEX grants from. Empty "
            "list = reject-all (safe default). Set via "
            "DS__TRUSTED_ISSUER_AIDS as a JSON list."
        ),
    )


    # Where to ask each trusted issuer whether a credential was revoked:
    # issuer AID -> issuer base URL (GET {url}/credential-status?said=…).
    # Fail closed: a grant from an issuer without an entry is rejected.
    issuer_status_urls: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Issuer AID -> base URL of its revocation status endpoint. Set "
            "via DS__ISSUER_STATUS_URLS as a JSON object."
        ),
    )

@lru_cache(maxsize=1)
def get_settings() -> Settings:
    # mypy can't see that pydantic BaseSettings pulls every field's
    # default from Field(default=…) / Field(default_factory=…) at
    # construction time — it reads each required-type annotation as if
    # the constructor demanded an explicit kwarg. The call itself is
    # the standard pydantic-settings idiom.
    return Settings()  # type: ignore[call-arg]
