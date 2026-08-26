"""JWT validation suitable for local HS256 tests and RS256/OIDC-style public keys.

Never accepts unsigned tokens or alg=none. Never logs token contents.
Algorithm is taken only from configuration — never from an attacker-controlled header alone.
"""

from __future__ import annotations

import jwt
from jwt.exceptions import InvalidTokenError

from grc_agent.auth.models import VALID_ROLES, Principal, Role
from grc_agent.config import Settings

_FORBIDDEN_ALGORITHMS = frozenset({"none"})


class AuthenticationError(Exception):
    """Authentication failed. ``reason`` is for audit logs only — never client bodies."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _configured_algorithm(settings: Settings) -> str:
    algorithm = settings.jwt_algorithm.strip()
    if not algorithm or algorithm.lower() in _FORBIDDEN_ALGORITHMS:
        raise AuthenticationError("invalid_algorithm_configuration")
    return algorithm


def _verification_key(settings: Settings, algorithm: str) -> str:
    """Return the key material for the *configured* algorithm only.

    Symmetric (HS*) and asymmetric (RS*/ES*) paths are never mixed, which blocks
    algorithm-confusion attacks that treat an RSA public key as an HMAC secret.
    """
    algo = algorithm.upper()
    if algo.startswith("HS"):
        secret = settings.jwt_secret
        if not secret:
            raise AuthenticationError("missing_jwt_secret")
        return secret
    if algo.startswith("RS") or algo.startswith("ES"):
        public_key = settings.jwt_public_key
        if not public_key:
            raise AuthenticationError("missing_jwt_public_key")
        return public_key
    raise AuthenticationError("unsupported_jwt_algorithm")


def _reject_if_header_alg_mismatch(token: str, configured_algorithm: str) -> None:
    """Defense in depth: token header alg must match the configured algorithm."""
    try:
        header = jwt.get_unverified_header(token)
    except InvalidTokenError as exc:
        raise AuthenticationError("malformed_token") from exc
    header_alg = str(header.get("alg", "")).strip()
    if not header_alg or header_alg.lower() == "none":
        raise AuthenticationError("rejected_alg_none")
    if header_alg.lower() != configured_algorithm.lower():
        raise AuthenticationError("algorithm_mismatch")


def validate_access_token(token: str, settings: Settings) -> Principal:
    """Validate a Bearer access token and return a Principal.

    Raises AuthenticationError on any failure. Does not echo token material.
    """
    text = (token or "").strip()
    if not text:
        raise AuthenticationError("missing_token")

    configured = _configured_algorithm(settings)
    if text.count(".") >= 1:
        _reject_if_header_alg_mismatch(text, configured)

    key = _verification_key(settings, configured)
    options = {
        "require": ["exp", "iat", "sub"],
        "verify_signature": True,
        "verify_exp": True,
        "verify_nbf": True,
        "verify_iat": True,
        "verify_aud": bool(settings.jwt_audience),
        "verify_iss": bool(settings.jwt_issuer),
    }
    try:
        claims = jwt.decode(
            text,
            key=key,
            algorithms=[configured],
            audience=settings.jwt_audience or None,
            issuer=settings.jwt_issuer or None,
            options=options,
        )
    except InvalidTokenError as exc:
        message = str(exc).lower()
        if "expired" in message:
            raise AuthenticationError("token_expired") from exc
        if "audience" in message:
            raise AuthenticationError("invalid_audience") from exc
        if "issuer" in message:
            raise AuthenticationError("invalid_issuer") from exc
        if "signature" in message:
            raise AuthenticationError("invalid_signature") from exc
        raise AuthenticationError("invalid_token") from exc

    if not isinstance(claims, dict):
        raise AuthenticationError("invalid_claims")

    subject = str(claims.get("sub", "")).strip()
    if not subject:
        raise AuthenticationError("missing_subject")

    role_raw = str(claims.get("role", "")).strip().lower()
    try:
        role = Role(role_raw)
    except ValueError as exc:
        raise AuthenticationError("invalid_role") from exc
    if role not in VALID_ROLES:
        raise AuthenticationError("invalid_role")

    tenant_id = str(claims.get("tenant_id") or claims.get("tid") or "").strip()
    if not tenant_id:
        raise AuthenticationError("missing_tenant")

    return Principal(subject=subject, role=role, tenant_id=tenant_id)
