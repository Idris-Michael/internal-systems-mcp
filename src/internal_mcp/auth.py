"""Bearer tokens for the MCP endpoint: signed, expiring, bound to this server, carrying scopes.

This server is an OAuth *resource server*: it verifies tokens, it does not issue them. Tokens are
HS256 JWTs here so the repo runs with no identity provider; in production you would swap
:class:`JwtVerifier` for one that checks RS256 tokens against your provider's JWKS (Entra ID,
Okta, Auth0). The scope model and every check after verification stay the same.
"""

from __future__ import annotations

import time
import uuid

import jwt
from mcp.server.auth.provider import AccessToken

ISSUER = "https://auth.internal.example"
AUDIENCE = "internal-systems-mcp"
SCOPES = frozenset({"brand:read", "crm:read", "drafts:write"})
MAX_TTL_S = 3600


class JwtVerifier:
    """Implements the MCP SDK's TokenVerifier protocol. Returns None for any token it can't trust."""

    def __init__(self, secret: str) -> None:
        if len(secret) < 32:
            raise ValueError("token signing secret must be at least 32 characters")
        self._secret = secret

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            claims = jwt.decode(
                token,
                self._secret,
                algorithms=["HS256"],  # pinned: "none" and algorithm swaps are rejected
                audience=AUDIENCE,
                issuer=ISSUER,
                options={"require": ["exp", "iat", "sub", "aud", "iss", "scope"]},
            )
        except jwt.PyJWTError:
            return None
        if claims["exp"] - claims["iat"] > MAX_TTL_S:
            return None  # long-lived tokens are refused even if correctly signed
        scopes = [s for s in str(claims["scope"]).split() if s in SCOPES]
        return AccessToken(
            token=token,
            client_id=str(claims["sub"]),
            scopes=scopes,
            expires_at=int(claims["exp"]),
            subject=str(claims["sub"]),
        )


def mint_token(secret: str, client_id: str, scopes: list[str], ttl_s: int = 900) -> str:
    """Dev-only issuer, standing in for the identity provider. Unknown scopes are rejected."""
    unknown = set(scopes) - SCOPES
    if unknown:
        raise ValueError(f"unknown scopes: {sorted(unknown)}")
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": client_id,
        "scope": " ".join(scopes),
        "iat": now,
        "exp": now + ttl_s,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(claims, secret, algorithm="HS256")
