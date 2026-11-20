"""JWT issue / verify with per-node secrets and key-version tracking."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from network.secrets_store import load_secret

ALGORITHM = "HS256"
TOKEN_TTL_SECONDS = 300
bearer_scheme = HTTPBearer(auto_error=False)


@dataclass
class NodeAuthState:
    port: int
    secret: str
    key_version: int = 1
    revoked_jtis: set[str] = field(default_factory=set)
    issued_tokens: int = 0

    def refresh_secret(self, new_secret: str) -> None:
        self.secret = new_secret
        self.key_version += 1
        self.revoked_jtis.clear()


def create_token(
    state: NodeAuthState,
    subject: str,
    claims: dict[str, Any] | None = None,
    ttl: int = TOKEN_TTL_SECONDS,
) -> str:
    now = int(time.time())
    jti = f"{state.port}-{now}-{state.issued_tokens}"
    payload: dict[str, Any] = {
        "sub": subject,
        "iss": f"node-{state.port}",
        "iat": now,
        "exp": now + ttl,
        "jti": jti,
        "kv": state.key_version,
    }
    if claims:
        reserved = set(payload) & set(claims)
        if reserved:
            raise ValueError("Cannot override reserved JWT claims")
        payload.update(claims)
    token = jwt.encode(payload, state.secret, algorithm=ALGORITHM)
    state.issued_tokens += 1
    return token


def decode_token(state: NodeAuthState, token: str) -> dict[str, Any]:
    try:
        payload = jwt.decode(token, state.secret, algorithms=[ALGORITHM], issuer=f"node-{state.port}", options={"require": ["exp", "iat", "sub", "iss", "jti", "kv"]})
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc

    if payload.get("kv") != state.key_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token key version revoked (secret rotated)",
        )
    jti = payload.get("jti")
    if jti and jti in state.revoked_jtis:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token revoked")
    return payload


def make_auth_dependency(state: NodeAuthState):
    async def require_jwt(
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    ) -> dict[str, Any]:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Bearer token")
        return decode_token(state, credentials.credentials)

    return require_jwt


def bootstrap_auth_state(port: int) -> NodeAuthState:
    return NodeAuthState(port=port, secret=load_secret(port))
