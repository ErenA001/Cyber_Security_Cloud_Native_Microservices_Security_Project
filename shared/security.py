from __future__ import annotations

import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

import jwt
from fastapi import Depends, HTTPException, Request, status

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "")
if len(JWT_SECRET_KEY) < 32 or JWT_SECRET_KEY == "GENERATE_WITH_SETUP_SCRIPT":
    raise RuntimeError("JWT_SECRET_KEY is missing or too short. Run scripts/setup.py and restart the stack.")

JWT_ISSUER = "cloudguard-auth"
JWT_AUDIENCE = "cloudguard-api"
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "60"))
if not 5 <= ACCESS_TOKEN_MINUTES <= 240:
    raise RuntimeError("ACCESS_TOKEN_MINUTES must be between 5 and 240.")
COOKIE_NAME = "cloudguard_access"


def create_access_token(username: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "role": role,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_MINUTES)).timestamp()),
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")


def decode_access_token(token: str) -> dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=["HS256"],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            options={"require": ["sub", "role", "iss", "aud", "iat", "exp", "jti"]},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required or session expired.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    if payload.get("role") not in {"admin", "analyst"} or not isinstance(payload.get("sub"), str):
        raise HTTPException(status_code=401, detail="Invalid session.")
    return payload


def get_current_user(request: Request) -> dict[str, str]:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        authorization = request.headers.get("Authorization", "")
        if authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required.")
    payload = decode_access_token(token)
    return {"username": payload["sub"], "role": payload["role"]}


def require_admin(user: dict[str, str] = Depends(get_current_user)) -> dict[str, str]:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Administrator role required.")
    return user


def require_same_origin_request(request: Request) -> None:
    """Require a non-simple browser header and reject cross-site state changes."""
    if request.headers.get("X-Requested-With") != "XMLHttpRequest":
        raise HTTPException(status_code=403, detail="Request origin check failed.")
    fetch_site = request.headers.get("Sec-Fetch-Site", "").lower()
    if fetch_site == "cross-site":
        raise HTTPException(status_code=403, detail="Cross-site request rejected.")
    origin = request.headers.get("Origin")
    host = request.headers.get("Host")
    if origin and host:
        try:
            origin_parts = urlsplit(origin)
            expected_scheme = request.headers.get("X-Forwarded-Proto", request.url.scheme).lower()
            if origin_parts.netloc.lower() != host.lower() or origin_parts.scheme.lower() != expected_scheme:
                raise HTTPException(status_code=403, detail="Cross-origin request rejected.")
        except ValueError as exc:
            raise HTTPException(status_code=403, detail="Invalid request origin.") from exc
