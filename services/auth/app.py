from __future__ import annotations

import os
import sqlite3
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from shared.events import emit_event
from shared.security import (
    ACCESS_TOKEN_MINUTES,
    COOKIE_NAME,
    create_access_token,
    get_current_user,
    require_same_origin_request,
)

DB_PATH = Path(os.getenv("AUTH_DATABASE_PATH", "/data/auth.db"))
ADMIN_USERNAME = os.getenv("BOOTSTRAP_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
PASSWORD_HASHER = PasswordHasher()
DUMMY_PASSWORD_HASH = PASSWORD_HASHER.hash("cloudguard-dummy-password")


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=2, max_length=64, pattern=r"^[a-zA-Z0-9_.@-]+$")
    password: str = Field(min_length=1, max_length=256)


class ChangePasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=14, max_length=256)


def connect_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


@contextmanager
def db_session():
    connection = connect_db()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database() -> None:
    if len(ADMIN_PASSWORD) < 14 or ADMIN_PASSWORD == "GENERATE_WITH_SETUP_SCRIPT":
        raise RuntimeError("BOOTSTRAP_ADMIN_PASSWORD is missing. Run python3 scripts/setup.py first.")
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db_session() as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'analyst')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )"""
        )
        row = connection.execute("SELECT username FROM users WHERE username = ?", (ADMIN_USERNAME,)).fetchone()
        if row is None:
            connection.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
                (ADMIN_USERNAME, PASSWORD_HASHER.hash(ADMIN_PASSWORD)),
            )


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(title="CloudGuard Auth Service", version="2.0.0", docs_url=None, redoc_url=None, lifespan=lifespan)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "auth"}


@app.post("/login", dependencies=[Depends(require_same_origin_request)])
async def login(data: LoginRequest, request: Request, response: Response):
    with db_session() as connection:
        row = connection.execute(
            "SELECT username, password_hash, role FROM users WHERE username = ?",
            (data.username,),
        ).fetchone()

    valid = False
    if row is not None:
        try:
            valid = PASSWORD_HASHER.verify(row["password_hash"], data.password)
        except VerificationError:
            valid = False
    else:
        # Perform a dummy Argon2 verification to reduce username-enumeration timing differences.
        try:
            PASSWORD_HASHER.verify(DUMMY_PASSWORD_HASH, data.password)
        except VerificationError:
            pass

    if not valid:
        await emit_event(
            "auth.login.failed",
            "auth",
            "WARNING",
            actor=data.username,
            details={"reason": "invalid_credentials"},
            request_id=request.headers.get("X-Request-ID"),
        )
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    token = create_access_token(row["username"], row["role"])
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=ACCESS_TOKEN_MINUTES * 60,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        path="/",
    )
    await emit_event(
        "auth.login.succeeded",
        "auth",
        "INFO",
        actor=row["username"],
        details={"method": "password", "role": row["role"]},
        request_id=request.headers.get("X-Request-ID"),
    )
    return {"authenticated": True, "user": {"username": row["username"], "role": row["role"]}}


@app.get("/me")
async def me(user: dict[str, str] = Depends(get_current_user)):
    return {"user": user}


@app.post("/logout", dependencies=[Depends(require_same_origin_request)])
async def logout(response: Response, user: dict[str, str] = Depends(get_current_user)):
    response.delete_cookie(key=COOKIE_NAME, path="/", httponly=True, secure=COOKIE_SECURE, samesite="strict")
    await emit_event("auth.logout", "auth", "INFO", actor=user["username"])
    return {"authenticated": False}


@app.post("/change-password", dependencies=[Depends(require_same_origin_request)])
async def change_password(
    data: ChangePasswordRequest,
    response: Response,
    user: dict[str, str] = Depends(get_current_user),
):
    with db_session() as connection:
        row = connection.execute(
            "SELECT password_hash FROM users WHERE username = ?", (user["username"],)
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail="Account no longer exists.")
        try:
            valid = PASSWORD_HASHER.verify(row["password_hash"], data.current_password)
        except VerificationError:
            valid = False
        if not valid:
            raise HTTPException(status_code=400, detail="Current password is incorrect.")
        if data.current_password == data.new_password:
            raise HTTPException(status_code=400, detail="Choose a different new password.")
        connection.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (PASSWORD_HASHER.hash(data.new_password), user["username"]),
        )
    response.delete_cookie(key=COOKIE_NAME, path="/", httponly=True, secure=COOKIE_SECURE, samesite="strict")
    await emit_event("auth.password.changed", "auth", "INFO", actor=user["username"], details={"method": "self_service"})
    return {"changed": True, "reauthentication_required": True}
