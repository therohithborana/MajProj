import hashlib
import os
import secrets
from typing import Optional

from fastapi import Depends, Header, HTTPException

from db import db
from models import serialize_document


def hash_password(password: str, salt: Optional[str] = None):
    raw_salt = salt or secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        raw_salt.encode("utf-8"),
        100000,
    ).hex()
    return {"salt": raw_salt, "hash": hashed}


def verify_password(password: str, password_hash: str, password_salt: str):
    computed = hash_password(password, password_salt)
    return secrets.compare_digest(computed["hash"], password_hash)


def create_session_token():
    return secrets.token_urlsafe(32)


def _extract_bearer_token(authorization: Optional[str]):
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip()


def get_current_user(authorization: Optional[str] = Header(default=None)):
    token = _extract_bearer_token(authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Missing authentication token")
    user = db.users.find_one({"session_token": token})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    return serialize_document(user)


def require_user(user=Depends(get_current_user)):
    return user

