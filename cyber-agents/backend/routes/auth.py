from fastapi import APIRouter, Depends, HTTPException

from auth import require_user
from auth import create_session_token, hash_password, verify_password
from db import db
from models import LoginRequest, SignupRequest, serialize_document, utc_now


router = APIRouter(prefix="/auth", tags=["auth"])


def _public_user(user):
    safe = serialize_document(user)
    safe.pop("password_hash", None)
    safe.pop("password_salt", None)
    safe.pop("session_token", None)
    return safe


@router.post("/signup")
async def signup(payload: SignupRequest):
    existing = db.users.find_one({"email": payload.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    password_data = hash_password(payload.password)
    token = create_session_token()
    user = {
        "name": payload.name.strip(),
        "email": payload.email.lower(),
        "password_hash": password_data["hash"],
        "password_salt": password_data["salt"],
        "session_token": token,
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }
    insert_result = db.users.insert_one(user)
    created_user = db.users.find_one({"_id": insert_result.inserted_id})
    return {"token": token, "user": _public_user(created_user)}


@router.post("/login")
async def login(payload: LoginRequest):
    user = db.users.find_one({"email": payload.email.lower()})
    if not user or not verify_password(payload.password, user["password_hash"], user["password_salt"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_session_token()
    db.users.update_one(
        {"_id": user["_id"]},
        {"$set": {"session_token": token, "updated_at": utc_now()}},
    )
    refreshed = db.users.find_one({"_id": user["_id"]})
    return {"token": token, "user": _public_user(refreshed)}


@router.get("/me")
async def me(user=Depends(require_user)):
    return {"user": _public_user(user)}
