from datetime import datetime, timezone
from typing import Optional

from bson import ObjectId
from pydantic import BaseModel, EmailStr, Field


def utc_now():
    return datetime.now(timezone.utc)


def object_id_str(value):
    if isinstance(value, ObjectId):
        return str(value)
    return value


def serialize_document(document):
    if not document:
        return None
    serialized = {}
    for key, value in document.items():
        if isinstance(value, ObjectId):
            serialized[key] = str(value)
        elif isinstance(value, dict):
            serialized[key] = serialize_document(value)
        elif isinstance(value, list):
            serialized[key] = [serialize_document(item) if isinstance(item, dict) else object_id_str(item) for item in value]
        else:
            serialized[key] = value
    return serialized


class SignupRequest(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class WebsiteCreateRequest(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    domain: str = Field(min_length=3, max_length=255)
    environment: str = Field(min_length=2, max_length=64, default="development")
    use_demo: bool = True
    web_server: str = Field(default="nginx")
    access_log_path: Optional[str] = None
    auth_log_path: Optional[str] = None
    network_log_path: Optional[str] = None


class ApprovalRequest(BaseModel):
    decision: str

