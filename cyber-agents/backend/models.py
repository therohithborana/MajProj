from datetime import datetime, timezone
from typing import Literal, Optional

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
    if isinstance(document, datetime):
        return document.isoformat()
    serialized = {}
    for key, value in document.items():
        if isinstance(value, ObjectId):
            serialized[key] = str(value)
        elif isinstance(value, datetime):
            serialized[key] = value.isoformat()
        elif isinstance(value, dict):
            serialized[key] = serialize_document(value)
        elif isinstance(value, list):
            serialized[key] = [
                serialize_document(item)
                if isinstance(item, dict)
                else item.isoformat()
                if isinstance(item, datetime)
                else object_id_str(item)
                for item in value
            ]
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


class IncidentNoteRequest(BaseModel):
    note: str = Field(min_length=2, max_length=4000)


class IncidentAssignRequest(BaseModel):
    assignee: str = Field(min_length=2, max_length=120)


class IngestEvent(BaseModel):
    event_type: Literal["access", "auth", "network"]
    timestamp: Optional[datetime] = None
    message: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status_code: Optional[int] = None
    username: Optional[str] = None
    result: Optional[str] = None
    bytes_sent: Optional[int] = None
    packets: Optional[int] = None
    flags: Optional[str] = None
    user_agent: Optional[str] = None
    metadata: dict = Field(default_factory=dict)


class CollectorIngestRequest(BaseModel):
    attack_id: Optional[str] = Field(default=None, max_length=64)
    source_label: Optional[str] = Field(default=None, max_length=120)
    run_detection: bool = False
    events: list[IngestEvent] = Field(min_length=1, max_length=500)

