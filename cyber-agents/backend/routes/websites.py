from pathlib import Path
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from bson import ObjectId

from auth import require_user
from db import db
from models import WebsiteCreateRequest, serialize_document, utc_now


router = APIRouter(prefix="/websites", tags=["websites"])


def _website_query(user_id: str, website_id: str):
    try:
        return {"_id": ObjectId(website_id), "user_id": user_id}
    except Exception as exc:
        raise HTTPException(status_code=404, detail="Website not found") from exc


def _runtime_log_paths(website_id: str):
    runtime_dir = Path(__file__).resolve().parent.parent / "runtime_logs" / website_id
    runtime_dir.mkdir(parents=True, exist_ok=True)
    return {
        "access": str(runtime_dir / "access.log"),
        "auth": str(runtime_dir / "auth.log"),
        "network": str(runtime_dir / "network.log"),
    }


def _collector_config():
    return {
        "status": "active",
        "ingest_token": secrets.token_urlsafe(24),
        "heartbeat_interval_seconds": 15,
        "mode": "agent",
    }


@router.get("")
async def list_websites(user=Depends(require_user)):
    websites = [serialize_document(document) for document in db.websites.find({"user_id": user["_id"]}).sort("created_at", 1)]
    return websites


@router.post("")
async def create_website(payload: WebsiteCreateRequest, user=Depends(require_user)):
    website = {
        "user_id": user["_id"],
        "name": payload.name.strip(),
        "domain": payload.domain.strip(),
        "environment": payload.environment.strip(),
        "connection_type": "demo" if payload.use_demo else "manual",
        "status": "connected" if payload.use_demo else "pending",
        "dummy_site_enabled": payload.use_demo,
        "log_sources": {
            "web_server": payload.web_server,
            "access_log_path": payload.access_log_path,
            "auth_log_path": payload.auth_log_path,
            "network_log_path": payload.network_log_path,
        },
        "collector": _collector_config(),
        "demo_site": {
            "name": "NovaCart",
            "theme": "startup-commerce",
            "enabled": True,
        },
        "telemetry_stats": {
            "events_ingested": 0,
            "last_event_at": None,
            "sources_seen": [],
        },
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }
    insert_result = db.websites.insert_one(website)
    created = db.websites.find_one({"_id": insert_result.inserted_id})
    if payload.use_demo:
        runtime_paths = _runtime_log_paths(str(insert_result.inserted_id))
        db.websites.update_one(
            {"_id": insert_result.inserted_id},
            {
                "$set": {
                    "status": "connected",
                    "dummy_site": {
                        "enabled": True,
                        "runtime_log_paths": runtime_paths,
                    },
                    "updated_at": utc_now(),
                }
            },
        )
        created = db.websites.find_one({"_id": insert_result.inserted_id})
    return serialize_document(created)


@router.get("/{website_id}")
async def get_website(website_id: str, user=Depends(require_user)):
    website = db.websites.find_one(_website_query(user["_id"], website_id))
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")
    return serialize_document(website)


@router.get("/{website_id}/integration")
async def get_website_integration(website_id: str, request: Request, user=Depends(require_user)):
    website = db.websites.find_one(_website_query(user["_id"], website_id))
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")

    serialized = serialize_document(website)
    origin = str(request.base_url).rstrip("/")
    token = serialized.get("collector", {}).get("ingest_token", "")
    example_payload = {
        "source_label": f"{serialized['name']} web collector",
        "run_detection": True,
        "events": [
            {
                "event_type": "access",
                "timestamp": utc_now().isoformat(),
                "src_ip": "198.51.100.24",
                "path": "/admin/login",
                "method": "POST",
                "status_code": 401,
                "bytes_sent": 712,
                "user_agent": "startup-app-client",
                "message": "Access event from the customer website",
            },
            {
                "event_type": "auth",
                "timestamp": utc_now().isoformat(),
                "src_ip": "198.51.100.24",
                "username": "admin",
                "result": "FAILED",
                "port": 22,
                "message": "Authentication failure from the customer website",
            },
        ],
    }
    return {
        "website_id": serialized["_id"],
        "website_name": serialized["name"],
        "ingest_url": f"{origin}/collector/ingest",
        "token_header": "X-Collector-Token",
        "collector_token": token,
        "protocols": {
            "primary_runtime": "mcp_tools",
            "mcp_endpoint": f"{origin}/mcp",
            "mcp_tools_url": f"{origin}/mcp/tools",
            "observability_url": f"{origin}/websites/{serialized['_id']}/observability",
            "runtime": "mcp_tools_plus_openrouter",
            "opentelemetry": {
                "enabled": True,
                "collection_mode": "custom_security_events_plus_opentelemetry",
                "heartbeat_interval_seconds": 8,
            },
        },
        "sample_payload": example_payload,
        "curl_example": (
            f"curl -X POST {origin}/collector/ingest "
            f"-H 'Content-Type: application/json' "
            f"-H 'X-Collector-Token: {token}' "
            f"-d '<payload-json>'"
        ),
        "python_collector_path": "backend/collector_agent.py",
    }


@router.post("/{website_id}/connect-demo")
async def connect_demo_site(website_id: str, user=Depends(require_user)):
    query = _website_query(user["_id"], website_id)
    website = db.websites.find_one(query)
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")

    runtime_paths = _runtime_log_paths(website_id)
    db.websites.update_one(
        query,
        {
            "$set": {
                "connection_type": "demo",
                "status": "connected",
                "dummy_site_enabled": True,
                "dummy_site": {
                    "enabled": True,
                    "runtime_log_paths": runtime_paths,
                },
                "updated_at": utc_now(),
            }
        },
    )
    updated = db.websites.find_one(query)
    return serialize_document(updated)
