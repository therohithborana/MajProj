import hashlib
from datetime import datetime, timezone


def _now():
    return datetime.now(timezone.utc).isoformat()


def _event_hash(website_id: str, raw_line: str, timestamp: str, source_type: str):
    material = f"{website_id}|{source_type}|{timestamp}|{raw_line}".encode("utf-8", errors="ignore")
    return hashlib.sha256(material).hexdigest()


def normalize_event(parsed: dict, website_id: str, source_type: str = "access"):
    timestamp = parsed.get("timestamp") or _now()
    raw_line = parsed.get("raw_line") or ""
    event_source = parsed.get("source_type") or source_type or "access"
    normalized = {
        "website_id": website_id,
        "source_type": event_source,
        "event_type": "http_request" if event_source == "access" else event_source,
        "timestamp": timestamp,
        "received_at": datetime.now(timezone.utc),
        "ip": parsed.get("ip") or "unknown",
        "method": parsed.get("method") or "GET",
        "path": parsed.get("path") or "/",
        "status": int(parsed.get("status") or 0),
        "user_agent": parsed.get("user_agent") or "",
        "bytes": int(parsed.get("bytes") or 0),
        "raw_line": raw_line,
        "parser": parsed.get("parser") or "unknown",
        "attributes": parsed.get("attributes") or {},
    }
    normalized["event_hash"] = _event_hash(website_id, raw_line, str(timestamp), event_source)
    return normalized


def event_to_access_line(event: dict):
    user_agent = (event.get("user_agent") or "-").replace(" ", "_")
    return (
        f"{event.get('timestamp')} ACCESS src={event.get('ip', 'unknown')} "
        f"method={event.get('method', 'GET')} path={event.get('path', '/')} "
        f"status={event.get('status', 0)} bytes={event.get('bytes', 0)} user_agent={user_agent}"
    )


def event_to_auth_line(event: dict):
    if event.get("status") not in {401, 403}:
        return None
    path = str(event.get("path") or "")
    if not any(marker in path.lower() for marker in ("login", "auth", "admin")):
        return None
    return (
        f"{event.get('timestamp')} AUTH service=http src={event.get('ip', 'unknown')} "
        f"user=unknown result=FAILED port=80"
    )
