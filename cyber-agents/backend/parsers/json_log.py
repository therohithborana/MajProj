import json
from datetime import datetime, timezone


def _first_present(payload: dict, keys, default=None):
    for key in keys:
        if key in payload and payload[key] not in (None, ""):
            return payload[key]
    return default


def parse_json_log(line: str):
    raw = line.strip()
    if not raw:
        raise ValueError("Empty JSON log line")

    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("JSON log line must be an object")

    status = _first_present(payload, ["status", "status_code", "response_status"], 0)
    try:
        status = int(status)
    except (TypeError, ValueError):
        status = 0

    return {
        "source_type": _first_present(payload, ["source_type", "type"], "access"),
        "ip": _first_present(payload, ["ip", "src", "source_ip", "remote_addr", "client_ip"], "unknown"),
        "timestamp": _first_present(payload, ["timestamp", "time", "ts"], datetime.now(timezone.utc).isoformat()),
        "method": str(_first_present(payload, ["method", "http_method"], "GET")).upper(),
        "path": _first_present(payload, ["endpoint", "path", "url", "request_uri"], "/"),
        "status": status,
        "user_agent": _first_present(payload, ["user_agent", "ua", "http_user_agent"], ""),
        "raw_line": raw,
        "parser": "json",
        "attributes": payload,
    }
