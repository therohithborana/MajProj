import re
from datetime import datetime, timezone


COMBINED_LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: HTTP/[^"]+)?" '
    r'(?P<status>\d{3}) (?P<bytes>\S+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)

KEY_VALUE_ACCESS_RE = re.compile(
    r"^(?P<timestamp>\S+) ACCESS .*?src=(?P<ip>\S+) .*?method=(?P<method>\S+) "
    r".*?path=(?P<path>\S+) .*?status=(?P<status>\d{3}).*?(?:user_agent=(?P<user_agent>.+))?$"
)


def _parse_nginx_timestamp(value: str):
    try:
        parsed = datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")
        return parsed.astimezone(timezone.utc).isoformat()
    except ValueError:
        return value


def _to_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_access_log(line: str):
    raw = line.strip()
    if not raw:
        raise ValueError("Empty log line")

    key_value_match = KEY_VALUE_ACCESS_RE.match(raw)
    if key_value_match:
        data = key_value_match.groupdict()
        return {
            "source_type": "access",
            "ip": data["ip"],
            "timestamp": data["timestamp"],
            "method": data["method"],
            "path": data["path"],
            "status": _to_int(data["status"]),
            "user_agent": (data.get("user_agent") or "").strip(),
            "raw_line": raw,
            "parser": "cyberagent_access",
        }

    combined_match = COMBINED_LOG_RE.match(raw)
    if not combined_match:
        raise ValueError("Unsupported access log format")

    data = combined_match.groupdict()
    return {
        "source_type": "access",
        "ip": data["ip"],
        "timestamp": _parse_nginx_timestamp(data["timestamp"]),
        "method": data["method"],
        "path": data["path"],
        "status": _to_int(data["status"]),
        "bytes": _to_int(data["bytes"]),
        "referer": data.get("referer") or "",
        "user_agent": data.get("user_agent") or "",
        "raw_line": raw,
        "parser": "nginx_apache_combined",
    }
