import json
import os
import time
import urllib.request
from datetime import datetime, timezone


API_BASE = os.getenv("CYBERAGENT_API_BASE", "http://localhost:8000")
COLLECTOR_TOKEN = os.getenv("CYBERAGENT_COLLECTOR_TOKEN", "paste-project-collector-token")
SOURCE_LABEL = os.getenv("CYBERAGENT_SOURCE_LABEL", "NovaCart demo collector")


def now():
    return datetime.now(timezone.utc).isoformat()


def build_demo_batch():
    return {
        "source_label": SOURCE_LABEL,
        "run_detection": True,
        "events": [
            {
                "event_type": "access",
                "timestamp": now(),
                "src_ip": "198.51.100.24",
                "path": "/admin/login",
                "method": "POST",
                "status_code": 401,
                "bytes_sent": 712,
                "user_agent": "startup-app-client",
                "message": f"{now()} ACCESS src=198.51.100.24 method=POST path=/admin/login status=401 bytes=712 user_agent=startup-app-client",
            },
            {
                "event_type": "auth",
                "timestamp": now(),
                "src_ip": "198.51.100.24",
                "username": "admin",
                "result": "FAILED",
                "port": 22,
                "message": f"{now()} AUTH service=sshd src=198.51.100.24 user=admin result=FAILED port=22",
            },
            {
                "event_type": "network",
                "timestamp": now(),
                "src_ip": "198.51.100.24",
                "dst_ip": "10.0.0.12",
                "port": 22,
                "protocol": "TCP",
                "packets": 120,
                "bytes_sent": 4500,
                "flags": "ACK",
                "message": f"{now()} NETFLOW src=198.51.100.24 dst=10.0.0.12:22 proto=TCP packets=120 bytes=4500 flags=ACK",
            },
        ]
    }


def send_batch(batch):
    body = json.dumps(batch).encode("utf-8")
    request = urllib.request.Request(
        f"{API_BASE}/collector/ingest",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Collector-Token": COLLECTOR_TOKEN,
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


if __name__ == "__main__":
    if COLLECTOR_TOKEN == "paste-project-collector-token":
        raise SystemExit("Set CYBERAGENT_COLLECTOR_TOKEN before running the collector agent.")
    while True:
        print(send_batch(build_demo_batch()))
        time.sleep(5)
