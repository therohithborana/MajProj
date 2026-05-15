import argparse
import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ml_model import infer


def _ts(seconds: int) -> str:
    base = datetime.now(timezone.utc).replace(microsecond=0)
    return (base + timedelta(seconds=seconds)).isoformat()


def _base_context() -> dict:
    return {
        "telemetry": {
            "events": [],
            "events_by_type": {
                "access": [],
                "auth": [],
                "network": [],
            },
            "total_events_observed": 0,
        },
        "anomaly": {
            "failed_auth_attempts": 0,
            "port_span": 0,
            "suspicious_path_hits": 0,
            "request_burst": 0,
            "src_ips": [],
            "primary_src_ip": None,
            "target_ip": None,
            "target_port": None,
        },
    }


def _finalize(context: dict) -> dict:
    events_by_type = context["telemetry"]["events_by_type"]
    events = events_by_type["access"] + events_by_type["auth"] + events_by_type["network"]
    context["telemetry"]["events"] = events
    context["telemetry"]["total_events_observed"] = len(events)
    return context


def build_bruteforce_context() -> dict:
    context = _base_context()
    src_ip = "203.0.113.44"
    target_ip = "10.0.4.12"
    auth_events = []
    for idx in range(12):
        auth_events.append(
            {
                "event_type": "auth",
                "timestamp": _ts(idx),
                "src_ip": src_ip,
                "dst_ip": target_ip,
                "port": 22,
                "protocol": "tcp",
                "username": "admin",
                "result": "FAILED",
                "message": f"SSH login failed for admin from {src_ip}",
                "packets": 3,
                "bytes_sent": 240,
                "flags": "syn",
                "metadata": {},
            }
        )
    context["telemetry"]["events_by_type"]["auth"] = auth_events
    context["anomaly"].update(
        {
            "failed_auth_attempts": 12,
            "request_burst": 5,
            "src_ips": [src_ip],
            "primary_src_ip": src_ip,
            "target_ip": target_ip,
            "target_port": 22,
        }
    )
    return _finalize(context)


def build_portscan_context() -> dict:
    context = _base_context()
    src_ip = "198.51.100.22"
    target_ip = "10.0.6.9"
    network_events = []
    ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]
    for idx, port in enumerate(ports):
        network_events.append(
            {
                "event_type": "network",
                "timestamp": _ts(idx),
                "src_ip": src_ip,
                "dst_ip": target_ip,
                "port": port,
                "protocol": "tcp",
                "packets": 2,
                "bytes_sent": 120,
                "flags": "syn",
                "message": f"SYN probe to {target_ip}:{port}",
                "metadata": {},
            }
        )
    context["telemetry"]["events_by_type"]["network"] = network_events
    context["anomaly"].update(
        {
            "port_span": len(ports),
            "request_burst": 7,
            "src_ips": [src_ip],
            "primary_src_ip": src_ip,
            "target_ip": target_ip,
            "target_port": 443,
        }
    )
    return _finalize(context)


def build_recon_context() -> dict:
    context = _base_context()
    src_ip = "192.0.2.17"
    target_ip = "10.0.8.14"
    paths = [
        "/admin",
        "/.env",
        "/wp-admin",
        "/phpmyadmin",
        "/backup.zip",
        "/server-status",
    ]
    access_events = []
    for idx, path in enumerate(paths):
        access_events.append(
            {
                "event_type": "access",
                "timestamp": _ts(idx),
                "src_ip": src_ip,
                "dst_ip": target_ip,
                "port": 443,
                "protocol": "tcp",
                "method": "GET",
                "path": path,
                "status_code": 404,
                "message": f"GET {path} returned 404",
                "bytes_sent": 512,
                "packets": 4,
                "metadata": {"user_agent": "curl/8.0"},
            }
        )
    context["telemetry"]["events_by_type"]["access"] = access_events
    context["anomaly"].update(
        {
            "suspicious_path_hits": len(paths),
            "request_burst": 9,
            "src_ips": [src_ip],
            "primary_src_ip": src_ip,
            "target_ip": target_ip,
            "target_port": 443,
        }
    )
    return _finalize(context)


def build_ddos_context() -> dict:
    context = _base_context()
    target_ip = "10.0.10.5"
    source_ips = [f"198.18.0.{idx}" for idx in range(1, 15)]
    network_events = []
    for idx, src_ip in enumerate(source_ips):
        network_events.append(
            {
                "event_type": "network",
                "timestamp": _ts(idx),
                "src_ip": src_ip,
                "dst_ip": target_ip,
                "port": 80,
                "protocol": "tcp",
                "packets": 180 + idx * 3,
                "bytes_sent": 24_000 + idx * 800,
                "flags": "syn",
                "message": f"SYN-heavy ingress burst from {src_ip}",
                "metadata": {},
            }
        )
    context["telemetry"]["events_by_type"]["network"] = network_events
    context["anomaly"].update(
        {
            "request_burst": 36,
            "src_ips": source_ips,
            "primary_src_ip": source_ips[0],
            "target_ip": target_ip,
            "target_port": 80,
        }
    )
    return _finalize(context)


SCENARIO_BUILDERS = {
    "bruteforce": build_bruteforce_context,
    "portscan": build_portscan_context,
    "recon": build_recon_context,
    "ddos": build_ddos_context,
}


def main():
    parser = argparse.ArgumentParser(description="Exercise the pretrained CyberAgent ML classifier directly.")
    parser.add_argument(
        "--scenario",
        choices=sorted(SCENARIO_BUILDERS.keys()),
        default="bruteforce",
        help="Built-in scenario to run.",
    )
    parser.add_argument(
        "--input",
        type=Path,
        help="Optional path to a JSON file with a full infer(context) payload. Overrides --scenario.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print the result as formatted JSON.",
    )
    args = parser.parse_args()

    if args.input:
        context = json.loads(args.input.read_text())
    else:
        context = SCENARIO_BUILDERS[args.scenario]()

    result = infer(deepcopy(context))
    output = {
        "scenario": args.scenario if not args.input else str(args.input),
        "context_summary": {
            "total_events": context["telemetry"]["total_events_observed"],
            "access_events": len(context["telemetry"]["events_by_type"]["access"]),
            "auth_events": len(context["telemetry"]["events_by_type"]["auth"]),
            "network_events": len(context["telemetry"]["events_by_type"]["network"]),
            "anomaly": context["anomaly"],
        },
        "ml_result": result,
    }
    if args.pretty:
        print(json.dumps(output, indent=2))
    else:
        print(json.dumps(output))


if __name__ == "__main__":
    main()
