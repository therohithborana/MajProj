import random
import uuid
from datetime import datetime, timezone


ATTACK_TYPES = ("DDoS", "BruteForce", "PortScan", "SuspiciousRecon")


def _random_ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _now():
    return datetime.now(timezone.utc)


def _iso(ts):
    return ts.isoformat()


def _access_event(ts, src_ip, path, status_code, user_agent, method="GET", bytes_sent=None, attack_id=None):
    return {
        "event_type": "access",
        "timestamp": _iso(ts),
        "src_ip": src_ip,
        "path": path,
        "method": method,
        "status_code": status_code,
        "bytes_sent": bytes_sent if bytes_sent is not None else random.randint(200, 4096),
        "user_agent": user_agent,
        "message": (
            f"{_iso(ts)} ACCESS src={src_ip} method={method} path={path} "
            f"status={status_code} bytes={bytes_sent if bytes_sent is not None else random.randint(200, 4096)} "
            f"user_agent={user_agent}"
        ),
        "metadata": {"attack_id": attack_id} if attack_id else {},
    }


def _auth_event(ts, src_ip, username, result, port, attack_id=None):
    return {
        "event_type": "auth",
        "timestamp": _iso(ts),
        "src_ip": src_ip,
        "username": username,
        "result": result,
        "port": port,
        "message": f"{_iso(ts)} AUTH service=sshd src={src_ip} user={username} result={result} port={port}",
        "metadata": {"attack_id": attack_id} if attack_id else {},
    }


def _network_event(ts, src_ip, dst_ip, port, packets, bytes_sent, flags, attack_id=None):
    return {
        "event_type": "network",
        "timestamp": _iso(ts),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "port": port,
        "protocol": "TCP",
        "packets": packets,
        "bytes_sent": bytes_sent,
        "flags": flags,
        "message": (
            f"{_iso(ts)} NETFLOW src={src_ip} dst={dst_ip}:{port} proto=TCP "
            f"packets={packets} bytes={bytes_sent} flags={flags}"
        ),
        "metadata": {"attack_id": attack_id} if attack_id else {},
    }


def _ddos_events(attack_id, target_ip, target_port):
    src_ips = [_random_ip() for _ in range(random.randint(12, 24))]
    events = []
    for _ in range(random.randint(28, 42)):
        ts = _now()
        ip = random.choice(src_ips)
        path = random.choice(["/", "/login", "/api/search", "/products", "/checkout"])
        status = random.choice([200, 200, 200, 429, 503])
        bytes_sent = random.randint(512, 4096)
        packets = random.randint(4000, 12000)
        flow_bytes = random.randint(200000, 900000)
        events.append(_access_event(ts, ip, path, status, "loadbot", bytes_sent=bytes_sent, attack_id=attack_id))
        events.append(_network_event(ts, ip, target_ip, target_port, packets, flow_bytes, "SYN", attack_id=attack_id))
    return {
        "attack_type": "DDoS",
        "severity": "CRITICAL",
        "primary_src_ip": src_ips[0],
        "src_ips": src_ips,
        "target_ip": target_ip,
        "target_port": target_port,
        "events": events,
        "description": "Distributed HTTP flood and SYN-heavy network burst targeting the public service.",
    }


def _bruteforce_events(attack_id, target_ip, target_port):
    src_ip = _random_ip()
    username = random.choice(["admin", "root", "deploy", "support"])
    events = []
    for _ in range(random.randint(14, 24)):
        ts = _now()
        events.append(_auth_event(ts, src_ip, username, "FAILED", target_port, attack_id=attack_id))
        events.append(
            _network_event(
                ts,
                src_ip,
                target_ip,
                target_port,
                random.randint(80, 220),
                random.randint(4000, 12000),
                "ACK",
                attack_id=attack_id,
            )
        )
    events.append(
        _access_event(_now(), src_ip, "/admin/login", 401, "credential-checker", method="POST", bytes_sent=732, attack_id=attack_id)
    )
    return {
        "attack_type": "BruteForce",
        "severity": "HIGH",
        "primary_src_ip": src_ip,
        "src_ips": [src_ip],
        "target_ip": target_ip,
        "target_port": target_port,
        "events": events,
        "description": "Repeated authentication failures against an exposed remote access service.",
    }


def _portscan_events(attack_id, target_ip):
    src_ip = _random_ip()
    ports = list(range(random.randint(24, 64), random.randint(120, 280)))
    ports = ports[: random.randint(18, 34)]
    events = []
    for port in ports:
        ts = _now()
        events.append(
            _network_event(
                ts,
                src_ip,
                target_ip,
                port,
                random.randint(8, 32),
                random.randint(300, 1600),
                "SYN",
                attack_id=attack_id,
            )
        )
        if port in {80, 443, 8080}:
            events.append(_access_event(ts, src_ip, "/", random.choice([400, 404, 301]), "scan-probe", attack_id=attack_id))
    return {
        "attack_type": "PortScan",
        "severity": "MEDIUM",
        "primary_src_ip": src_ip,
        "src_ips": [src_ip],
        "target_ip": target_ip,
        "target_port": ports[0] if ports else 80,
        "events": events,
        "description": "Sequential connection attempts across multiple ports consistent with reconnaissance.",
    }


def _recon_events(attack_id, target_ip):
    src_ip = _random_ip()
    paths = [
        "/admin",
        "/admin/login",
        "/.env",
        "/config.php",
        "/phpmyadmin",
        "/wp-admin",
        "/backup.zip",
        "/server-status",
    ]
    events = []
    for path in paths + random.sample(paths, k=4):
        ts = _now()
        status = random.choice([403, 404, 401])
        events.append(_access_event(ts, src_ip, path, status, "recon-bot", attack_id=attack_id))
        events.append(
            _network_event(
                ts,
                src_ip,
                target_ip,
                random.choice([80, 443]),
                random.randint(10, 28),
                random.randint(500, 2400),
                "SYN",
                attack_id=attack_id,
            )
        )
    return {
        "attack_type": "SuspiciousRecon",
        "severity": "MEDIUM",
        "primary_src_ip": src_ip,
        "src_ips": [src_ip],
        "target_ip": target_ip,
        "target_port": 443,
        "events": events,
        "description": "Repeated probes for sensitive paths and administrative entry points.",
    }


def simulate_attack():
    attack_id = uuid.uuid4().hex[:8].upper()
    target_ip = _random_ip()
    attack_type = random.choice(ATTACK_TYPES)

    if attack_type == "DDoS":
        scenario = _ddos_events(attack_id, target_ip, random.choice([80, 443]))
    elif attack_type == "BruteForce":
        scenario = _bruteforce_events(attack_id, target_ip, random.choice([22, 3389, 21]))
    elif attack_type == "PortScan":
        scenario = _portscan_events(attack_id, target_ip)
    else:
        scenario = _recon_events(attack_id, target_ip)

    return {
        "attack_id": attack_id,
        "timestamp": _iso(_now()),
        "description": scenario["description"],
        "attack_profile": {
            "attack_type": scenario["attack_type"],
            "severity": scenario["severity"],
            "src_ips": scenario["src_ips"],
            "primary_src_ip": scenario["primary_src_ip"],
            "target_ip": scenario["target_ip"],
            "target_port": scenario["target_port"],
            "protocol": "TCP",
        },
        "events": scenario["events"],
    }
