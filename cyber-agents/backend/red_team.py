import random
import uuid
from datetime import datetime, timezone
from pathlib import Path


ATTACK_TYPES = ("DDoS", "BruteForce", "PortScan")
LOG_FILES = {
    "access": "access.log",
    "auth": "auth.log",
    "network": "network.log",
}


def _random_ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_lines(path: Path, lines):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for line in lines:
            handle.write(f"{line}\n")


def _ddos_lines(target_ip: str, target_port: int):
    src_ips = [_random_ip() for _ in range(random.randint(12, 28))]
    request_count = random.randint(24, 40)
    access_lines = []
    network_lines = []
    for _ in range(request_count):
        ip = random.choice(src_ips)
        ts = _now()
        path = random.choice(["/", "/login", "/api/search", "/products"])
        status = random.choice([200, 200, 200, 429, 503])
        access_lines.append(
            f'{ts} ACCESS src={ip} method=GET path={path} status={status} bytes={random.randint(512, 4096)} user_agent=loadbot'
        )
        network_lines.append(
            f"{ts} NETFLOW src={ip} dst={target_ip}:{target_port} proto=TCP packets={random.randint(4000, 12000)} bytes={random.randint(200000, 900000)} flags=SYN"
        )
    return {
        "attack_type": "DDoS",
        "severity": "CRITICAL",
        "src_ips": src_ips,
        "primary_src_ip": src_ips[0],
        "target_ip": target_ip,
        "target_port": target_port,
        "protocol": "TCP",
        "packet_rate": random.randint(8000, 42000),
        "description": "Burst of distributed HTTP requests and SYN-heavy network flow targeting the public service.",
        "raw_logs": {
            "access": access_lines,
            "auth": [],
            "network": network_lines,
        },
    }


def _bruteforce_lines(target_ip: str, target_port: int):
    src_ip = _random_ip()
    auth_lines = []
    network_lines = []
    access_lines = []
    username = random.choice(["admin", "root", "deploy", "support"])
    for _ in range(random.randint(14, 24)):
        ts = _now()
        auth_lines.append(
            f"{ts} AUTH service=sshd src={src_ip} user={username} result=FAILED port={target_port}"
        )
        network_lines.append(
            f"{ts} NETFLOW src={src_ip} dst={target_ip}:{target_port} proto=TCP packets={random.randint(80, 220)} bytes={random.randint(4000, 12000)} flags=ACK"
        )
    access_lines.append(
        f"{_now()} ACCESS src={src_ip} method=POST path=/admin/login status=401 bytes=732 user_agent=credential-checker"
    )
    return {
        "attack_type": "BruteForce",
        "severity": "HIGH",
        "src_ips": [src_ip],
        "primary_src_ip": src_ip,
        "target_ip": target_ip,
        "target_port": target_port,
        "protocol": "TCP",
        "packet_rate": random.randint(120, 480),
        "description": "Repeated authentication failures against an exposed remote access service.",
        "raw_logs": {
            "access": access_lines,
            "auth": auth_lines,
            "network": network_lines,
        },
    }


def _portscan_lines(target_ip: str):
    src_ip = _random_ip()
    ports = list(range(random.randint(1, 64), random.randint(120, 320)))
    ports = ports[: random.randint(18, 36)]
    network_lines = []
    access_lines = []
    for port in ports:
        ts = _now()
        network_lines.append(
            f"{ts} NETFLOW src={src_ip} dst={target_ip}:{port} proto=TCP packets={random.randint(8, 32)} bytes={random.randint(300, 1600)} flags=SYN"
        )
        if port in {80, 443, 8080}:
            access_lines.append(
                f'{ts} ACCESS src={src_ip} method=GET path=/ status={random.choice([404, 400, 301])} bytes={random.randint(128, 700)} user_agent=scan-probe'
            )
    return {
        "attack_type": "PortScan",
        "severity": "MEDIUM",
        "src_ips": [src_ip],
        "primary_src_ip": src_ip,
        "target_ip": target_ip,
        "target_port": ports[0] if ports else 1,
        "protocol": "TCP",
        "packet_rate": random.randint(60, 260),
        "description": "Sequential connection attempts across multiple ports consistent with reconnaissance.",
        "raw_logs": {
            "access": access_lines,
            "auth": [],
            "network": network_lines,
        },
    }


def simulate_attack(log_dir: str):
    attack_id = uuid.uuid4().hex[:8].upper()
    target_ip = _random_ip()
    attack_type = random.choice(ATTACK_TYPES)

    if attack_type == "DDoS":
        scenario = _ddos_lines(target_ip, random.choice([80, 443]))
    elif attack_type == "BruteForce":
        scenario = _bruteforce_lines(target_ip, random.choice([22, 3389, 21]))
    else:
        scenario = _portscan_lines(target_ip)

    runtime_dir = Path(log_dir)
    log_paths = {name: str(runtime_dir / filename) for name, filename in LOG_FILES.items()}
    for name, path_str in log_paths.items():
        _write_lines(Path(path_str), scenario["raw_logs"].get(name, []))

    return {
        "attack_id": attack_id,
        "timestamp": _now(),
        "description": scenario["description"],
        "attack_profile": {
            "attack_type": scenario["attack_type"],
            "severity": scenario["severity"],
            "src_ips": scenario["src_ips"],
            "primary_src_ip": scenario["primary_src_ip"],
            "target_ip": scenario["target_ip"],
            "target_port": scenario["target_port"],
            "protocol": scenario["protocol"],
            "packet_rate": scenario["packet_rate"],
        },
        "telemetry": {
            "log_paths": log_paths,
            "generated_logs": scenario["raw_logs"],
        },
    }
