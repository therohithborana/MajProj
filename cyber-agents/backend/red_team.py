import random
import uuid
from datetime import datetime, timezone


ATTACK_TYPES = ("DDoS", "BruteForce", "PortScan")
PROTOCOLS = ("TCP", "UDP")


def _random_ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _base_features(packet_rate: int, src_count: int):
    features = {
        "flow_duration": round(random.uniform(10.0, 5000.0), 3),
        "total_fwd_packets": random.randint(200, 20000),
        "total_bwd_packets": random.randint(10, 5000),
        "fwd_packet_length_mean": round(random.uniform(40.0, 1500.0), 3),
        "bwd_packet_length_mean": round(random.uniform(40.0, 1500.0), 3),
        "flow_bytes_per_sec": round(random.uniform(1024.0, 1000000.0), 3),
        "flow_packets_per_sec": round(random.uniform(50.0, float(packet_rate)), 3),
        "syn_flag_count": random.randint(0, max(1, src_count * 12)),
        "rst_flag_count": random.randint(0, max(1, src_count * 4)),
        "psh_flag_count": random.randint(0, max(1, src_count * 6)),
        "ack_flag_count": random.randint(src_count, max(src_count + 1, src_count * 40)),
        "avg_packet_size": round(random.uniform(64.0, 1400.0), 3),
        "idle_mean": round(random.uniform(0.1, 50.0), 3),
    }
    for i in range(12, 81):
        features[f"feature_{i}"] = round(random.uniform(0.01, 9999.99), 4)
    return features


def generate_attack():
    attack_type = random.choice(ATTACK_TYPES)
    attack_id = uuid.uuid4().hex[:8].upper()
    timestamp = datetime.now(timezone.utc).isoformat()
    target_ip = _random_ip()

    if attack_type == "DDoS":
        src_ips = [_random_ip() for _ in range(random.randint(10, 50))]
        target_port = random.choice([80, 443])
        packet_rate = random.randint(5000, 50000)
        severity = "CRITICAL"
        protocol = random.choice(PROTOCOLS)
        description = "Distributed traffic flood intended to exhaust edge capacity and overwhelm the exposed service."
        raw_log = (
            f"{timestamp} ALERT ddos_detected target={target_ip}:{target_port} "
            f"sources={len(src_ips)} rate={packet_rate}/s proto={protocol}"
        )
    elif attack_type == "BruteForce":
        src_ips = [_random_ip()]
        target_port = random.choice([22, 3389, 21])
        packet_rate = random.randint(100, 500)
        severity = "HIGH"
        protocol = "TCP"
        description = "Repeated authentication attempts observed against a remote access service."
        raw_log = (
            f"{timestamp} ALERT brute_force source={src_ips[0]} target={target_ip}:{target_port} "
            f"attempt_rate={packet_rate}/s"
        )
    else:
        src_ips = [_random_ip()]
        target_port = random.randint(1, 1024)
        packet_rate = random.randint(50, 300)
        severity = "MEDIUM"
        protocol = "TCP"
        description = "Sequential reconnaissance traffic consistent with a wide port scan."
        raw_log = (
            f"{timestamp} ALERT port_scan source={src_ips[0]} target={target_ip} "
            f"ports=1-1024 sample_port={target_port} rate={packet_rate}/s"
        )

    attack = {
        "attack_id": attack_id,
        "timestamp": timestamp,
        "attack_type": attack_type,
        "severity": severity,
        "src_ips": src_ips,
        "primary_src_ip": src_ips[0],
        "target_ip": target_ip,
        "target_port": target_port,
        "protocol": protocol,
        "packet_rate": packet_rate,
        "description": description,
        "raw_log": raw_log,
        "features": _base_features(packet_rate, len(src_ips)),
    }
    return attack
