from __future__ import annotations

import math
from collections import Counter
from functools import lru_cache
from pathlib import Path

import joblib
import pandas as pd
import xgboost as xgb
from huggingface_hub import hf_hub_download


MODEL_DIR = Path(__file__).resolve().parent / "runtime_models"
CLASS_LABELS = ["DDoS", "BruteForce", "PortScan", "SuspiciousRecon"]
WAF_REPO = "netgoat-ai/koda-waf"
NIDS_REPO = "netgoat-ai/koda-nids"
SAFE_SERVICE_FALLBACK = "-"
SAFE_STATE_FALLBACK = "con"
SAFE_PROTO_FALLBACK = "tcp"
SQL_TOKENS = ("select", "union", "sleep(", "information_schema", "drop", "insert", "update", "--", " or ")
XSS_TOKENS = ("<script", "javascript:", "onerror=", "onload=", "alert(", "<img", "<svg")
FILE_TOKENS = ("../", "..\\", "/etc/passwd", "win.ini", ".env", "wp-admin", "phpmyadmin", "config", "backup")


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return round(-sum((count / total) * math.log2(count / total) for count in counts.values()), 4)


def _spec_char_count(text: str) -> int:
    return sum(1 for char in text if not char.isalnum() and not char.isspace())


def _digit_ratio(text: str) -> float:
    if not text:
        return 0.0
    return round(sum(1 for char in text if char.isdigit()) / max(len(text), 1), 4)


def _token_count(text: str, tokens: tuple[str, ...]) -> int:
    lowered = (text or "").lower()
    return sum(lowered.count(token) for token in tokens)


def _service_from_port(port: int | None) -> str:
    return {
        21: "ftp",
        22: "ssh",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        1812: "radius",
        161: "snmp",
        443: "ssl",
        6667: "irc",
    }.get(int(port or 0), SAFE_SERVICE_FALLBACK)


def _state_from_events(auth_events: list[dict], network_events: list[dict]) -> str:
    if any((event.get("flags") or "").lower() == "rst" for event in network_events):
        return "rst"
    if any((event.get("flags") or "").lower() == "fin" for event in network_events):
        return "fin"
    if any(str(event.get("result", "")).upper() == "FAILED" for event in auth_events):
        return "req"
    return SAFE_STATE_FALLBACK


def _safe_transform(encoder, value: str, fallback: str):
    normalized = (value or fallback).strip().lower()
    classes = set(getattr(encoder, "classes_", []))
    candidate = normalized if normalized in classes else fallback
    return int(encoder.transform([candidate])[0])


@lru_cache(maxsize=1)
def _load_waf_assets():
    model_path = hf_hub_download(repo_id=WAF_REPO, filename="smart_waf_model.pkl", repo_type="model")
    cols_path = hf_hub_download(repo_id=WAF_REPO, filename="model_features.pkl", repo_type="model")
    return joblib.load(model_path), list(joblib.load(cols_path))


@lru_cache(maxsize=1)
def _load_nids_assets():
    model_path = hf_hub_download(repo_id=NIDS_REPO, filename="xgb_intrusion_model.json", repo_type="model")
    enc_path = hf_hub_download(repo_id=NIDS_REPO, filename="label_encoders.pkl", repo_type="model")
    model = xgb.XGBClassifier()
    model.load_model(model_path)
    return model, joblib.load(enc_path)


def _build_waf_features(access_events: list[dict]) -> dict:
    latest = access_events[-1] if access_events else {}
    path = latest.get("path") or ""
    body = str((latest.get("metadata") or {}).get("body") or latest.get("message") or "")
    user_agent = str((latest.get("metadata") or {}).get("user_agent") or latest.get("user_agent") or "")
    return {
        "path_len": len(path),
        "path_entropy": _shannon_entropy(path),
        "path_spec_chars": _spec_char_count(path),
        "path_digit_ratio": _digit_ratio(path),
        "path_cnt_sql": _token_count(path, SQL_TOKENS),
        "path_cnt_xss": _token_count(path, XSS_TOKENS),
        "path_cnt_file": _token_count(path, FILE_TOKENS),
        "body_len": len(body),
        "body_entropy": _shannon_entropy(body),
        "body_spec_chars": _spec_char_count(body),
        "body_digit_ratio": _digit_ratio(body),
        "body_cnt_sql": _token_count(body, SQL_TOKENS),
        "body_cnt_xss": _token_count(body, XSS_TOKENS),
        "body_cnt_file": _token_count(body, FILE_TOKENS),
        "ua_entropy": _shannon_entropy(user_agent),
        "ua_spec_chars": _spec_char_count(user_agent),
        "ua_digit_ratio": _digit_ratio(user_agent),
        "ua_cnt_sql": _token_count(user_agent, SQL_TOKENS),
        "ua_cnt_xss": _token_count(user_agent, XSS_TOKENS),
        "ua_cnt_file": _token_count(user_agent, FILE_TOKENS),
        "is_post": 1 if str(latest.get("method") or "").upper() == "POST" else 0,
    }


def _build_nids_features(telemetry: dict, anomaly: dict) -> dict:
    events = telemetry.get("events") or []
    auth_events = telemetry.get("events_by_type", {}).get("auth", [])
    network_events = telemetry.get("events_by_type", {}).get("network", [])
    ports = [int(event.get("port") or 0) for event in network_events if event.get("port") is not None]
    pkts = [int(event.get("packets") or 0) for event in network_events]
    bytes_sent = [int(event.get("bytes_sent") or 0) for event in events]
    src_counts = Counter(event.get("src_ip") for event in events if event.get("src_ip"))
    dst_counts = Counter(event.get("dst_ip") for event in events if event.get("dst_ip"))
    primary_port = ports[0] if ports else anomaly.get("target_port") or 80
    predominant_proto = str(
        max(
            (str(event.get("protocol") or SAFE_PROTO_FALLBACK).lower() for event in network_events),
            key=lambda proto: sum(1 for event in network_events if str(event.get("protocol") or SAFE_PROTO_FALLBACK).lower() == proto),
            default=SAFE_PROTO_FALLBACK,
        )
    )

    timestamps = [event.get("timestamp") for event in events if event.get("timestamp")]
    duration = max(len(events) - 1, 1)
    if timestamps:
        try:
            start = pd.to_datetime(min(timestamps))
            end = pd.to_datetime(max(timestamps))
            duration = max((end - start).total_seconds(), 1.0)
        except Exception:
            duration = max(len(events) - 1, 1)

    total_packets = sum(pkts)
    total_bytes = sum(bytes_sent)
    source_count = max(len(src_counts), 1)
    destination_count = max(len(dst_counts), 1)
    request_burst = float(anomaly.get("request_burst") or 0.0)
    failed_auth = float(anomaly.get("failed_auth_attempts") or 0.0)

    return {
        "dur": float(duration),
        "proto": predominant_proto,
        "service": _service_from_port(primary_port),
        "state": _state_from_events(auth_events, network_events),
        "spkts": float(total_packets),
        "dpkts": float(max(total_packets * 0.6, 1.0)),
        "sbytes": float(total_bytes),
        "dbytes": float(max(total_bytes * 0.5, 1.0)),
        "rate": round((total_packets + max(request_burst, 1.0)) / max(duration, 1.0), 4),
        "sttl": float(64 if failed_auth or request_burst else 128),
        "dttl": float(64),
        "sload": round(total_bytes / max(duration, 1.0), 4),
        "dload": round((total_bytes * 0.5) / max(duration, 1.0), 4),
        "sloss": float(anomaly.get("syn_event_count") or 0),
        "dloss": float(max((anomaly.get("syn_event_count") or 0) * 0.35, 0)),
        "sinpkt": round(max(duration, 1.0) / max(total_packets, 1), 6),
        "dinpkt": round(max(duration, 1.0) / max(total_packets * 0.6, 1), 6),
        "sjit": round((anomaly.get("port_span") or 0) * 0.1, 4),
        "djit": round((anomaly.get("suspicious_path_hits") or 0) * 0.1, 4),
        "swin": 255.0,
        "stcpb": float(total_bytes),
        "dtcpb": float(total_bytes * 0.5),
        "dwin": 255.0,
        "tcprtt": round((anomaly.get("port_span") or 1) * 0.02, 4),
        "synack": round((anomaly.get("syn_event_count") or 0) * 0.015, 4),
        "ackdat": round((failed_auth or 1) * 0.012, 4),
        "smean": round(total_bytes / max(total_packets, 1), 4),
        "dmean": round((total_bytes * 0.5) / max(total_packets, 1), 4),
        "trans_depth": float(max(request_burst, 1.0)),
        "response_body_len": float(total_bytes),
        "ct_srv_src": float(src_counts.most_common(1)[0][1] if src_counts else 0),
        "ct_state_ttl": float(anomaly.get("failed_auth_attempts") or anomaly.get("syn_event_count") or 0),
        "ct_dst_ltm": float(destination_count),
        "ct_src_dport_ltm": float(len(set(ports)) or anomaly.get("port_span") or 0),
        "ct_dst_sport_ltm": float(len(set(ports)) or 1),
        "ct_dst_src_ltm": float(source_count * destination_count),
        "is_ftp_login": 0.0,
        "ct_ftp_cmd": 0.0,
        "ct_flw_http_mthd": float(sum(1 for event in telemetry.get("events_by_type", {}).get("access", []) if event.get("method"))),
        "ct_src_ltm": float(source_count),
        "ct_srv_dst": float(destination_count),
        "is_sm_ips_ports": 1.0 if source_count == 1 and destination_count == 1 else 0.0,
    }


def _predict_waf(access_events: list[dict]) -> dict:
    model, columns = _load_waf_assets()
    features = _build_waf_features(access_events)
    frame = pd.DataFrame([features]).reindex(columns=columns, fill_value=0.0)
    probability = float(model.predict_proba(frame)[0][1])
    return {
        "probability": round(probability, 4),
        "threshold_log": 0.75,
        "threshold_block": 0.90,
        "features": {key: features[key] for key in columns if key in features},
        "model": "netgoat-ai/koda-waf",
    }


def _predict_nids(telemetry: dict, anomaly: dict) -> dict:
    model, encoders = _load_nids_assets()
    raw_features = _build_nids_features(telemetry, anomaly)
    encoded = dict(raw_features)
    encoded["proto"] = _safe_transform(encoders["proto"], raw_features["proto"], SAFE_PROTO_FALLBACK)
    encoded["service"] = _safe_transform(encoders["service"], raw_features["service"], SAFE_SERVICE_FALLBACK)
    encoded["state"] = _safe_transform(encoders["state"], raw_features["state"], SAFE_STATE_FALLBACK)
    frame = pd.DataFrame([encoded], columns=model.get_booster().feature_names)
    probability = float(model.predict_proba(frame)[0][1])
    return {
        "probability": round(probability, 4),
        "raw_features": raw_features,
        "encoded_features": encoded,
        "model": "netgoat-ai/koda-nids",
    }


def infer(context: dict) -> dict:
    telemetry = context.get("telemetry") or {}
    anomaly = context.get("anomaly") or {}
    access_events = telemetry.get("events_by_type", {}).get("access", [])

    waf_result = _predict_waf(access_events)
    nids_result = _predict_nids(telemetry, anomaly)

    failed_auth_attempts = float(anomaly.get("failed_auth_attempts") or 0.0)
    port_span = float(anomaly.get("port_span") or 0.0)
    suspicious_path_hits = float(anomaly.get("suspicious_path_hits") or 0.0)
    request_burst = float(anomaly.get("request_burst") or 0.0)
    source_count = float(len(anomaly.get("src_ips") or []))

    auth_pressure = min(failed_auth_attempts / 16.0, 1.0)
    scan_pressure = min(port_span / 18.0, 1.0)
    recon_pressure = min(suspicious_path_hits / 8.0, 1.0)
    volume_pressure = min((request_burst / 24.0) + (source_count / 14.0), 1.0)

    raw_scores = {
        "DDoS": max(nids_result["probability"] * 0.55 + volume_pressure * 0.45, 0.01),
        "BruteForce": max(auth_pressure * 0.7 + (nids_result["probability"] * 0.15) + (source_count <= 3) * 0.15, 0.01),
        "PortScan": max(scan_pressure * 0.65 + nids_result["probability"] * 0.35, 0.01),
        "SuspiciousRecon": max(recon_pressure * 0.45 + waf_result["probability"] * 0.55, 0.01),
    }
    total = sum(raw_scores.values()) or 1.0
    confidence_scores = {label: round(raw_scores[label] / total, 4) for label in CLASS_LABELS}
    predicted_class = max(confidence_scores, key=confidence_scores.get)
    confidence = round(confidence_scores[predicted_class], 4)

    return {
        "predicted_class": predicted_class,
        "confidence": confidence,
        "confidence_scores": confidence_scores,
        "training_method": "pretrained_model_fusion",
        "model_version": "koda-waf-v1_plus_koda-nids-v1",
        "components": {
            "waf": waf_result,
            "nids": nids_result,
        },
        "features": {
            "failed_auth_attempts": failed_auth_attempts,
            "port_span": port_span,
            "suspicious_path_hits": suspicious_path_hits,
            "request_burst": request_burst,
            "source_count": source_count,
            "auth_pressure": round(auth_pressure, 4),
            "scan_pressure": round(scan_pressure, 4),
            "recon_pressure": round(recon_pressure, 4),
            "volume_pressure": round(volume_pressure, 4),
        },
    }
