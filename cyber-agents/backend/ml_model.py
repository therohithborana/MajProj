from __future__ import annotations

import json
import random
from math import exp
from pathlib import Path


MODEL_DIR = Path(__file__).resolve().parent / "runtime_models"
MODEL_PATH = MODEL_DIR / "threat_model.json"
FEATURES = [
    "request_burst",
    "failed_auth_attempts",
    "port_span",
    "suspicious_path_hits",
    "unique_sources",
    "packet_rate",
    "bytes_rate",
    "syn_event_count",
]
CLASS_LABELS = ["DDoS", "BruteForce", "PortScan", "SuspiciousRecon"]

PROFILE_RANGES = {
    "DDoS": {
        "request_burst": (20, 40),
        "failed_auth_attempts": (0, 2),
        "port_span": (1, 4),
        "suspicious_path_hits": (0, 2),
        "unique_sources": (10, 28),
        "packet_rate": (3500, 12000),
        "bytes_rate": (150000, 500000),
        "syn_event_count": (10, 35),
    },
    "BruteForce": {
        "request_burst": (1, 8),
        "failed_auth_attempts": (10, 28),
        "port_span": (1, 5),
        "suspicious_path_hits": (0, 2),
        "unique_sources": (1, 4),
        "packet_rate": (40, 500),
        "bytes_rate": (2500, 15000),
        "syn_event_count": (0, 6),
    },
    "PortScan": {
        "request_burst": (2, 10),
        "failed_auth_attempts": (0, 3),
        "port_span": (12, 35),
        "suspicious_path_hits": (0, 2),
        "unique_sources": (1, 3),
        "packet_rate": (120, 900),
        "bytes_rate": (4000, 28000),
        "syn_event_count": (4, 20),
    },
    "SuspiciousRecon": {
        "request_burst": (4, 14),
        "failed_auth_attempts": (0, 2),
        "port_span": (1, 8),
        "suspicious_path_hits": (6, 18),
        "unique_sources": (1, 5),
        "packet_rate": (70, 500),
        "bytes_rate": (3000, 20000),
        "syn_event_count": (1, 10),
    },
}


def _sample_point(label: str, rng: random.Random) -> dict:
    profile = PROFILE_RANGES[label]
    return {
        feature: rng.uniform(*profile[feature])
        for feature in FEATURES
    }


def _distance(a: dict, b: dict) -> float:
    return sum((float(a.get(feature, 0.0)) - float(b.get(feature, 0.0))) ** 2 for feature in FEATURES) ** 0.5


def train_and_persist_model(seed: int = 14) -> dict:
    rng = random.Random(seed)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    samples = {label: [_sample_point(label, rng) for _ in range(80)] for label in CLASS_LABELS}
    centroids = {}
    spreads = {}
    for label, items in samples.items():
        centroids[label] = {
            feature: round(sum(item[feature] for item in items) / len(items), 4)
            for feature in FEATURES
        }
        spreads[label] = round(
            max(sum(_distance(item, centroids[label]) for item in items) / len(items), 1.0),
            4,
        )
    artifact = {
        "version": "1.0.0",
        "features": FEATURES,
        "labels": CLASS_LABELS,
        "centroids": centroids,
        "spreads": spreads,
        "training_method": "synthetic_centroid_classifier",
        "sample_count": sum(len(items) for items in samples.values()),
    }
    MODEL_PATH.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    return artifact


def load_model() -> dict:
    if not MODEL_PATH.exists():
        return train_and_persist_model()
    return json.loads(MODEL_PATH.read_text(encoding="utf-8"))


def infer(features: dict) -> dict:
    model = load_model()
    scores = {}
    distances = {}
    for label in model["labels"]:
        centroid = model["centroids"][label]
        spread = max(float(model["spreads"].get(label, 1.0)), 1.0)
        dist = _distance(features, centroid)
        distances[label] = round(dist, 4)
        scores[label] = exp(-(dist / spread))

    total = sum(scores.values()) or 1.0
    probabilities = {label: round(scores[label] / total, 4) for label in model["labels"]}
    predicted = max(probabilities, key=probabilities.get)
    confidence = probabilities[predicted]
    return {
        "predicted_class": predicted,
        "confidence": confidence,
        "confidence_scores": probabilities,
        "distances": distances,
        "model_version": model["version"],
        "training_method": model["training_method"],
        "features": {feature: round(float(features.get(feature, 0.0)), 4) for feature in FEATURES},
    }
