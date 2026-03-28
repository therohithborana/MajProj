import json
import random
from collections import Counter, defaultdict
from pathlib import Path
from typing import TypedDict

from langgraph.graph import END, StateGraph

from gemini_client import call_gemini


class AgentState(TypedDict, total=False):
    simulation: dict
    telemetry: dict
    anomaly: dict
    classification: dict
    mitigation_plan: dict
    approval_status: str
    action_result: dict
    incident_report: dict
    current_stage: str


def _clean_json_payload(text: str) -> str:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:].strip()
    return cleaned


def _read_recent_lines(path_str: str, limit: int = 50):
    path = Path(path_str)
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as handle:
        lines = [line.strip() for line in handle.readlines() if line.strip()]
    return lines[-limit:]


def _extract_value(line: str, key: str, default=""):
    marker = f"{key}="
    if marker not in line:
        return default
    tail = line.split(marker, 1)[1]
    return tail.split(" ", 1)[0].strip()


def log_monitor(state: AgentState) -> AgentState:
    log_paths = state["simulation"]["telemetry"]["log_paths"]
    recent_logs = {name: _read_recent_lines(path) for name, path in log_paths.items()}
    total_logs = sum(len(lines) for lines in recent_logs.values())

    state["telemetry"] = {
        "log_paths": log_paths,
        "recent_logs": recent_logs,
        "log_counts": {name: len(lines) for name, lines in recent_logs.items()},
        "total_logs_observed": total_logs,
    }
    state["current_stage"] = "log_monitoring"
    return state


def anomaly_detection(state: AgentState) -> AgentState:
    telemetry = state["telemetry"]
    access_logs = telemetry["recent_logs"].get("access", [])
    auth_logs = telemetry["recent_logs"].get("auth", [])
    network_logs = telemetry["recent_logs"].get("network", [])

    source_counter = Counter()
    port_counter = Counter()
    failed_auth = Counter()
    request_paths = Counter()
    packet_total = 0

    for line in access_logs + auth_logs + network_logs:
        src = _extract_value(line, "src")
        if src:
            source_counter[src] += 1

    for line in access_logs:
        path = _extract_value(line, "path")
        if path:
            request_paths[path] += 1

    for line in auth_logs:
        src = _extract_value(line, "src")
        result = _extract_value(line, "result")
        if src and result == "FAILED":
            failed_auth[src] += 1
        port = _extract_value(line, "port")
        if port:
            port_counter[port] += 1

    network_ports_by_src = defaultdict(set)
    syn_count = 0
    for line in network_logs:
        src = _extract_value(line, "src")
        dst = _extract_value(line, "dst")
        flags = _extract_value(line, "flags")
        packets = _extract_value(line, "packets", "0")
        if dst and ":" in dst:
            _, port = dst.rsplit(":", 1)
            port_counter[port] += 1
            if src:
                network_ports_by_src[src].add(port)
        try:
            packet_total += int(packets)
        except ValueError:
            pass
        if flags == "SYN":
            syn_count += 1

    primary_src_ip = source_counter.most_common(1)[0][0] if source_counter else "unknown"
    unique_src_ips = sorted(source_counter.keys())
    unique_ports = sorted({int(port) for port in port_counter if port.isdigit()})
    max_failed_auth = failed_auth[primary_src_ip] if primary_src_ip in failed_auth else 0
    scan_span = len(network_ports_by_src.get(primary_src_ip, set()))
    request_burst = len(access_logs)

    if len(unique_src_ips) >= 10 and request_burst >= 20 and packet_total >= 100000:
        anomaly_type = "traffic_spike"
        severity = "CRITICAL"
        summary = "Large burst of access and network flow events from many sources."
    elif max_failed_auth >= 10:
        anomaly_type = "auth_failure_burst"
        severity = "HIGH"
        summary = "Repeated failed authentication attempts from the same source."
    elif scan_span >= 12:
        anomaly_type = "sequential_port_probe"
        severity = "MEDIUM"
        summary = "Single source touched many destination ports in a short interval."
    else:
        anomaly_type = "suspicious_activity"
        severity = "MEDIUM"
        summary = "Telemetry deviated from normal expectations and requires review."

    target_port = unique_ports[0] if unique_ports else 80
    target_ip = ""
    for line in network_logs:
        dst = _extract_value(line, "dst")
        if dst and ":" in dst:
            target_ip = dst.rsplit(":", 1)[0]
            break

    state["anomaly"] = {
        "anomaly_type": anomaly_type,
        "severity": severity,
        "summary": summary,
        "primary_src_ip": primary_src_ip,
        "src_ips": unique_src_ips[:20],
        "target_ip": target_ip or "unknown",
        "target_port": target_port,
        "request_burst": request_burst,
        "failed_auth_attempts": max_failed_auth,
        "ports_touched": unique_ports[:30],
        "port_span": scan_span,
        "total_packets_observed": packet_total,
        "syn_event_count": syn_count,
        "sample_logs": {
            "access": access_logs[-5:],
            "auth": auth_logs[-5:],
            "network": network_logs[-5:],
        },
    }
    state["current_stage"] = "anomaly_detected"
    return state


def _normalize_scores(raw_scores, predicted_class):
    labels = ["DDoS", "BruteForce", "PortScan"]
    total = sum(max(raw_scores.get(label, 0.01), 0.01) for label in labels)
    normalized = {
        label: round(max(raw_scores.get(label, 0.01), 0.01) / total, 4)
        for label in labels
    }
    diff = round(1.0 - sum(normalized.values()), 4)
    normalized[predicted_class] = round(normalized[predicted_class] + diff, 4)
    return normalized


def threat_classification(state: AgentState) -> AgentState:
    anomaly = state["anomaly"]
    telemetry = state["telemetry"]

    if anomaly["anomaly_type"] == "traffic_spike":
        predicted_class = "DDoS"
        confidence = round(random.uniform(0.9, 0.98), 4)
        raw_scores = {"DDoS": confidence, "BruteForce": 0.04, "PortScan": 0.03}
    elif anomaly["anomaly_type"] == "auth_failure_burst":
        predicted_class = "BruteForce"
        confidence = round(random.uniform(0.88, 0.97), 4)
        raw_scores = {"DDoS": 0.05, "BruteForce": confidence, "PortScan": 0.04}
    elif anomaly["anomaly_type"] == "sequential_port_probe":
        predicted_class = "PortScan"
        confidence = round(random.uniform(0.86, 0.96), 4)
        raw_scores = {"DDoS": 0.04, "BruteForce": 0.05, "PortScan": confidence}
    else:
        predicted_class = "PortScan"
        confidence = round(random.uniform(0.74, 0.84), 4)
        raw_scores = {"DDoS": 0.15, "BruteForce": 0.2, "PortScan": confidence}

    risk_score = min(
        100,
        int(
            confidence * 100
            + anomaly["request_burst"] * 0.4
            + anomaly["failed_auth_attempts"] * 1.2
            + anomaly["port_span"] * 0.8
        ),
    )

    packet_rate_estimate = max(1, int(anomaly["total_packets_observed"] / max(1, telemetry["total_logs_observed"])))
    protocol = "TCP"

    attack = {
        "attack_id": state["simulation"]["attack_id"],
        "timestamp": state["simulation"]["timestamp"],
        "attack_type": predicted_class,
        "severity": anomaly["severity"],
        "src_ips": anomaly["src_ips"] or [anomaly["primary_src_ip"]],
        "primary_src_ip": anomaly["primary_src_ip"],
        "target_ip": anomaly["target_ip"],
        "target_port": anomaly["target_port"],
        "protocol": protocol,
        "packet_rate": packet_rate_estimate,
        "description": anomaly["summary"],
        "raw_log": "\n".join(
            anomaly["sample_logs"]["network"] or anomaly["sample_logs"]["auth"] or anomaly["sample_logs"]["access"]
        ),
    }

    key_indicators = [
        f"Observed {telemetry['total_logs_observed']} log lines across access, auth, and network telemetry.",
        f"Primary source {attack['primary_src_ip']} appeared in {len(attack['src_ips'])} correlated source entries.",
        f"Target port {attack['target_port']} and protocol {attack['protocol']} matched the dominant anomaly pattern.",
        f"Risk score reached {risk_score} based on request burst, auth failures, and port spread.",
    ]

    state["classification"] = {
        "predicted_class": predicted_class,
        "confidence": confidence,
        "confidence_scores": _normalize_scores(raw_scores, predicted_class),
        "key_indicators": key_indicators,
        "risk_score": risk_score,
        "attack": attack,
    }
    state["current_stage"] = "classified"
    return state


def _fallback_mitigation_plan(state: AgentState):
    attack = state["classification"]["attack"]
    primary_ip = attack["primary_src_ip"]
    target_port = attack["target_port"]
    return {
        "strategy": f"Contain {attack['attack_type']} traffic",
        "estimated_mitigation_time": "10 minutes",
        "collateral_risk": "MEDIUM - Temporary restrictions may affect legitimate sessions on the targeted service.",
        "steps": [
            {
                "step": 1,
                "action": "Block hostile source",
                "command": f"iptables -A INPUT -s {primary_ip} -j DROP",
                "impact": "Drops packets from the most active suspicious source.",
                "reversible": True,
            },
            {
                "step": 2,
                "action": "Limit traffic on target port",
                "command": f"ufw limit {target_port}/tcp",
                "impact": "Applies rate limiting to reduce abusive connection pressure.",
                "reversible": True,
            },
            {
                "step": 3,
                "action": "Escalate abusive IP to fail2ban",
                "command": f"fail2ban-client set sshd banip {primary_ip}",
                "impact": "Adds the primary source to a temporary deny list.",
                "reversible": True,
            },
        ],
    }


def threat_resolve(state: AgentState) -> AgentState:
    attack = state["classification"]["attack"]
    classification = state["classification"]
    prompt = f"""
You are a senior cybersecurity engineer. An attack has been detected with the following details:

Attack Type: {attack["attack_type"]}
Severity: {attack["severity"]}
Source IP(s): {attack["src_ips"]}
Target: {attack["target_ip"]}:{attack["target_port"]}
Protocol: {attack["protocol"]}
Packet Rate: {attack["packet_rate"]}/sec
Detection Confidence: {round(classification["confidence"] * 100, 2)}%
Risk Score: {classification["risk_score"]}/100

Generate a mitigation plan as a JSON object with exactly this structure:
{{
  "strategy": "short strategy name",
  "estimated_mitigation_time": "X minutes",
  "collateral_risk": "LOW/MEDIUM/HIGH — one sentence explanation",
  "steps": [
    {{
      "step": 1,
      "action": "action name",
      "command": "exact shell command to run",
      "impact": "what this does",
      "reversible": true
    }}
  ]
}}

Rules:
- Provide exactly 3-4 steps
- Commands must be real Linux shell commands (iptables, ufw, fail2ban-client, etc.)
- Use the actual source IP and target port in the commands
- reversible must be a boolean
- Return ONLY the JSON, no markdown, no explanation
""".strip()

    fallback = _fallback_mitigation_plan(state)
    try:
        response = call_gemini(prompt)
        parsed = json.loads(_clean_json_payload(response))
        if not isinstance(parsed, dict) or "steps" not in parsed:
            raise ValueError("Invalid mitigation plan")
        state["mitigation_plan"] = parsed
    except Exception:
        state["mitigation_plan"] = fallback

    state["approval_status"] = "pending"
    state["current_stage"] = "awaiting_approval"
    return state


def action(state: AgentState) -> AgentState:
    attack = state["classification"]["attack"]
    mitigation_plan = state.get("mitigation_plan", {})
    decision = state.get("approval_status")

    if decision == "approved":
        executed_steps = []
        total_execution_time_ms = 0
        for step in mitigation_plan.get("steps", []):
            execution_time_ms = random.randint(50, 400)
            total_execution_time_ms += execution_time_ms
            executed_steps.append({**step, "status": "EXECUTED", "execution_time_ms": execution_time_ms})
        action_result = {
            "status": "MITIGATED",
            "steps_executed": executed_steps,
            "total_execution_time_ms": total_execution_time_ms,
            "blocked_ips": attack["src_ips"],
        }
        state["current_stage"] = "mitigated"
    else:
        action_result = {
            "status": "MANUAL_INTERVENTION_REQUIRED",
            "ticket_id": f"SEC-{attack['attack_id']}",
            "assigned_to": "security-team@company.com",
        }
        state["current_stage"] = "manual_queue"

    state["action_result"] = action_result
    return state


def _fallback_incident_report(state: AgentState, resolved_in: int):
    attack = state["classification"]["attack"]
    classification = state["classification"]
    status = state["action_result"]["status"]
    return {
        "report_id": f"INC-{attack['attack_id']}",
        "executive_summary": (
            f"Telemetry from access, auth, and network logs revealed a {attack['severity']} {attack['attack_type']} incident "
            f"targeting {attack['target_ip']}:{attack['target_port']}. CyberAgent analyzed the evidence, generated a response plan, "
            f"and concluded with status {status}."
        ),
        "attack_summary": {
            "type": attack["attack_type"],
            "severity": attack["severity"],
            "source": attack["primary_src_ip"],
            "target": f"{attack['target_ip']}:{attack['target_port']}",
            "confidence": f"{round(classification['confidence'] * 100, 2)}%",
            "risk_score": classification["risk_score"],
        },
        "response": status,
        "recommendations": [
            "Keep continuous monitoring active on access, auth, and network logs.",
            "Review exposed services on the targeted host and confirm rate-limiting rules.",
            "Validate follow-up hardening actions for the affected entry point.",
        ],
        "timeline": {
            "detected": attack["timestamp"],
            "classified": "T+1.2s",
            "plan_generated": "T+3.5s",
            "resolved": f"T+{resolved_in}s",
        },
    }


def report(state: AgentState) -> AgentState:
    attack = state["classification"]["attack"]
    classification = state["classification"]
    status = state["action_result"]["status"]
    resolved_in = random.randint(8, 30)
    steps_taken = len(state["action_result"].get("steps_executed", []))
    prompt = f"""
You are a cybersecurity incident reporter. Write a concise professional incident report summary.

Incident Details:
- Attack Type: {attack["attack_type"]}
- Severity: {attack["severity"]}
- Source IP: {attack["primary_src_ip"]}
- Target: {attack["target_ip"]}:{attack["target_port"]}
- Detection Confidence: {round(classification["confidence"] * 100, 2)}%
- Risk Score: {classification["risk_score"]}/100
- Resolution: {status}
- Steps Taken: {steps_taken}

Return a JSON object with exactly this structure:
{{
  "report_id": "INC-{attack["attack_id"]}",
  "executive_summary": "2-3 sentence plain English summary of what happened and how it was resolved",
  "attack_summary": {{
    "type": "{attack["attack_type"]}",
    "severity": "{attack["severity"]}",
    "source": "{attack["primary_src_ip"]}",
    "target": "{attack["target_ip"]}:{attack["target_port"]}",
    "confidence": "{round(classification["confidence"] * 100, 2)}%",
    "risk_score": {classification["risk_score"]}
  }},
  "response": "{status}",
  "recommendations": ["recommendation 1", "recommendation 2", "recommendation 3"],
  "timeline": {{
    "detected": "{attack["timestamp"]}",
    "classified": "T+1.2s",
    "plan_generated": "T+3.5s",
    "resolved": "T+{resolved_in}s"
  }}
}}

Return ONLY the JSON, no markdown, no explanation.
""".strip()

    fallback = _fallback_incident_report(state, resolved_in)
    try:
        response = call_gemini(prompt)
        parsed = json.loads(_clean_json_payload(response))
        if not isinstance(parsed, dict) or "executive_summary" not in parsed:
            raise ValueError("Invalid incident report")
        state["incident_report"] = parsed
    except Exception:
        state["incident_report"] = fallback
    return state


_detection_builder = StateGraph(AgentState)
_detection_builder.add_node("log_monitor", log_monitor)
_detection_builder.add_node("anomaly_detection", anomaly_detection)
_detection_builder.add_node("threat_classification", threat_classification)
_detection_builder.add_node("threat_resolve", threat_resolve)
_detection_builder.set_entry_point("log_monitor")
_detection_builder.add_edge("log_monitor", "anomaly_detection")
_detection_builder.add_edge("anomaly_detection", "threat_classification")
_detection_builder.add_edge("threat_classification", "threat_resolve")
_detection_builder.add_edge("threat_resolve", END)
detection_graph = _detection_builder.compile()

_action_builder = StateGraph(AgentState)
_action_builder.add_node("action", action)
_action_builder.add_node("report", report)
_action_builder.set_entry_point("action")
_action_builder.add_edge("action", "report")
_action_builder.add_edge("report", END)
action_graph = _action_builder.compile()
