import json
import random
from collections import Counter, defaultdict
from typing import TypedDict

from langgraph.graph import END, StateGraph

from gemini_client import call_gemini


class AgentState(TypedDict, total=False):
    website: dict
    simulation: dict
    telemetry: dict
    anomaly: dict
    correlation: dict
    classification: dict
    investigation: dict
    mitigation_plan: dict
    policy_decision: dict
    approval_status: str
    action_result: dict
    incident_report: dict
    agent_trace: list
    current_stage: str


SENSITIVE_PATH_TOKENS = ("/admin", "/.env", "phpmyadmin", "wp-admin", "server-status", "config", "backup")


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


def _trace(state: AgentState, agent: str, stage: str, summary: str, details=None):
    entries = list(state.get("agent_trace", []))
    entries.append(
        {
            "agent": agent,
            "stage": stage,
            "summary": summary,
            "details": details or {},
        }
    )
    state["agent_trace"] = entries


def normalization(state: AgentState) -> AgentState:
    raw_events = state["simulation"]["events"]
    normalized_events = []
    event_counts = Counter()
    unique_sources = set()

    for event in raw_events:
        normalized = {
            "event_type": event.get("event_type"),
            "timestamp": event.get("timestamp"),
            "src_ip": event.get("src_ip"),
            "dst_ip": event.get("dst_ip"),
            "port": event.get("port"),
            "protocol": event.get("protocol"),
            "method": event.get("method"),
            "path": event.get("path"),
            "status_code": event.get("status_code"),
            "username": event.get("username"),
            "result": event.get("result"),
            "bytes_sent": event.get("bytes_sent", 0),
            "packets": event.get("packets", 0),
            "flags": event.get("flags"),
            "message": event.get("message", ""),
            "metadata": event.get("metadata", {}),
        }
        normalized_events.append(normalized)
        event_counts[normalized["event_type"]] += 1
        if normalized.get("src_ip"):
            unique_sources.add(normalized["src_ip"])

    state["telemetry"] = {
        "events": normalized_events,
        "event_counts": dict(event_counts),
        "total_events_observed": len(normalized_events),
        "source_count": len(unique_sources),
        "events_by_type": {
            "access": [event for event in normalized_events if event["event_type"] == "access"],
            "auth": [event for event in normalized_events if event["event_type"] == "auth"],
            "network": [event for event in normalized_events if event["event_type"] == "network"],
        },
    }
    state["current_stage"] = "normalization"
    _trace(
        state,
        "Normalization Agent",
        "normalization",
        "Converted raw collector payloads into a common event schema.",
        {"counts": dict(event_counts), "sources": len(unique_sources)},
    )
    return state


def detection(state: AgentState) -> AgentState:
    telemetry = state["telemetry"]
    access_events = telemetry["events_by_type"]["access"]
    auth_events = telemetry["events_by_type"]["auth"]
    network_events = telemetry["events_by_type"]["network"]

    source_counter = Counter()
    port_counter = Counter()
    failed_auth = Counter()
    request_paths = Counter()
    packet_total = 0
    bytes_total = 0
    network_ports_by_src = defaultdict(set)
    target_counter = Counter()
    flagged_paths = []
    syn_count = 0

    for event in telemetry["events"]:
        src = event.get("src_ip")
        if src:
            source_counter[src] += 1

    for event in access_events:
        path = event.get("path") or ""
        if path:
            request_paths[path] += 1
            if any(token in path for token in SENSITIVE_PATH_TOKENS):
                flagged_paths.append(path)

    for event in auth_events:
        src = event.get("src_ip")
        if src and event.get("result") == "FAILED":
            failed_auth[src] += 1
        if event.get("port"):
            port_counter[str(event["port"])] += 1

    for event in network_events:
        src = event.get("src_ip")
        dst_ip = event.get("dst_ip")
        port = event.get("port")
        flags = event.get("flags")
        packets = int(event.get("packets") or 0)
        packet_total += packets
        bytes_total += int(event.get("bytes_sent") or 0)
        if dst_ip:
            target_counter[dst_ip] += 1
        if port:
            port_counter[str(port)] += 1
        if src and port:
            network_ports_by_src[src].add(port)
        if flags == "SYN":
            syn_count += 1

    primary_src_ip = source_counter.most_common(1)[0][0] if source_counter else "unknown"
    unique_src_ips = sorted(source_counter.keys())
    unique_ports = sorted({int(port) for port in port_counter if port.isdigit()})
    scan_span = len(network_ports_by_src.get(primary_src_ip, set()))
    max_failed_auth = failed_auth[primary_src_ip] if primary_src_ip in failed_auth else 0
    request_burst = len(access_events)
    suspicious_path_hits = len(flagged_paths)
    dominant_target = target_counter.most_common(1)[0][0] if target_counter else "unknown"
    target_port = unique_ports[0] if unique_ports else 80

    if len(unique_src_ips) >= 10 and request_burst >= 20 and packet_total >= 100000:
        anomaly_type = "traffic_spike"
        severity = "CRITICAL"
        summary = "Distributed traffic spike indicates a DDoS-style service disruption attempt."
    elif max_failed_auth >= 10:
        anomaly_type = "auth_failure_burst"
        severity = "HIGH"
        summary = "Repeated failed authentication attempts suggest credential abuse."
    elif scan_span >= 12:
        anomaly_type = "sequential_port_probe"
        severity = "MEDIUM"
        summary = "A single source probed many ports in a short interval."
    elif suspicious_path_hits >= 6:
        anomaly_type = "suspicious_path_recon"
        severity = "MEDIUM"
        summary = "Repeated access to sensitive paths indicates application reconnaissance."
    else:
        anomaly_type = "baseline"
        severity = "LOW"
        summary = "Observed activity remains within expected guardrails."

    state["anomaly"] = {
        "anomaly_type": anomaly_type,
        "severity": severity,
        "summary": summary,
        "primary_src_ip": primary_src_ip,
        "src_ips": unique_src_ips[:30],
        "target_ip": dominant_target,
        "target_port": target_port,
        "request_burst": request_burst,
        "failed_auth_attempts": max_failed_auth,
        "ports_touched": unique_ports[:40],
        "port_span": scan_span,
        "total_packets_observed": packet_total,
        "total_bytes_observed": bytes_total,
        "syn_event_count": syn_count,
        "suspicious_path_hits": suspicious_path_hits,
        "flagged_paths": flagged_paths[:12],
        "sample_events": {
            "access": access_events[-5:],
            "auth": auth_events[-5:],
            "network": network_events[-5:],
        },
    }
    state["current_stage"] = "detection"
    _trace(
        state,
        "Detection Agent",
        "detection",
        summary,
        {
            "anomaly_type": anomaly_type,
            "severity": severity,
            "request_burst": request_burst,
            "failed_auth_attempts": max_failed_auth,
            "port_span": scan_span,
            "suspicious_path_hits": suspicious_path_hits,
        },
    )
    return state


def correlation(state: AgentState) -> AgentState:
    telemetry = state["telemetry"]
    anomaly = state["anomaly"]
    events = telemetry["events"]
    primary_src = anomaly["primary_src_ip"]
    correlated = [event for event in events if event.get("src_ip") == primary_src][:20]
    affected_paths = sorted({event.get("path") for event in correlated if event.get("path")})[:10]
    affected_ports = sorted({event.get("port") for event in correlated if event.get("port")})[:10]
    timeline = [
        {
            "timestamp": event.get("timestamp"),
            "event_type": event.get("event_type"),
            "summary": event.get("message"),
        }
        for event in correlated[:10]
    ]

    state["correlation"] = {
        "primary_src_ip": primary_src,
        "event_count": len(correlated),
        "affected_paths": affected_paths,
        "affected_ports": affected_ports,
        "timeline": timeline,
        "evidence_window": correlated[-8:],
    }
    state["current_stage"] = "correlation"
    _trace(
        state,
        "Correlation Agent",
        "correlation",
        "Linked access, auth, and network signals into one attack story.",
        {"evidence_events": len(correlated), "affected_ports": affected_ports, "affected_paths": affected_paths},
    )
    return state


def _normalize_scores(raw_scores, predicted_class):
    labels = ["DDoS", "BruteForce", "PortScan", "SuspiciousRecon"]
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
        raw_scores = {"DDoS": 0.93, "BruteForce": 0.03, "PortScan": 0.02, "SuspiciousRecon": 0.02}
    elif anomaly["anomaly_type"] == "auth_failure_burst":
        predicted_class = "BruteForce"
        raw_scores = {"DDoS": 0.02, "BruteForce": 0.92, "PortScan": 0.03, "SuspiciousRecon": 0.03}
    elif anomaly["anomaly_type"] == "sequential_port_probe":
        predicted_class = "PortScan"
        raw_scores = {"DDoS": 0.03, "BruteForce": 0.04, "PortScan": 0.9, "SuspiciousRecon": 0.03}
    elif anomaly["anomaly_type"] == "suspicious_path_recon":
        predicted_class = "SuspiciousRecon"
        raw_scores = {"DDoS": 0.03, "BruteForce": 0.04, "PortScan": 0.13, "SuspiciousRecon": 0.8}
    else:
        predicted_class = "SuspiciousRecon"
        raw_scores = {"DDoS": 0.15, "BruteForce": 0.15, "PortScan": 0.2, "SuspiciousRecon": 0.5}

    confidence_scores = _normalize_scores(raw_scores, predicted_class)
    confidence = confidence_scores[predicted_class]
    risk_score = min(
        100,
        int(
            confidence * 100
            + anomaly["request_burst"] * 0.5
            + anomaly["failed_auth_attempts"] * 1.4
            + anomaly["port_span"] * 1.1
            + anomaly["suspicious_path_hits"] * 1.8
        ),
    )
    severity = "CRITICAL" if risk_score >= 90 else "HIGH" if risk_score >= 75 else "MEDIUM" if risk_score >= 45 else "LOW"

    attack = {
        "attack_id": state["simulation"]["attack_id"],
        "timestamp": state["simulation"]["timestamp"],
        "attack_type": predicted_class,
        "severity": severity,
        "src_ips": anomaly["src_ips"] or [anomaly["primary_src_ip"]],
        "primary_src_ip": anomaly["primary_src_ip"],
        "target_ip": anomaly["target_ip"],
        "target_port": anomaly["target_port"],
        "protocol": "TCP",
        "packet_rate": max(1, int(anomaly["total_packets_observed"] / max(1, telemetry["total_events_observed"]))),
        "description": anomaly["summary"],
        "raw_log": "\n".join(
            event.get("message", "")
            for event in (
                anomaly["sample_events"]["network"] or anomaly["sample_events"]["auth"] or anomaly["sample_events"]["access"]
            )
        ),
    }

    key_indicators = [
        f"Observed {telemetry['total_events_observed']} events across access, auth, and network telemetry.",
        f"Primary source {attack['primary_src_ip']} appeared in {len(attack['src_ips'])} correlated source entries.",
        f"Risk score reached {risk_score} from authentication failures, request bursts, port spread, and path probes.",
        f"Dominant target {attack['target_ip']}:{attack['target_port']} matched the highest-risk activity cluster.",
    ]

    state["classification"] = {
        "predicted_class": predicted_class,
        "confidence": confidence,
        "confidence_scores": confidence_scores,
        "key_indicators": key_indicators,
        "risk_score": risk_score,
        "attack": attack,
    }
    state["current_stage"] = "classification"
    _trace(
        state,
        "Threat Classification Agent",
        "classification",
        f"Classified the incident as {predicted_class} with {round(confidence * 100, 1)}% confidence.",
        {"risk_score": risk_score, "severity": severity},
    )
    return state


def investigation(state: AgentState) -> AgentState:
    classification = state["classification"]
    anomaly = state["anomaly"]
    correlation_data = state["correlation"]
    attack = classification["attack"]

    state["investigation"] = {
        "summary": f"{attack['attack_type']} activity impacted {attack['target_ip']}:{attack['target_port']}.",
        "affected_assets": [f"{attack['target_ip']}:{attack['target_port']}"],
        "attacker_profile": {
            "primary_src_ip": attack["primary_src_ip"],
            "src_ip_count": len(attack["src_ips"]),
            "behavior": anomaly["summary"],
        },
        "evidence": correlation_data["evidence_window"],
        "timeline": correlation_data["timeline"],
        "recommended_owner": "security-team@company.com",
    }
    state["current_stage"] = "investigation"
    _trace(
        state,
        "Investigation Agent",
        "investigation",
        "Compiled evidence, attacker profile, and response-ready timeline.",
        {"affected_assets": state["investigation"]["affected_assets"], "timeline_items": len(correlation_data["timeline"])},
    )
    return state


def _fallback_mitigation_plan(state: AgentState):
    attack = state["classification"]["attack"]
    attack_type = attack["attack_type"]
    primary_ip = attack["primary_src_ip"]
    target_port = attack["target_port"]
    if attack_type == "BruteForce":
        strategy = "Throttle authentication abuse and isolate hostile source"
    elif attack_type == "DDoS":
        strategy = "Rate limit public ingress and drop malicious sources"
    elif attack_type == "PortScan":
        strategy = "Block scanning source and tighten exposed ports"
    else:
        strategy = "Restrict reconnaissance source and increase monitoring"
    return {
        "strategy": strategy,
        "estimated_mitigation_time": "6 minutes",
        "collateral_risk": "MEDIUM - Temporary restrictions may affect legitimate traffic sharing the same source range.",
        "steps": [
            {
                "step": 1,
                "action": "Block hostile source",
                "command": f"iptables -A INPUT -s {primary_ip} -j DROP",
                "impact": "Drops traffic from the most suspicious source.",
                "reversible": True,
            },
            {
                "step": 2,
                "action": "Limit traffic on target service",
                "command": f"ufw limit {target_port}/tcp",
                "impact": "Reduces abusive connection pressure on the target service.",
                "reversible": True,
            },
            {
                "step": 3,
                "action": "Escalate to temporary deny list",
                "command": f"fail2ban-client set sshd banip {primary_ip}",
                "impact": "Applies a temporary ban through the host intrusion-prevention layer.",
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
  "collateral_risk": "LOW/MEDIUM/HIGH - one sentence explanation",
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
- Commands must be real Linux shell commands
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

    state["current_stage"] = "response_planning"
    _trace(
        state,
        "Response Planning Agent",
        "response_planning",
        "Drafted a containment plan and response playbook.",
        {"strategy": state["mitigation_plan"]["strategy"], "steps": len(state["mitigation_plan"].get("steps", []))},
    )
    return state


def policy(state: AgentState) -> AgentState:
    classification = state["classification"]
    mitigation_plan = state["mitigation_plan"]
    attack = classification["attack"]
    risk_score = classification["risk_score"]

    if attack["attack_type"] == "BruteForce" and risk_score < 90:
        mode = "auto_execute"
        reason = "Credential abuse can be contained with reversible low-blast-radius actions."
    elif attack["attack_type"] == "SuspiciousRecon":
        mode = "auto_execute"
        reason = "Reconnaissance is low-risk to contain and benefits from fast automated blocking."
    elif attack["attack_type"] == "PortScan":
        mode = "approval_required"
        reason = "Port scan response may impact legitimate scanners or monitoring ranges."
    elif attack["attack_type"] == "DDoS":
        mode = "approval_required"
        reason = "Traffic controls on public services can affect legitimate customer sessions."
    else:
        mode = "manual_escalation"
        reason = "The evidence is ambiguous and requires a human analyst."

    state["policy_decision"] = {
        "mode": mode,
        "reason": reason,
        "auto_execute": mode == "auto_execute",
        "safe_actions": [step["action"] for step in mitigation_plan.get("steps", []) if step.get("reversible")],
    }
    state["approval_status"] = "auto_approved" if mode == "auto_execute" else "pending" if mode == "approval_required" else "manual_required"
    state["current_stage"] = "policy_decision"
    _trace(
        state,
        "Policy Agent",
        "policy_decision",
        f"Selected {mode} based on risk, reversibility, and blast-radius policy.",
        {"reason": reason},
    )
    return state


def action(state: AgentState) -> AgentState:
    attack = state["classification"]["attack"]
    mitigation_plan = state.get("mitigation_plan", {})
    decision = state.get("approval_status")

    if decision in {"approved", "auto_approved"}:
        executed_steps = []
        total_execution_time_ms = 0
        for step in mitigation_plan.get("steps", []):
            execution_time_ms = random.randint(50, 400)
            total_execution_time_ms += execution_time_ms
            executed_steps.append({**step, "status": "EXECUTED", "execution_time_ms": execution_time_ms})
        action_result = {
            "status": "MITIGATED",
            "execution_mode": "AUTONOMOUS" if decision == "auto_approved" else "HUMAN_APPROVED",
            "steps_executed": executed_steps,
            "total_execution_time_ms": total_execution_time_ms,
            "blocked_ips": attack["src_ips"],
        }
        state["current_stage"] = "mitigated"
    elif decision == "rejected":
        action_result = {
            "status": "MANUAL_INTERVENTION_REQUIRED",
            "execution_mode": "HUMAN_REJECTED",
            "ticket_id": f"SEC-{attack['attack_id']}",
            "assigned_to": "security-team@company.com",
        }
        state["current_stage"] = "manual_queue"
    else:
        action_result = {
            "status": "MANUAL_ESCALATION_REQUIRED",
            "execution_mode": "POLICY_ESCALATED",
            "ticket_id": f"SEC-{attack['attack_id']}",
            "assigned_to": "security-team@company.com",
        }
        state["current_stage"] = "manual_queue"

    state["action_result"] = action_result
    _trace(
        state,
        "Action Agent",
        "action",
        f"Completed the response path with status {action_result['status']}.",
        {"execution_mode": action_result["execution_mode"]},
    )
    return state


def _fallback_incident_report(state: AgentState, resolved_in: int):
    attack = state["classification"]["attack"]
    classification = state["classification"]
    status = state["action_result"]["status"]
    policy_decision = state["policy_decision"]
    return {
        "report_id": f"INC-{attack['attack_id']}",
        "executive_summary": (
            f"Telemetry from collector-fed access, auth, and network streams revealed a {attack['severity']} "
            f"{attack['attack_type']} incident targeting {attack['target_ip']}:{attack['target_port']}. "
            f"CyberAgent investigated, planned a response, applied policy mode {policy_decision['mode']}, and finished with status {status}."
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
        "automation": {
            "policy_mode": policy_decision["mode"],
            "execution_mode": state["action_result"].get("execution_mode"),
        },
        "recommendations": [
            "Keep collector telemetry active on access, auth, and network sources.",
            "Review exposed services on the targeted host and validate rate-limiting coverage.",
            "Tune automation policy thresholds for the affected attack pattern.",
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
    policy_mode = state["policy_decision"]["mode"]
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
- Policy Mode: {policy_mode}
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
  "automation": {{
    "policy_mode": "{policy_mode}",
    "execution_mode": "{state["action_result"].get("execution_mode", "")}"
  }},
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
    _trace(
        state,
        "Reporting Agent",
        "report",
        "Generated the final incident summary and recommendations.",
        {"report_id": state["incident_report"]["report_id"]},
    )
    return state


_detection_builder = StateGraph(AgentState)
_detection_builder.add_node("normalization", normalization)
_detection_builder.add_node("detection", detection)
_detection_builder.add_node("correlation_agent", correlation)
_detection_builder.add_node("threat_classification", threat_classification)
_detection_builder.add_node("investigation_agent", investigation)
_detection_builder.add_node("threat_resolve", threat_resolve)
_detection_builder.add_node("policy", policy)
_detection_builder.set_entry_point("normalization")
_detection_builder.add_edge("normalization", "detection")
_detection_builder.add_edge("detection", "correlation_agent")
_detection_builder.add_edge("correlation_agent", "threat_classification")
_detection_builder.add_edge("threat_classification", "investigation_agent")
_detection_builder.add_edge("investigation_agent", "threat_resolve")
_detection_builder.add_edge("threat_resolve", "policy")
_detection_builder.add_edge("policy", END)
detection_graph = _detection_builder.compile()

_action_builder = StateGraph(AgentState)
_action_builder.add_node("action", action)
_action_builder.add_node("report", report)
_action_builder.set_entry_point("action")
_action_builder.add_edge("action", "report")
_action_builder.add_edge("report", END)
action_graph = _action_builder.compile()
