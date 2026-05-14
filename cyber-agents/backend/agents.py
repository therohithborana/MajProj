import json
import random
from collections import Counter, defaultdict
from typing import TypedDict

from langgraph.graph import END, StateGraph

from gemini_client import call_gemini


CLASS_LABELS = ["DDoS", "BruteForce", "PortScan", "SuspiciousRecon"]
SENSITIVE_PATH_TOKENS = ("/admin", "/.env", "phpmyadmin", "wp-admin", "server-status", "config", "backup")

CLASSIFIER_SYSTEM_PROMPT = """
You are the Threat Classification Agent in an AI cybersecurity platform.
Your role is to classify suspicious activity based on evidence from detection and correlation stages.
You must behave like a careful security analyst, not a marketing assistant.
Prefer conservative classifications, explicitly cite signals, and return strict JSON only.
""".strip()

INVESTIGATOR_SYSTEM_PROMPT = """
You are the Investigation Agent in an AI cybersecurity platform.
Your role is to transform classification output and evidence into an analyst-ready incident brief.
Focus on attacker behavior, affected assets, timeline, hypotheses, and next analyst actions.
Return strict JSON only.
""".strip()

POLICY_SYSTEM_PROMPT = """
You are the Policy Agent in an AI cybersecurity platform.
Your role is to decide whether a proposed response should be auto-executed, require human approval, or be manually escalated.
Optimize for operational safety, reversibility, blast radius, and confidence in the evidence.
Return strict JSON only.
""".strip()

RESPONSE_SYSTEM_PROMPT = """
You are the Response Planning Agent in an AI cybersecurity platform.
Your role is to propose safe, practical Linux mitigation commands for the observed attack.
Return strict JSON only.
""".strip()

REPORT_SYSTEM_PROMPT = """
You are the Reporting Agent in an AI cybersecurity platform.
Your role is to write a concise but professional incident report for analysts and stakeholders.
Return strict JSON only.
""".strip()


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
    agent_messages: list
    llm_usage: dict
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


def _record_message(
    state: AgentState,
    sender: str,
    recipient: str,
    subject: str,
    content: str,
    artifacts=None,
):
    messages = list(state.get("agent_messages", []))
    messages.append(
        {
            "from": sender,
            "to": recipient,
            "subject": subject,
            "content": content,
            "artifacts": artifacts or {},
        }
    )
    state["agent_messages"] = messages


def _mark_llm_usage(state: AgentState, agent: str, used: bool, runtime: str | None = None):
    usage = dict(state.get("llm_usage", {}))
    usage[agent] = {"used": used}
    if runtime:
        usage[agent]["runtime"] = runtime
    state["llm_usage"] = usage


def _normalize_scores(raw_scores, predicted_class):
    total = sum(max(raw_scores.get(label, 0.01), 0.01) for label in CLASS_LABELS)
    normalized = {
        label: round(max(raw_scores.get(label, 0.01), 0.01) / total, 4)
        for label in CLASS_LABELS
    }
    diff = round(1.0 - sum(normalized.values()), 4)
    normalized[predicted_class] = round(normalized[predicted_class] + diff, 4)
    return normalized


def _llm_json(system_prompt: str, task_prompt: str):
    combined_prompt = f"{system_prompt}\n\n{task_prompt}".strip()
    response = call_gemini(combined_prompt)
    return json.loads(_clean_json_payload(response))


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
        "normalization_brief": {
            "event_types": dict(event_counts),
            "source_count": len(unique_sources),
            "total_events": len(normalized_events),
        },
    }
    state["current_stage"] = "normalization"
    _trace(
        state,
        "Normalization Agent",
        "normalization",
        "Converted raw collector payloads into a shared event schema for downstream agents.",
        {"counts": dict(event_counts), "sources": len(unique_sources)},
    )
    _record_message(
        state,
        "Normalization Agent",
        "Detection Agent",
        "Normalized telemetry bundle",
        "Telemetry is normalized and grouped into access, auth, and network channels.",
        state["telemetry"]["normalization_brief"],
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
    max_failed_auth = max(failed_auth.values()) if failed_auth else 0
    request_burst = len(access_events)
    suspicious_path_hits = len(flagged_paths)
    dominant_target = target_counter.most_common(1)[0][0] if target_counter else "unknown"
    target_port = unique_ports[0] if unique_ports else 80

    candidate_labels = []
    if len(unique_src_ips) >= 10 and request_burst >= 20 and packet_total >= 100000:
        candidate_labels.append("DDoS")
    if max_failed_auth >= 10:
        candidate_labels.append("BruteForce")
    if scan_span >= 12:
        candidate_labels.append("PortScan")
    if suspicious_path_hits >= 6:
        candidate_labels.append("SuspiciousRecon")

    anomaly_type = "baseline"
    severity = "LOW"
    summary = "Observed activity remains within expected guardrails."

    if "DDoS" in candidate_labels:
        anomaly_type = "traffic_spike"
        severity = "CRITICAL"
        summary = "Distributed traffic spike indicates a DDoS-style service disruption attempt."
    elif "BruteForce" in candidate_labels:
        anomaly_type = "auth_failure_burst"
        severity = "HIGH"
        summary = "Repeated failed authentication attempts suggest credential abuse."
    elif "PortScan" in candidate_labels:
        anomaly_type = "sequential_port_probe"
        severity = "MEDIUM"
        summary = "A single source probed many ports in a short interval."
    elif "SuspiciousRecon" in candidate_labels:
        anomaly_type = "suspicious_path_recon"
        severity = "MEDIUM"
        summary = "Repeated access to sensitive paths indicates application reconnaissance."

    state["anomaly"] = {
        "anomaly_type": anomaly_type,
        "severity": severity,
        "summary": summary,
        "candidate_labels": candidate_labels or ["Baseline"],
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
        "heuristic_summary": {
            "unique_sources": len(unique_src_ips),
            "request_burst": request_burst,
            "failed_auth_attempts": max_failed_auth,
            "port_span": scan_span,
            "suspicious_path_hits": suspicious_path_hits,
        },
    }
    state["current_stage"] = "detection"
    _trace(
        state,
        "Detection Agent",
        "detection",
        summary,
        state["anomaly"]["heuristic_summary"],
    )
    _record_message(
        state,
        "Detection Agent",
        "Correlation Agent",
        "Detection brief",
        "Heuristic detections identified candidate attack labels and suspicious signals for correlation.",
        {
            "candidate_labels": state["anomaly"]["candidate_labels"],
            "primary_src_ip": primary_src_ip,
            "target_ip": dominant_target,
            "heuristics": state["anomaly"]["heuristic_summary"],
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
        "correlation_brief": {
            "event_count": len(correlated),
            "affected_paths": affected_paths,
            "affected_ports": affected_ports,
            "timeline_items": len(timeline),
        },
    }
    state["current_stage"] = "correlation"
    _trace(
        state,
        "Correlation Agent",
        "correlation",
        "Linked access, auth, and network signals into a shared attack narrative.",
        state["correlation"]["correlation_brief"],
    )
    _record_message(
        state,
        "Correlation Agent",
        "Threat Classification Agent",
        "Correlated evidence bundle",
        "Evidence has been grouped around the primary source and likely target.",
        state["correlation"]["correlation_brief"],
    )
    return state


def _heuristic_classification(anomaly: dict, telemetry: dict, state: AgentState):
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
    return predicted_class, confidence, confidence_scores, risk_score, severity, attack


def threat_classification(state: AgentState) -> AgentState:
    anomaly = state["anomaly"]
    telemetry = state["telemetry"]
    correlation_data = state["correlation"]

    predicted_class, confidence, confidence_scores, risk_score, severity, attack = _heuristic_classification(anomaly, telemetry, state)
    confidence_source = "heuristic"
    reasoning = [
        f"Candidate labels from detection: {', '.join(anomaly['candidate_labels'])}.",
        f"Primary source {attack['primary_src_ip']} generated correlated access/auth/network activity.",
    ]

    classifier_prompt = f"""
Classification request:
- Candidate labels: {anomaly["candidate_labels"]}
- Detection summary: {anomaly["summary"]}
- Unique sources: {len(anomaly["src_ips"])}
- Primary source: {anomaly["primary_src_ip"]}
- Target: {anomaly["target_ip"]}:{anomaly["target_port"]}
- Request burst: {anomaly["request_burst"]}
- Failed auth attempts: {anomaly["failed_auth_attempts"]}
- Port span: {anomaly["port_span"]}
- Suspicious path hits: {anomaly["suspicious_path_hits"]}
- Affected paths: {correlation_data["affected_paths"]}
- Affected ports: {correlation_data["affected_ports"]}
- Example timeline: {correlation_data["timeline"][:4]}

Return a JSON object with exactly this structure:
{{
  "predicted_class": "one of DDoS, BruteForce, PortScan, SuspiciousRecon",
  "confidence": 0.0,
  "severity": "LOW/HIGH/MEDIUM/CRITICAL",
  "reasoning": ["short reason 1", "short reason 2"],
  "key_indicators": ["indicator 1", "indicator 2", "indicator 3"],
  "confidence_scores": {{
    "DDoS": 0.0,
    "BruteForce": 0.0,
    "PortScan": 0.0,
    "SuspiciousRecon": 0.0
  }}
}}

Rules:
- confidence must be between 0 and 1
- confidence_scores must sum to about 1
- be conservative and evidence-based
- return JSON only
""".strip()

    try:
        parsed = _llm_json(CLASSIFIER_SYSTEM_PROMPT, classifier_prompt)
        llm_class = parsed["predicted_class"]
        llm_scores = _normalize_scores(parsed.get("confidence_scores", {}), llm_class)
        llm_conf = round(float(parsed["confidence"]), 4)
        predicted_class = llm_class if llm_class in CLASS_LABELS else predicted_class
        confidence_scores = llm_scores
        confidence = min(max(llm_conf, 0.0), 1.0)
        severity = parsed.get("severity", severity)
        confidence_source = "llm_reviewed"
        reasoning = parsed.get("reasoning", reasoning)
        _mark_llm_usage(state, "Threat Classification Agent", True, "direct_gemini")
    except Exception:
        _mark_llm_usage(state, "Threat Classification Agent", False)

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
    attack["attack_type"] = predicted_class
    attack["severity"] = severity

    key_indicators = [
        f"Observed {telemetry['total_events_observed']} events across access, auth, and network telemetry.",
        f"Primary source {attack['primary_src_ip']} appeared in {len(attack['src_ips'])} correlated source entries.",
        f"Risk score reached {risk_score} from authentication failures, request bursts, port spread, and path probes.",
        f"Dominant target {attack['target_ip']}:{attack['target_port']} matched the highest-risk activity cluster.",
    ]

    state["classification"] = {
        "predicted_class": predicted_class,
        "confidence": confidence,
        "confidence_source": confidence_source,
        "confidence_scores": confidence_scores,
        "reasoning": reasoning,
        "key_indicators": key_indicators,
        "risk_score": risk_score,
        "attack": attack,
        "classification_brief": {
            "predicted_class": predicted_class,
            "severity": severity,
            "confidence": confidence,
            "confidence_source": confidence_source,
            "risk_score": risk_score,
        },
    }
    state["current_stage"] = "classification"
    _trace(
        state,
        "Threat Classification Agent",
        "classification",
        f"Classified the incident as {predicted_class} with {round(confidence * 100, 1)}% confidence ({confidence_source}).",
        state["classification"]["classification_brief"],
    )
    _record_message(
        state,
        "Threat Classification Agent",
        "Investigation Agent",
        "Classification verdict",
        "The correlated evidence has been classified and is ready for analyst-style investigation.",
        state["classification"]["classification_brief"],
    )
    return state


def _fallback_investigation(state: AgentState):
    classification = state["classification"]
    anomaly = state["anomaly"]
    correlation_data = state["correlation"]
    attack = classification["attack"]
    return {
        "summary": f"{attack['attack_type']} activity impacted {attack['target_ip']}:{attack['target_port']}.",
        "affected_assets": [f"{attack['target_ip']}:{attack['target_port']}"],
        "attacker_profile": {
            "primary_src_ip": attack["primary_src_ip"],
            "src_ip_count": len(attack["src_ips"]),
            "behavior": anomaly["summary"],
        },
        "timeline": correlation_data["timeline"],
        "evidence": correlation_data["evidence_window"],
        "hypotheses": [
            "The attacker is testing exposed entry points before broader exploitation.",
            "The activity is coordinated enough to justify immediate containment review.",
        ],
        "recommended_owner": "security-team@company.com",
        "urgency": attack["severity"],
    }


def investigation(state: AgentState) -> AgentState:
    classification = state["classification"]
    anomaly = state["anomaly"]
    correlation_data = state["correlation"]
    attack = classification["attack"]
    fallback = _fallback_investigation(state)

    investigator_prompt = f"""
Investigation request:
- Attack type: {classification["predicted_class"]}
- Severity: {attack["severity"]}
- Confidence: {classification["confidence"]}
- Confidence source: {classification["confidence_source"]}
- Risk score: {classification["risk_score"]}
- Detection summary: {anomaly["summary"]}
- Correlation brief: {correlation_data["correlation_brief"]}
- Evidence timeline: {correlation_data["timeline"]}
- Evidence window: {correlation_data["evidence_window"]}

Return a JSON object with exactly this structure:
{{
  "summary": "one concise paragraph",
  "affected_assets": ["asset 1"],
  "attacker_profile": {{
    "primary_src_ip": "ip",
    "src_ip_count": 1,
    "behavior": "behavior summary"
  }},
  "timeline": [{{"timestamp": "...", "event_type": "...", "summary": "..."}}],
  "evidence": [{{"event_type": "...", "message": "..."}}],
  "hypotheses": ["hypothesis 1", "hypothesis 2"],
  "recommended_owner": "role or team",
  "urgency": "LOW/HIGH/MEDIUM/CRITICAL"
}}

Rules:
- keep timeline grounded in supplied evidence
- do not invent malware names
- return JSON only
""".strip()

    try:
        parsed = _llm_json(INVESTIGATOR_SYSTEM_PROMPT, investigator_prompt)
        state["investigation"] = {
            **fallback,
            **parsed,
            "timeline": parsed.get("timeline") or fallback["timeline"],
            "evidence": parsed.get("evidence") or fallback["evidence"],
        }
        _mark_llm_usage(state, "Investigation Agent", True, "direct_gemini")
    except Exception:
        state["investigation"] = fallback
        _mark_llm_usage(state, "Investigation Agent", False)

    state["current_stage"] = "investigation"
    _trace(
        state,
        "Investigation Agent",
        "investigation",
        "Compiled an analyst-style incident brief with evidence, timeline, and attacker profile.",
        {
            "affected_assets": state["investigation"]["affected_assets"],
            "hypotheses": state["investigation"].get("hypotheses", [])[:2],
        },
    )
    _record_message(
        state,
        "Investigation Agent",
        "Response Planning Agent",
        "Investigation brief",
        "Investigation has produced a contextual brief for mitigation planning.",
        {
            "summary": state["investigation"]["summary"],
            "affected_assets": state["investigation"]["affected_assets"],
            "urgency": state["investigation"].get("urgency"),
        },
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
    investigation_data = state["investigation"]
    prompt = f"""
Mitigation planning request:
- Attack Type: {attack["attack_type"]}
- Severity: {attack["severity"]}
- Source IP(s): {attack["src_ips"]}
- Target: {attack["target_ip"]}:{attack["target_port"]}
- Protocol: {attack["protocol"]}
- Packet Rate: {attack["packet_rate"]}/sec
- Detection Confidence: {round(classification["confidence"] * 100, 2)}%
- Confidence Source: {classification["confidence_source"]}
- Risk Score: {classification["risk_score"]}/100
- Investigation Summary: {investigation_data["summary"]}

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
- return JSON only
""".strip()

    fallback = _fallback_mitigation_plan(state)
    try:
        parsed = _llm_json(RESPONSE_SYSTEM_PROMPT, prompt)
        if not isinstance(parsed, dict) or "steps" not in parsed:
            raise ValueError("Invalid mitigation plan")
        state["mitigation_plan"] = parsed
        _mark_llm_usage(state, "Response Planning Agent", True, "direct_gemini")
    except Exception:
        state["mitigation_plan"] = fallback
        _mark_llm_usage(state, "Response Planning Agent", False)

    state["current_stage"] = "response_planning"
    _trace(
        state,
        "Response Planning Agent",
        "response_planning",
        "Drafted a containment plan and response playbook.",
        {"strategy": state["mitigation_plan"]["strategy"], "steps": len(state["mitigation_plan"].get("steps", []))},
    )
    _record_message(
        state,
        "Response Planning Agent",
        "Policy Agent",
        "Mitigation plan review",
        "Mitigation steps are ready for automation policy review.",
        {
            "strategy": state["mitigation_plan"]["strategy"],
            "collateral_risk": state["mitigation_plan"]["collateral_risk"],
            "steps": len(state["mitigation_plan"].get("steps", [])),
        },
    )
    return state


def _fallback_policy_decision(state: AgentState):
    classification = state["classification"]
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
    return mode, reason


def policy(state: AgentState) -> AgentState:
    classification = state["classification"]
    mitigation_plan = state["mitigation_plan"]
    investigation_data = state["investigation"]
    attack = classification["attack"]

    mode, reason = _fallback_policy_decision(state)
    policy_prompt = f"""
Policy review request:
- Attack type: {attack["attack_type"]}
- Severity: {attack["severity"]}
- Confidence: {classification["confidence"]}
- Confidence source: {classification["confidence_source"]}
- Risk score: {classification["risk_score"]}
- Investigation urgency: {investigation_data.get("urgency")}
- Investigation summary: {investigation_data["summary"]}
- Mitigation strategy: {mitigation_plan["strategy"]}
- Collateral risk: {mitigation_plan["collateral_risk"]}
- Steps: {mitigation_plan["steps"]}

Return a JSON object with exactly this structure:
{{
  "mode": "auto_execute or approval_required or manual_escalation",
  "reason": "one concise sentence",
  "safety_notes": ["note 1", "note 2"],
  "requires_human_review": true
}}

Rules:
- prefer auto_execute only for clearly reversible low-blast-radius actions
- approval_required is appropriate for customer-facing service impact
- manual_escalation is appropriate for ambiguous or high-uncertainty cases
- return JSON only
""".strip()

    safety_notes = []
    decision_source = "heuristic"
    try:
        parsed = _llm_json(POLICY_SYSTEM_PROMPT, policy_prompt)
        mode = parsed.get("mode", mode)
        if mode not in {"auto_execute", "approval_required", "manual_escalation"}:
            mode = mode
        reason = parsed.get("reason", reason)
        safety_notes = parsed.get("safety_notes", [])
        decision_source = "llm_reviewed"
        _mark_llm_usage(state, "Policy Agent", True, "direct_gemini")
    except Exception:
        _mark_llm_usage(state, "Policy Agent", False)

    state["policy_decision"] = {
        "mode": mode,
        "reason": reason,
        "decision_source": decision_source,
        "auto_execute": mode == "auto_execute",
        "safe_actions": [step["action"] for step in mitigation_plan.get("steps", []) if step.get("reversible")],
        "safety_notes": safety_notes,
    }
    state["approval_status"] = (
        "auto_approved" if mode == "auto_execute" else "pending" if mode == "approval_required" else "manual_required"
    )
    state["current_stage"] = "policy_decision"
    _trace(
        state,
        "Policy Agent",
        "policy_decision",
        f"Selected {mode} based on risk, reversibility, blast radius, and review context.",
        {"reason": reason, "decision_source": decision_source},
    )
    _record_message(
        state,
        "Policy Agent",
        "Action Agent",
        "Policy verdict",
        "Policy review has determined the action path for containment.",
        {
            "mode": mode,
            "reason": reason,
            "decision_source": decision_source,
        },
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
    _record_message(
        state,
        "Action Agent",
        "Reporting Agent",
        "Action outcome",
        "The response path has completed and is ready for incident reporting.",
        {
            "status": action_result["status"],
            "execution_mode": action_result["execution_mode"],
        },
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
            "confidence_source": classification["confidence_source"],
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
Incident report request:
- Attack Type: {attack["attack_type"]}
- Severity: {attack["severity"]}
- Source IP: {attack["primary_src_ip"]}
- Target: {attack["target_ip"]}:{attack["target_port"]}
- Detection Confidence: {round(classification["confidence"] * 100, 2)}%
- Confidence Source: {classification["confidence_source"]}
- Risk Score: {classification["risk_score"]}/100
- Resolution: {status}
- Policy Mode: {policy_mode}
- Steps Taken: {steps_taken}
- Investigation Summary: {state["investigation"]["summary"]}

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
    "confidence_source": "{classification["confidence_source"]}",
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

Return JSON only.
""".strip()

    fallback = _fallback_incident_report(state, resolved_in)
    try:
        parsed = _llm_json(REPORT_SYSTEM_PROMPT, prompt)
        if not isinstance(parsed, dict) or "executive_summary" not in parsed:
            raise ValueError("Invalid incident report")
        state["incident_report"] = parsed
        _mark_llm_usage(state, "Reporting Agent", True, "direct_gemini")
    except Exception:
        state["incident_report"] = fallback
        _mark_llm_usage(state, "Reporting Agent", False)

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
