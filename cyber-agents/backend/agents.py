import json
import random
from typing import TypedDict

from langgraph.graph import END, StateGraph

from gemini_client import call_gemini


class AgentState(TypedDict, total=False):
    attack: dict
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


def _normalize_scores(raw_scores, predicted_class):
    classes = ["DDoS", "BruteForce", "PortScan"]
    if not isinstance(raw_scores, dict):
        raw_scores = {}

    scores = {}
    for label in classes:
        value = raw_scores.get(label, random.uniform(0.05, 0.9))
        try:
            scores[label] = max(float(value), 0.01)
        except (TypeError, ValueError):
            scores[label] = random.uniform(0.05, 0.9)

    max_label = max(scores, key=scores.get)
    if max_label != predicted_class:
        scores[predicted_class] = max(scores.values()) + 0.05

    total = sum(scores.values()) or 1.0
    normalized = {label: round(scores[label] / total, 4) for label in classes}
    diff = round(1.0 - sum(normalized.values()), 4)
    normalized[predicted_class] = round(normalized[predicted_class] + diff, 4)
    return normalized


def threat_detection(state: AgentState) -> AgentState:
    attack = state["attack"]
    predicted_class = attack["attack_type"]
    confidence = round(random.uniform(0.82, 0.99), 4)

    base_scores = {
        "DDoS": random.uniform(0.02, 0.2),
        "BruteForce": random.uniform(0.02, 0.2),
        "PortScan": random.uniform(0.02, 0.2),
    }
    base_scores[predicted_class] = confidence
    confidence_scores = _normalize_scores(base_scores, predicted_class)
    risk_score = min(
        100,
        max(
            0,
            int(
                confidence * 100
                + (15 if attack["severity"] == "CRITICAL" else 8 if attack["severity"] == "HIGH" else 3)
            ),
        ),
    )

    key_indicators = [
        f"Traffic pattern aligned with the {predicted_class} pattern observed in this incident.",
        f"Observed packet rate of {attack['packet_rate']}/sec exceeded the baseline for {attack['target_ip']}.",
        f"Protocol {attack['protocol']} activity and destination port {attack['target_port']} aligned with the predicted class.",
        f"Source distribution from {len(attack['src_ips'])} host(s) increased the calculated risk score to {risk_score}.",
    ]

    state["classification"] = {
        "predicted_class": predicted_class,
        "confidence": confidence,
        "confidence_scores": confidence_scores,
        "key_indicators": key_indicators,
        "risk_score": risk_score,
    }
    state["current_stage"] = "threat_detected"
    return state


def _fallback_mitigation_plan(state: AgentState):
    attack = state["attack"]
    primary_ip = attack["primary_src_ip"]
    target_port = attack["target_port"]
    return {
        "strategy": f"Contain {attack['attack_type']} traffic",
        "estimated_mitigation_time": "12 minutes",
        "collateral_risk": "MEDIUM - Blocking malicious traffic may briefly affect adjacent services sharing the same exposure path.",
        "steps": [
            {
                "step": 1,
                "action": "Block source IP",
                "command": f"iptables -A INPUT -s {primary_ip} -j DROP",
                "impact": "Drops packets from the primary hostile source immediately at the host firewall.",
                "reversible": True,
            },
            {
                "step": 2,
                "action": "Rate limit target service",
                "command": f"ufw limit {target_port}/tcp",
                "impact": "Reduces abusive connection volume against the targeted port.",
                "reversible": True,
            },
            {
                "step": 3,
                "action": "Ban repeated offenders",
                "command": f"fail2ban-client set sshd banip {primary_ip}",
                "impact": "Applies a temporary ban to the suspicious source using the host intrusion prevention service.",
                "reversible": True,
            },
        ],
    }


def threat_resolve(state: AgentState) -> AgentState:
    attack = state["attack"]
    classification = state["classification"]
    prompt = f"""
You are a senior cybersecurity engineer. An attack has been detected with the following details:

Attack Type: {attack["attack_type"]}
Severity: {attack["severity"]}
Source IP(s): {attack["src_ips"]}
Target: {attack["target_ip"]}:{attack["target_port"]}
Protocol: {attack["protocol"]}
Packet Rate: {attack["packet_rate"]}/sec
ML Model Confidence: {round(classification["confidence"] * 100, 2)}%
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


def _fallback_incident_report(state: AgentState, status: str, resolved_in: int):
    attack = state["attack"]
    classification = state["classification"]
    return {
        "report_id": f"INC-{attack['attack_id']}",
        "executive_summary": (
            f"A {attack['severity']} {attack['attack_type']} incident targeting {attack['target_ip']}:{attack['target_port']} "
            f"was detected and processed by CyberAgent. The event concluded with status {status}, with follow-up recommendations "
            "generated for the security team."
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
            "Review perimeter filtering rules for the targeted service.",
            "Tune alert thresholds using the observed indicators from this incident.",
            "Conduct a post-incident validation sweep across adjacent hosts.",
        ],
        "timeline": {
            "detected": attack["timestamp"],
            "classified": "T+1.2s",
            "plan_generated": "T+3.5s",
            "resolved": f"T+{resolved_in}s",
        },
    }


def action(state: AgentState) -> AgentState:
    attack = state["attack"]
    mitigation_plan = state.get("mitigation_plan", {})
    decision = state.get("approval_status")

    if decision == "approved":
        executed_steps = []
        total_execution_time_ms = 0
        for step in mitigation_plan.get("steps", []):
            execution_time_ms = random.randint(50, 400)
            total_execution_time_ms += execution_time_ms
            executed_steps.append(
                {
                    **step,
                    "status": "EXECUTED",
                    "execution_time_ms": execution_time_ms,
                }
            )

        status = "MITIGATED"
        action_result = {
            "status": status,
            "steps_executed": executed_steps,
            "total_execution_time_ms": total_execution_time_ms,
            "blocked_ips": attack["src_ips"],
        }
        state["current_stage"] = "mitigated"
    else:
        status = "MANUAL_INTERVENTION_REQUIRED"
        action_result = {
            "status": status,
            "ticket_id": f"SEC-{attack['attack_id']}",
            "assigned_to": "security-team@company.com",
        }
        state["current_stage"] = "manual_queue"

    state["action_result"] = action_result

    resolved_in = random.randint(8, 30)
    classification = state["classification"]
    steps_taken = len(action_result.get("steps_executed", []))
    prompt = f"""
You are a cybersecurity incident reporter. Write a concise professional incident report summary.

Incident Details:
- Attack Type: {attack["attack_type"]}
- Severity: {attack["severity"]}
- Source IP: {attack["primary_src_ip"]}
- Target: {attack["target_ip"]}:{attack["target_port"]}
- ML Confidence: {round(classification["confidence"] * 100, 2)}%
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

    fallback = _fallback_incident_report(state, status, resolved_in)
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
_detection_builder.add_node("threat_detection", threat_detection)
_detection_builder.add_node("threat_resolve", threat_resolve)
_detection_builder.set_entry_point("threat_detection")
_detection_builder.add_edge("threat_detection", "threat_resolve")
_detection_builder.add_edge("threat_resolve", END)
detection_graph = _detection_builder.compile()

_action_builder = StateGraph(AgentState)
_action_builder.add_node("action", action)
_action_builder.set_entry_point("action")
_action_builder.add_edge("action", END)
action_graph = _action_builder.compile()
