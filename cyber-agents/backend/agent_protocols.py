import json
import uuid
from copy import deepcopy
from dataclasses import dataclass
from typing import Callable

from agents import (
    action,
    correlation,
    detection,
    investigation,
    normalization,
    policy,
    report,
    threat_classification,
    threat_resolve,
)
from models import serialize_document


ADK_RUNTIME_NAME = "google-adk-compatible"
AGUI_CONTENT_TYPE = "text/event-stream"
AGUI_EVENT_TYPES = {
    "run_started": "RUN_STARTED",
    "run_finished": "RUN_FINISHED",
    "run_error": "RUN_ERROR",
    "text_message_start": "TEXT_MESSAGE_START",
    "text_message_content": "TEXT_MESSAGE_CONTENT",
    "text_message_end": "TEXT_MESSAGE_END",
    "tool_call_start": "TOOL_CALL_START",
    "tool_call_args": "TOOL_CALL_ARGS",
    "tool_call_end": "TOOL_CALL_END",
    "tool_call_result": "TOOL_CALL_RESULT",
    "state_snapshot": "STATE_SNAPSHOT",
    "state_delta": "STATE_DELTA",
}


@dataclass(frozen=True)
class AgentDescriptor:
    public_name: str
    state_key: str
    description: str
    instruction_focus: str
    input_contract: dict
    output_contract: dict
    handler: Callable


AGENT_DESCRIPTORS = [
    AgentDescriptor(
        public_name="normalization_agent",
        state_key="normalization",
        description="Transforms collector payloads into the platform's canonical telemetry schema.",
        instruction_focus="Normalize raw access, auth, and network records without inventing evidence.",
        input_contract={"requires": ["simulation.events"]},
        output_contract={"writes": ["telemetry", "agent_trace", "agent_messages"]},
        handler=normalization,
    ),
    AgentDescriptor(
        public_name="detection_agent",
        state_key="detection",
        description="Runs first-pass threat triage over normalized telemetry.",
        instruction_focus="Detect brute force, traffic spikes, port scans, and suspicious recon conservatively.",
        input_contract={"requires": ["telemetry"]},
        output_contract={"writes": ["anomaly", "agent_trace", "agent_messages"]},
        handler=detection,
    ),
    AgentDescriptor(
        public_name="correlation_agent",
        state_key="correlation",
        description="Correlates access, auth, and network signals into one evidence bundle.",
        instruction_focus="Group related events into one storyline tied to the most suspicious actor.",
        input_contract={"requires": ["telemetry", "anomaly"]},
        output_contract={"writes": ["correlation", "agent_trace", "agent_messages"]},
        handler=correlation,
    ),
    AgentDescriptor(
        public_name="classification_agent",
        state_key="classification",
        description="Classifies the attack type and assigns confidence and risk context.",
        instruction_focus="Map correlated evidence to an attack category with justified confidence and severity.",
        input_contract={"requires": ["anomaly", "correlation"]},
        output_contract={"writes": ["classification", "agent_trace", "agent_messages"]},
        handler=threat_classification,
    ),
    AgentDescriptor(
        public_name="investigation_agent",
        state_key="investigation",
        description="Builds the analyst brief, attacker profile, and incident timeline.",
        instruction_focus="Prepare an evidence-grounded investigation brief for the response team.",
        input_contract={"requires": ["classification", "correlation"]},
        output_contract={"writes": ["investigation", "agent_trace", "agent_messages"]},
        handler=investigation,
    ),
    AgentDescriptor(
        public_name="response_planning_agent",
        state_key="response_planning",
        description="Drafts a practical containment plan and mitigation steps.",
        instruction_focus="Produce reversible Linux-focused response steps when possible.",
        input_contract={"requires": ["classification", "investigation"]},
        output_contract={"writes": ["mitigation_plan", "agent_trace", "agent_messages"]},
        handler=threat_resolve,
    ),
    AgentDescriptor(
        public_name="policy_agent",
        state_key="policy_decision",
        description="Applies automation guardrails to decide whether response is autonomous or human-approved.",
        instruction_focus="Optimize for reversibility, blast radius, and evidence quality.",
        input_contract={"requires": ["classification", "mitigation_plan", "investigation"]},
        output_contract={"writes": ["policy_decision", "approval_status", "agent_trace", "agent_messages"]},
        handler=policy,
    ),
    AgentDescriptor(
        public_name="action_agent",
        state_key="action",
        description="Executes the approved containment path or escalates to manual response.",
        instruction_focus="Apply the selected containment mode and record the execution outcome.",
        input_contract={"requires": ["policy_decision", "approval_status", "mitigation_plan"]},
        output_contract={"writes": ["action_result", "agent_trace", "agent_messages"]},
        handler=action,
    ),
    AgentDescriptor(
        public_name="reporting_agent",
        state_key="report",
        description="Produces the final incident report and recommendations.",
        instruction_focus="Summarize what happened, how it was handled, and what should happen next.",
        input_contract={"requires": ["classification", "investigation", "action_result"]},
        output_contract={"writes": ["incident_report", "agent_trace"]},
        handler=report,
    ),
]

AGENT_REGISTRY = {descriptor.public_name: descriptor for descriptor in AGENT_DESCRIPTORS}

DETECTION_SEQUENCE = [
    "normalization_agent",
    "detection_agent",
    "correlation_agent",
    "classification_agent",
    "investigation_agent",
    "response_planning_agent",
    "policy_agent",
]

RESOLUTION_SEQUENCE = [
    "action_agent",
    "reporting_agent",
]


def _state_summary(state: dict) -> dict:
    classification = state.get("classification") or {}
    policy_decision = state.get("policy_decision") or {}
    attack = classification.get("attack") or {}
    report_data = state.get("incident_report") or {}
    simulation = state.get("simulation") or {}
    return serialize_document(
        {
            "current_stage": state.get("current_stage"),
            "approval_status": state.get("approval_status"),
            "attack_id": simulation.get("attack_id"),
            "classification": {
                "predicted_class": classification.get("predicted_class"),
                "severity": attack.get("severity"),
                "risk_score": classification.get("risk_score"),
                "confidence": classification.get("confidence"),
                "confidence_source": classification.get("confidence_source"),
            },
            "policy": {
                "mode": policy_decision.get("mode"),
                "reason": policy_decision.get("reason"),
                "decision_source": policy_decision.get("decision_source"),
            },
            "report_id": report_data.get("report_id"),
        }
    )


def _stage_delta(state: dict, descriptor: AgentDescriptor) -> list[dict]:
    summary = _state_summary(state)
    delta = [
        {"op": "replace", "path": "/currentStage", "value": summary.get("current_stage")},
        {"op": "replace", "path": "/approvalStatus", "value": summary.get("approval_status")},
        {"op": "replace", "path": "/lastAgent", "value": descriptor.public_name},
    ]
    state_key = descriptor.state_key
    if state_key == "classification":
        delta.append(
            {
                "op": "replace",
                "path": "/classification",
                "value": summary.get("classification"),
            }
        )
    elif state_key == "policy_decision":
        delta.append({"op": "replace", "path": "/policy", "value": summary.get("policy")})
    elif state_key == "report":
        delta.append({"op": "replace", "path": "/reportId", "value": summary.get("report_id")})
    return delta


def _a2a_entry(caller: str, descriptor: AgentDescriptor, state_before: dict, state_after: dict) -> dict:
    return serialize_document(
        {
            "task_id": uuid.uuid4().hex,
            "protocol": "A2A",
            "runtime": ADK_RUNTIME_NAME,
            "from_agent": caller,
            "to_agent": descriptor.public_name,
            "input_contract": descriptor.input_contract,
            "output_contract": descriptor.output_contract,
            "input_summary": _state_summary(state_before),
            "output_summary": _state_summary(state_after),
            "state_delta": _stage_delta(state_after, descriptor),
            "status": "completed",
        }
    )


class SocA2ACoordinator:
    def __init__(self):
        self.root_agent = {
            "name": "soc_coordinator",
            "description": "Root ADK-style coordinator for the CyberAgent multi-agent SOC pipeline.",
            "protocol": "A2A",
            "runtime": ADK_RUNTIME_NAME,
            "sub_agents": DETECTION_SEQUENCE + RESOLUTION_SEQUENCE,
        }

    def agent_cards(self, base_url: str) -> list[dict]:
        cards = []
        for descriptor in AGENT_DESCRIPTORS:
            cards.append(
                {
                    "name": descriptor.public_name,
                    "description": descriptor.description,
                    "protocol": "A2A",
                    "runtime": ADK_RUNTIME_NAME,
                    "endpoint": f"{base_url}/a2a/agents/{descriptor.public_name}/invoke",
                    "agent_card": f"{base_url}/a2a/agents/{descriptor.public_name}/agent-card.json",
                    "instruction_focus": descriptor.instruction_focus,
                    "input_contract": descriptor.input_contract,
                    "output_contract": descriptor.output_contract,
                }
            )
        return cards

    def root_card(self, base_url: str) -> dict:
        return {
            **self.root_agent,
            "endpoint": f"{base_url}/a2a/soc_coordinator/run",
            "agent_card": f"{base_url}/a2a/soc_coordinator/agent-card.json",
        }

    def invoke_agent(self, agent_name: str, state: dict, caller: str = "soc_coordinator") -> dict:
        descriptor = AGENT_REGISTRY[agent_name]
        before = deepcopy(state)
        next_state = descriptor.handler(state)
        protocol_trace = list(next_state.get("protocol_trace", []))
        protocol_trace.append(_a2a_entry(caller, descriptor, before, next_state))
        next_state["protocol_trace"] = protocol_trace
        next_state["runtime_metadata"] = self._runtime_metadata()
        return next_state

    def run_detection_pipeline(self, state: dict) -> dict:
        current = deepcopy(state)
        caller = self.root_agent["name"]
        for agent_name in DETECTION_SEQUENCE:
            current = self.invoke_agent(agent_name, current, caller)
            caller = agent_name
        return current

    def run_resolution_pipeline(self, state: dict) -> dict:
        current = deepcopy(state)
        caller = "policy_agent"
        for agent_name in RESOLUTION_SEQUENCE:
            current = self.invoke_agent(agent_name, current, caller)
            caller = agent_name
        return current

    def _runtime_metadata(self) -> dict:
        return {
            "root_agent": self.root_agent["name"],
            "runtime": ADK_RUNTIME_NAME,
            "transport": "local_a2a_loopback",
            "supported_protocols": ["A2A", "AG-UI"],
            "adk_mode": "phase_1_compatible_runtime",
        }


def build_agui_snapshot(incident: dict) -> dict:
    classification = incident.get("classification", {})
    attack = classification.get("attack", {})
    return serialize_document(
        {
            "incidentId": incident.get("attack_id") or incident.get("simulation", {}).get("attack_id"),
            "currentStage": incident.get("current_stage"),
            "approvalStatus": incident.get("approval_status"),
            "attackType": classification.get("predicted_class"),
            "severity": attack.get("severity"),
            "riskScore": classification.get("risk_score"),
            "policyMode": incident.get("policy_decision", {}).get("mode"),
            "reportId": incident.get("incident_report", {}).get("report_id"),
            "runtime": incident.get("runtime_metadata", {}),
        }
    )


def agui_sse(event: dict) -> str:
    return f"data: {json.dumps(serialize_document(event), ensure_ascii=False)}\n\n"


def build_agui_event_stream(incident: dict, thread_id: str, run_id: str) -> list[dict]:
    incident_id = incident.get("attack_id") or incident.get("simulation", {}).get("attack_id")
    snapshot = build_agui_snapshot(incident)
    events = [
        {
            "type": AGUI_EVENT_TYPES["run_started"],
            "threadId": thread_id,
            "runId": run_id,
            "agentName": "soc_coordinator",
        },
        {
            "type": AGUI_EVENT_TYPES["state_snapshot"],
            "snapshot": snapshot,
        },
    ]

    parent_message_id = f"incident-{incident_id}"
    for index, trace in enumerate(incident.get("protocol_trace", []), start=1):
        tool_call_id = trace["task_id"]
        events.extend(
            [
                {
                    "type": AGUI_EVENT_TYPES["tool_call_start"],
                    "toolCallId": tool_call_id,
                    "toolCallName": trace["to_agent"],
                    "parentMessageId": parent_message_id,
                },
                {
                    "type": AGUI_EVENT_TYPES["tool_call_args"],
                    "toolCallId": tool_call_id,
                    "delta": json.dumps(trace.get("input_summary", {}), ensure_ascii=False),
                },
                {
                    "type": AGUI_EVENT_TYPES["tool_call_end"],
                    "toolCallId": tool_call_id,
                },
                {
                    "type": AGUI_EVENT_TYPES["tool_call_result"],
                    "messageId": f"{parent_message_id}-tool-{index}",
                    "toolCallId": tool_call_id,
                    "content": json.dumps(trace.get("output_summary", {}), ensure_ascii=False),
                    "role": "tool",
                },
                {
                    "type": AGUI_EVENT_TYPES["state_delta"],
                    "delta": trace.get("state_delta", []),
                },
            ]
        )

    message_id = f"{parent_message_id}-summary"
    summary = (
        incident.get("incident_report", {}).get("executive_summary")
        or incident.get("policy_decision", {}).get("reason")
        or incident.get("anomaly", {}).get("summary")
        or "Incident processed by the CyberAgent multi-agent runtime."
    )
    events.extend(
        [
            {
                "type": AGUI_EVENT_TYPES["text_message_start"],
                "messageId": message_id,
                "role": "assistant",
            },
            {
                "type": AGUI_EVENT_TYPES["text_message_content"],
                "messageId": message_id,
                "delta": summary,
            },
            {
                "type": AGUI_EVENT_TYPES["text_message_end"],
                "messageId": message_id,
            },
            {
                "type": AGUI_EVENT_TYPES["run_finished"],
                "threadId": thread_id,
                "runId": run_id,
            },
        ]
    )
    return events
