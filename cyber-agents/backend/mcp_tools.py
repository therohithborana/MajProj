import json
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
from otel_runtime import otel_runtime


@dataclass(frozen=True)
class McpTool:
    name: str
    title: str
    description: str
    input_schema: dict
    output_schema: dict
    owner_agent: str
    handler: Callable


TOOLS = [
    McpTool(
        name="telemetry.normalize_events",
        title="Normalize Events",
        description="Transform raw collector payloads into the shared CyberAgent telemetry schema.",
        input_schema={"type": "object", "properties": {"state": {"type": "object"}}, "required": ["state"]},
        output_schema={"type": "object", "properties": {"state": {"type": "object"}}},
        owner_agent="Telemetry Agent",
        handler=normalization,
    ),
    McpTool(
        name="telemetry.detect_threats",
        title="Detect Threats",
        description="Run first-pass threat triage across normalized access, auth, and network data.",
        input_schema={"type": "object", "properties": {"state": {"type": "object"}}, "required": ["state"]},
        output_schema={"type": "object", "properties": {"state": {"type": "object"}}},
        owner_agent="Detection Agent",
        handler=detection,
    ),
    McpTool(
        name="telemetry.correlate_evidence",
        title="Correlate Evidence",
        description="Group suspicious activity into a single incident storyline.",
        input_schema={"type": "object", "properties": {"state": {"type": "object"}}, "required": ["state"]},
        output_schema={"type": "object", "properties": {"state": {"type": "object"}}},
        owner_agent="Detection Agent",
        handler=correlation,
    ),
    McpTool(
        name="analysis.classify_threat",
        title="Classify Threat",
        description="Classify the likely attack type and calculate confidence and risk.",
        input_schema={"type": "object", "properties": {"state": {"type": "object"}}, "required": ["state"]},
        output_schema={"type": "object", "properties": {"state": {"type": "object"}}},
        owner_agent="Analysis Agent",
        handler=threat_classification,
    ),
    McpTool(
        name="analysis.investigate_incident",
        title="Investigate Incident",
        description="Build an analyst-ready incident brief from classification and evidence.",
        input_schema={"type": "object", "properties": {"state": {"type": "object"}}, "required": ["state"]},
        output_schema={"type": "object", "properties": {"state": {"type": "object"}}},
        owner_agent="Analysis Agent",
        handler=investigation,
    ),
    McpTool(
        name="response.plan_mitigation",
        title="Plan Mitigation",
        description="Generate a mitigation strategy and containment playbook.",
        input_schema={"type": "object", "properties": {"state": {"type": "object"}}, "required": ["state"]},
        output_schema={"type": "object", "properties": {"state": {"type": "object"}}},
        owner_agent="Response Agent",
        handler=threat_resolve,
    ),
    McpTool(
        name="response.review_policy",
        title="Review Policy",
        description="Apply automation policy and determine whether response is autonomous or human-approved.",
        input_schema={"type": "object", "properties": {"state": {"type": "object"}}, "required": ["state"]},
        output_schema={"type": "object", "properties": {"state": {"type": "object"}}},
        owner_agent="Response Agent",
        handler=policy,
    ),
    McpTool(
        name="response.execute_action",
        title="Execute Action",
        description="Execute or escalate the response path according to approval state.",
        input_schema={"type": "object", "properties": {"state": {"type": "object"}}, "required": ["state"]},
        output_schema={"type": "object", "properties": {"state": {"type": "object"}}},
        owner_agent="Action Agent",
        handler=action,
    ),
    McpTool(
        name="response.generate_report",
        title="Generate Report",
        description="Produce the final incident summary and recommendations.",
        input_schema={"type": "object", "properties": {"state": {"type": "object"}}, "required": ["state"]},
        output_schema={"type": "object", "properties": {"state": {"type": "object"}}},
        owner_agent="Action Agent",
        handler=report,
    ),
]

TOOLS_BY_NAME = {tool.name: tool for tool in TOOLS}

DETECTION_PLAN = [
    "telemetry.normalize_events",
    "telemetry.detect_threats",
    "telemetry.correlate_evidence",
    "analysis.classify_threat",
    "analysis.investigate_incident",
    "response.plan_mitigation",
    "response.review_policy",
]

RESOLUTION_PLAN = [
    "response.execute_action",
    "response.generate_report",
]


def _state_summary(state: dict) -> dict:
    classification = state.get("classification") or {}
    attack = classification.get("attack") or {}
    policy_decision = state.get("policy_decision") or {}
    return serialize_document(
        {
            "current_stage": state.get("current_stage"),
            "approval_status": state.get("approval_status"),
            "attack_id": (state.get("simulation") or {}).get("attack_id"),
            "classification": {
                "predicted_class": classification.get("predicted_class"),
                "severity": attack.get("severity"),
                "risk_score": classification.get("risk_score"),
                "confidence_source": classification.get("confidence_source"),
            },
            "policy": {
                "mode": policy_decision.get("mode"),
                "reason": policy_decision.get("reason"),
            },
            "report_id": (state.get("incident_report") or {}).get("report_id"),
        }
    )


class McpToolRuntime:
    def list_tools(self) -> list[dict]:
        return [
            {
                "name": tool.name,
                "title": tool.title,
                "description": tool.description,
                "inputSchema": tool.input_schema,
                "outputSchema": tool.output_schema,
            }
            for tool in TOOLS
        ]

    def call_tool(self, name: str, arguments: dict) -> dict:
        tool = TOOLS_BY_NAME.get(name)
        if not tool:
            raise KeyError(name)
        state = deepcopy(arguments.get("state") or {})
        next_state = otel_runtime.trace_tool_execution(tool.name, tool.owner_agent, state, tool.handler)
        summary = _state_summary(next_state)
        return {
            "content": [{"type": "text", "text": json.dumps(summary, ensure_ascii=False)}],
            "structuredContent": {
                "state": serialize_document(next_state),
                "summary": summary,
            },
            "isError": False,
        }


class McpMultiAgentCoordinator:
    def __init__(self):
        self.runtime = McpToolRuntime()

    def run_detection_pipeline(self, state: dict) -> dict:
        current = deepcopy(state)
        tool_trace = list(current.get("tool_trace", []))
        for tool_name in DETECTION_PLAN:
            before = deepcopy(current)
            result = self.runtime.call_tool(tool_name, {"state": current})
            current = result["structuredContent"]["state"]
            current["tool_trace"] = tool_trace + [
                {
                    "tool": tool_name,
                    "agent": TOOLS_BY_NAME[tool_name].owner_agent,
                    "input_summary": _state_summary(before),
                    "output_summary": result["structuredContent"]["summary"],
                }
            ]
            tool_trace = list(current["tool_trace"])
        current.setdefault("runtime_metadata", {}).update(self.runtime_metadata())
        return current

    def run_resolution_pipeline(self, state: dict) -> dict:
        current = deepcopy(state)
        tool_trace = list(current.get("tool_trace", []))
        for tool_name in RESOLUTION_PLAN:
            before = deepcopy(current)
            result = self.runtime.call_tool(tool_name, {"state": current})
            current = result["structuredContent"]["state"]
            current["tool_trace"] = tool_trace + [
                {
                    "tool": tool_name,
                    "agent": TOOLS_BY_NAME[tool_name].owner_agent,
                    "input_summary": _state_summary(before),
                    "output_summary": result["structuredContent"]["summary"],
                }
            ]
            tool_trace = list(current["tool_trace"])
        current.setdefault("runtime_metadata", {}).update(self.runtime_metadata())
        return current

    def runtime_metadata(self) -> dict:
        return {
            "active_runtime": "mcp_tools",
            "mcp_endpoint": "http://localhost:8000/mcp",
            "tool_count": len(TOOLS),
            "multiagent_mode": "tool_orchestrated",
        }
