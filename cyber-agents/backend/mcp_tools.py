import json
from copy import deepcopy
from dataclasses import dataclass
from typing import Callable

from agents import (
    CLASSIFIER_SYSTEM_PROMPT,
    CHALLENGE_SYSTEM_PROMPT,
    REPORT_SYSTEM_PROMPT,
    RESPONSE_SYSTEM_PROMPT,
    action,
    challenge_review,
    correlation,
    detection,
    normalization,
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
        name="analysis.challenge_classification",
        title="Challenge Classification",
        description="Critique the primary classifier and assess false-positive risk or alternative interpretations.",
        input_schema={"type": "object", "properties": {"state": {"type": "object"}}, "required": ["state"]},
        output_schema={"type": "object", "properties": {"state": {"type": "object"}}},
        owner_agent="Challenge Agent",
        handler=challenge_review,
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

LLM_AGENT_BY_TOOL = {
    "analysis.classify_threat": "Threat Classification Agent",
    "analysis.challenge_classification": "Challenge Agent",
    "response.plan_mitigation": "Response Planning Agent",
    "response.generate_report": "Reporting Agent",
}

TOOL_PROMPT_PROFILE = {
    "analysis.classify_threat": {
        "agent": "Threat Classification Agent",
        "system_prompt": CLASSIFIER_SYSTEM_PROMPT,
        "purpose": "Classify the suspicious activity conservatively from correlated evidence.",
    },
    "analysis.challenge_classification": {
        "agent": "Challenge Agent",
        "system_prompt": CHALLENGE_SYSTEM_PROMPT,
        "purpose": "Challenge the primary classifier and estimate false-positive risk.",
    },
    "response.plan_mitigation": {
        "agent": "Response Planning Agent",
        "system_prompt": RESPONSE_SYSTEM_PROMPT,
        "purpose": "Draft safe Linux containment and remediation steps.",
    },
    "response.generate_report": {
        "agent": "Reporting Agent",
        "system_prompt": REPORT_SYSTEM_PROMPT,
        "purpose": "Write a concise professional incident report for analysts.",
    },
}

DETECTION_PLAN = [
    "telemetry.normalize_events",
    "telemetry.detect_threats",
    "telemetry.correlate_evidence",
    "analysis.classify_threat",
    "analysis.challenge_classification",
    "response.plan_mitigation",
]

RESOLUTION_PLAN = [
    "response.execute_action",
    "response.generate_report",
]

PLANNER_SYSTEM_PROMPT = """
You are the SOC Coordinator Agent for CyberAgent.
Your role is to orchestrate specialist agents over MCP tools based on the current incident state.
Choose the single next tool that best advances the investigation or response.
You may skip redundant steps when the state already contains what the next agent needs.
Return strict JSON only.
""".strip()


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
                "ownerAgent": tool.owner_agent,
                "promptProfile": TOOL_PROMPT_PROFILE.get(tool.name, {}),
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
                "promptProfile": TOOL_PROMPT_PROFILE.get(name, {}),
            },
            "isError": False,
        }


class McpMultiAgentCoordinator:
    def __init__(self):
        self.runtime = McpToolRuntime()

    def _choose_next_tool(self, state: dict, pending_tools: list[str], phase: str) -> tuple[str, str, bool]:
        fallback_tool = pending_tools[0]
        classification = (state.get("classification") or {})
        confidence = float(classification.get("confidence") or 0.0)
        if (
            "analysis.challenge_classification" in pending_tools
            and confidence >= 0.9
            and phase == "detection"
        ):
            return (
                "analysis.challenge_classification",
                "Coordinator is closing out the bounded detection workflow with a final challenge review before response planning.",
                False,
            )
        if fallback_tool.startswith("telemetry."):
            reason = "Coordinator is advancing the bounded telemetry pipeline from normalization through correlation."
        elif fallback_tool.startswith("analysis."):
            reason = "Coordinator is advancing the bounded analysis pipeline from classification through challenge review."
        else:
            reason = "Coordinator is advancing the bounded response pipeline from planning through policy and execution."
        return fallback_tool, reason, False

    def _run_plan(self, state: dict, plan: list[str], phase: str, progress_callback: Callable = None) -> dict:
        current = deepcopy(state)
        tool_trace = list(current.get("tool_trace", []))
        pending_tools = list(plan)
        planner_trace = list((current.get("runtime_metadata") or {}).get("planner_trace") or [])
        while pending_tools:
            tool_name, reason, skip_challenge = self._choose_next_tool(current, pending_tools, phase)
            if skip_challenge and "analysis.challenge_classification" in pending_tools:
                pending_tools.remove("analysis.challenge_classification")
            if tool_name not in pending_tools:
                tool_name = pending_tools[0]
            pending_tools.remove(tool_name)
            before = deepcopy(current)
            result = self.runtime.call_tool(tool_name, {"state": current})
            current = result["structuredContent"]["state"]
            llm_agent = LLM_AGENT_BY_TOOL.get(tool_name)
            llm_usage = (current.get("llm_usage") or {}).get(llm_agent, {}) if llm_agent else {}
            planner_trace.append({"phase": phase, "tool": tool_name, "reason": reason})
            current["tool_trace"] = tool_trace + [
                {
                    "tool": tool_name,
                    "agent": TOOLS_BY_NAME[tool_name].owner_agent,
                    "input_summary": _state_summary(before),
                    "output_summary": result["structuredContent"]["summary"],
                    "llm_agent": llm_agent,
                    "llm_used": bool(llm_usage.get("used")) if llm_agent else False,
                    "llm_runtime": llm_usage.get("runtime") if llm_agent else None,
                    "prompt_profile": TOOL_PROMPT_PROFILE.get(tool_name, {}),
                    "planner_reason": reason,
                }
            ]
            tool_trace = list(current["tool_trace"])
            if progress_callback:
                progress_callback(tool_name, current, reason)
        current.setdefault("runtime_metadata", {}).update(self.runtime_metadata())
        current["runtime_metadata"]["planner_trace"] = planner_trace
        return current

    def run_detection_pipeline(self, state: dict, progress_callback: Callable = None) -> dict:
        return self._run_plan(state, DETECTION_PLAN, "detection", progress_callback)

    def run_resolution_pipeline(self, state: dict, progress_callback: Callable = None) -> dict:
        return self._run_plan(state, RESOLUTION_PLAN, "resolution", progress_callback)

    def runtime_metadata(self) -> dict:
        return {
            "active_runtime": "mcp_tools",
            "mcp_endpoint": "http://localhost:8000/mcp",
            "tool_count": len(TOOLS),
            "multiagent_mode": "agents_over_mcp_tools",
        }
