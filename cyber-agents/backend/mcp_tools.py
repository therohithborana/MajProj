import json
from copy import deepcopy
from dataclasses import dataclass
from typing import Callable

from agents import (
    CLASSIFIER_SYSTEM_PROMPT,
    CHALLENGE_SYSTEM_PROMPT,
    INVESTIGATOR_SYSTEM_PROMPT,
    POLICY_SYSTEM_PROMPT,
    REPORT_SYSTEM_PROMPT,
    RESPONSE_SYSTEM_PROMPT,
    action,
    challenge_review,
    correlation,
    detection,
    investigation,
    normalization,
    policy,
    report,
    threat_classification,
    threat_resolve,
)
from gemini_client import call_gemini
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

LLM_AGENT_BY_TOOL = {
    "analysis.classify_threat": "Threat Classification Agent",
    "analysis.challenge_classification": "Challenge Agent",
    "analysis.investigate_incident": "Investigation Agent",
    "response.plan_mitigation": "Response Planning Agent",
    "response.review_policy": "Policy Agent",
    "response.generate_report": "Reporting Agent",
}

TOOL_PROMPT_PROFILE = {
    "analysis.classify_threat": {
        "agent": "Threat Classification Agent",
        "system_prompt": CLASSIFIER_SYSTEM_PROMPT,
        "purpose": "Classify the suspicious activity conservatively from correlated evidence.",
    },
    "analysis.investigate_incident": {
        "agent": "Investigation Agent",
        "system_prompt": INVESTIGATOR_SYSTEM_PROMPT,
        "purpose": "Build an analyst-ready incident brief, timeline, and attacker profile.",
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
    "response.review_policy": {
        "agent": "Policy Agent",
        "system_prompt": POLICY_SYSTEM_PROMPT,
        "purpose": "Decide whether response should be autonomous, approved, or escalated.",
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
    "analysis.investigate_incident",
    "response.plan_mitigation",
    "response.review_policy",
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
        planner_prompt = f"""
Current phase: {phase}
Pending tools: {pending_tools}
Current state summary:
{json.dumps(_state_summary(state), ensure_ascii=False)}

Return a JSON object with exactly this shape:
{{
  "next_tool": "one item from pending tools",
  "reason": "one concise sentence",
  "skip_challenge": false
}}

Rules:
- next_tool must be one of the pending tools
- skip_challenge may only be true if analysis.challenge_classification is still pending and the classification confidence is already strong
- return JSON only
""".strip()
        response = call_gemini(f"{PLANNER_SYSTEM_PROMPT}\n\n{planner_prompt}")
        try:
            parsed = json.loads(response.strip().removeprefix("```json").removesuffix("```").strip())
            chosen = parsed.get("next_tool")
            if chosen in pending_tools:
                return chosen, str(parsed.get("reason") or "Coordinator selected the next MCP tool.").strip(), bool(parsed.get("skip_challenge"))
        except Exception:
            pass
        return fallback_tool, f"Coordinator selected {fallback_tool} from the remaining MCP plan.", False

    def run_detection_pipeline(self, state: dict) -> dict:
        current = deepcopy(state)
        tool_trace = list(current.get("tool_trace", []))
        pending_tools = list(DETECTION_PLAN)
        planner_trace = []
        while pending_tools:
            tool_name, reason, skip_challenge = self._choose_next_tool(current, pending_tools, "detection")
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
            planner_trace.append({"phase": "detection", "tool": tool_name, "reason": reason})
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
        current.setdefault("runtime_metadata", {}).update(self.runtime_metadata())
        current["runtime_metadata"]["planner_trace"] = planner_trace
        return current

    def run_resolution_pipeline(self, state: dict) -> dict:
        current = deepcopy(state)
        tool_trace = list(current.get("tool_trace", []))
        pending_tools = list(RESOLUTION_PLAN)
        planner_trace = list((current.get("runtime_metadata") or {}).get("planner_trace") or [])
        while pending_tools:
            tool_name, reason, _ = self._choose_next_tool(current, pending_tools, "resolution")
            if tool_name not in pending_tools:
                tool_name = pending_tools[0]
            pending_tools.remove(tool_name)
            before = deepcopy(current)
            result = self.runtime.call_tool(tool_name, {"state": current})
            current = result["structuredContent"]["state"]
            llm_agent = LLM_AGENT_BY_TOOL.get(tool_name)
            llm_usage = (current.get("llm_usage") or {}).get(llm_agent, {}) if llm_agent else {}
            planner_trace.append({"phase": "resolution", "tool": tool_name, "reason": reason})
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
        current.setdefault("runtime_metadata", {}).update(self.runtime_metadata())
        current["runtime_metadata"]["planner_trace"] = planner_trace
        return current

    def runtime_metadata(self) -> dict:
        return {
            "active_runtime": "mcp_tools",
            "mcp_endpoint": "http://localhost:8000/mcp",
            "tool_count": len(TOOLS),
            "multiagent_mode": "agents_over_mcp_tools",
        }
