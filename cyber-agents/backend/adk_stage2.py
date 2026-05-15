import asyncio
import json
import os
import uuid
from dataclasses import dataclass
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

try:
    if not os.getenv("GOOGLE_API_KEY") and os.getenv("GEMINI_API_KEY"):
        os.environ["GOOGLE_API_KEY"] = os.environ["GEMINI_API_KEY"]

    from google.adk.agents import Agent
    from google.adk.a2a.utils.agent_to_a2a import to_a2a
    from google.adk.runners import Runner
    from google.adk.sessions import InMemorySessionService
    from google.genai import types

    ADK_IMPORT_ERROR = None
except Exception as exc:  # pragma: no cover - guarded fallback
    Agent = None
    Runner = None
    InMemorySessionService = None
    types = None
    to_a2a = None
    ADK_IMPORT_ERROR = str(exc)


STAGE2_MODEL = os.getenv("ADK_STAGE2_MODEL", "gemini-2.0-flash")
STAGE2_AVAILABLE = Agent is not None and Runner is not None and to_a2a is not None


@dataclass(frozen=True)
class Stage2AgentSpec:
    key: str
    public_name: str
    instruction: str
    description: str
    mount_path: str


STAGE2_AGENT_SPECS = [
    Stage2AgentSpec(
        key="classification",
        public_name="classification_agent",
        instruction=(
            "You are the CyberAgent Threat Classification Agent. "
            "Read the supplied incident evidence, classify the attack conservatively, "
            "estimate confidence, and return strict JSON only."
        ),
        description="Classifies the likely attack category from correlated incident evidence.",
        mount_path="/stage2/a2a/classification",
    ),
    Stage2AgentSpec(
        key="investigation",
        public_name="investigation_agent",
        instruction=(
            "You are the CyberAgent Investigation Agent. "
            "Build an analyst-ready incident brief grounded in the supplied evidence and return strict JSON only."
        ),
        description="Builds the incident brief, evidence summary, timeline, and attacker profile.",
        mount_path="/stage2/a2a/investigation",
    ),
    Stage2AgentSpec(
        key="policy",
        public_name="policy_agent",
        instruction=(
            "You are the CyberAgent Policy Agent. "
            "Decide whether the proposed response should be auto-executed, require approval, or be manually escalated. "
            "Return strict JSON only."
        ),
        description="Applies automation guardrails and human-approval policy to incident response.",
        mount_path="/stage2/a2a/policy",
    ),
]

_SPECS_BY_KEY = {spec.key: spec for spec in STAGE2_AGENT_SPECS}
_AGENT_CACHE = {}
_RUNNER_CACHE = {}
_A2A_APP_CACHE = {}


def _build_agent(spec: Stage2AgentSpec):
    return Agent(
        name=spec.public_name,
        description=spec.description,
        model=STAGE2_MODEL,
        instruction=spec.instruction,
    )


def _get_agent(spec_key: str):
    spec = _SPECS_BY_KEY[spec_key]
    if spec_key not in _AGENT_CACHE:
        _AGENT_CACHE[spec_key] = _build_agent(spec)
    return _AGENT_CACHE[spec_key]


def _get_runner(spec_key: str):
    if spec_key not in _RUNNER_CACHE:
        spec = _SPECS_BY_KEY[spec_key]
        _RUNNER_CACHE[spec_key] = Runner(
            app_name=f"cyberagent-stage2-{spec.public_name}",
            agent=_get_agent(spec_key),
            session_service=InMemorySessionService(),
        )
    return _RUNNER_CACHE[spec_key]


def _extract_event_text(event) -> str:
    content = getattr(event, "content", None)
    if not content:
        return ""
    parts = getattr(content, "parts", None) or []
    chunks = []
    for part in parts:
        text = getattr(part, "text", None)
        if text:
            chunks.append(text)
    return "".join(chunks).strip()


async def _invoke_runner(spec_key: str, prompt: str) -> Optional[dict]:
    runner = _get_runner(spec_key)
    session_id = uuid.uuid4().hex
    await runner.session_service.create_session(
        app_name=f"cyberagent-stage2-{_SPECS_BY_KEY[spec_key].public_name}",
        user_id="cyberagent-stage2",
        session_id=session_id,
    )
    message = types.Content(role="user", parts=[types.Part(text=prompt)])
    raw_chunks = []
    async for event in runner.run_async(
        user_id="cyberagent-stage2",
        session_id=session_id,
        new_message=message,
    ):
        text = _extract_event_text(event)
        if text:
            raw_chunks.append(text)
    if not raw_chunks:
        return None
    raw_text = "\n".join(raw_chunks).strip()
    try:
        return json.loads(raw_text)
    except Exception:
        cleaned = raw_text.strip()
        if cleaned.startswith("```"):
            lines = cleaned.splitlines()
            if lines and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            cleaned = "\n".join(lines).strip()
            if cleaned.lower().startswith("json"):
                cleaned = cleaned[4:].strip()
        return json.loads(cleaned)


def run_stage2_review(spec_key: str, prompt: str) -> Optional[dict]:
    if not STAGE2_AVAILABLE:
        return None
    try:
        result = asyncio.run(_invoke_runner(spec_key, prompt))
    except Exception:
        return None
    if isinstance(result, dict):
        result["_stage2_runtime"] = {
            "mode": "google_adk_runner",
            "agent": _SPECS_BY_KEY[spec_key].public_name,
            "model": STAGE2_MODEL,
        }
    return result


def get_stage2_runtime_summary(base_url: str = "http://localhost:8000") -> dict:
    agents = []
    for spec in STAGE2_AGENT_SPECS:
        agents.append(
            {
                "name": spec.public_name,
                "description": spec.description,
                "mount_path": spec.mount_path,
                "base_url": f"{base_url}{spec.mount_path}",
                "agent_card_url": f"{base_url}{spec.mount_path}/.well-known/agent-card.json",
                "invoke_url": f"{base_url}{spec.mount_path}/invoke",
            }
        )
    return {
        "enabled": STAGE2_AVAILABLE,
        "mode": "adk_native_reasoning_with_a2a_apps" if STAGE2_AVAILABLE else "disabled",
        "model": STAGE2_MODEL,
        "runtime": "google-adk",
        "a2a_agents": agents,
        "import_error": ADK_IMPORT_ERROR,
    }


def get_stage2_a2a_apps():
    if not STAGE2_AVAILABLE:
        return {}
    if not _A2A_APP_CACHE:
        for spec in STAGE2_AGENT_SPECS:
            _A2A_APP_CACHE[spec.mount_path] = to_a2a(
                _get_agent(spec.key),
                host="localhost",
                port=8000,
            )
    return _A2A_APP_CACHE


def get_stage2_agent_card(agent_name: str, base_url: str = "http://localhost:8000") -> Optional[dict]:
    for spec in STAGE2_AGENT_SPECS:
        if spec.public_name == agent_name:
            return {
                "name": spec.public_name,
                "description": spec.description,
                "version": "0.0.1",
                "protocol": "A2A",
                "runtime": "google-adk",
                "url": f"{base_url}{spec.mount_path}/invoke",
                "preferredTransport": "http-json",
                "defaultInputModes": ["application/json", "text/plain"],
                "defaultOutputModes": ["application/json"],
                "capabilities": {
                    "streaming": False,
                    "stateTransitionHistory": True,
                },
                "skills": [
                    {
                        "id": spec.public_name,
                        "name": spec.public_name,
                        "description": spec.description,
                    }
                ],
            }
    return None
