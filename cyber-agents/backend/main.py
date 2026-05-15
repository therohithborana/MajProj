import asyncio
from contextlib import suppress
from datetime import datetime, timezone
import json
import uuid

from bson import ObjectId
from fastapi import Depends, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pymongo.errors import OperationFailure

from adk_stage2 import get_stage2_a2a_apps, get_stage2_agent_card, get_stage2_runtime_summary
from agent_protocols import (
    AGUI_CONTENT_TYPE,
    SocA2ACoordinator,
    agui_sse,
    build_agui_event_stream,
)
from auth import require_collector, require_user
from db import db, init_db
from mcp_tools import McpMultiAgentCoordinator
from models import AGUIRunRequest, A2AInvokeRequest, ApprovalRequest, CollectorIngestRequest, IncidentAssignRequest, IncidentNoteRequest, Stage2InvokeRequest, serialize_document, utc_now
from otel_runtime import otel_runtime
from red_team import simulate_attack
from routes.auth import router as auth_router
from routes.websites import router as websites_router


app = FastAPI(title="CyberAgent API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()

app.include_router(auth_router)
app.include_router(websites_router)
for mount_path, mounted_app in get_stage2_a2a_apps().items():
    app.mount(mount_path, mounted_app)

active_incidents = {}
connected_clients = []
attack_running = False
auto_task = None
auto_website_id = None
coordinator = SocA2ACoordinator()
mcp_coordinator = McpMultiAgentCoordinator()

STAGE_MESSAGES = {
    "normalization": "Normalization Agent converted raw collector telemetry into a shared event schema.",
    "detection": "Detection Agent evaluated rules across access, auth, and network data.",
    "correlation": "Correlation Agent linked the evidence into one attack storyline.",
    "classification": "Threat Classification Agent estimated the attack type and risk.",
    "investigation": "Investigation Agent prepared the attacker profile and timeline.",
    "response_planning": "Response Planning Agent drafted containment and remediation steps.",
    "policy_decision": "Policy Agent decided whether the incident can be auto-executed or needs approval.",
    "action": "Action Agent executed the approved response path.",
    "report": "Reporting Agent generated the final incident report.",
}


async def broadcast(event_type: str, data: dict):
    payload = {"type": event_type, "data": data}
    dead_clients = []
    for client in list(connected_clients):
        try:
            await client.send_json(payload)
        except Exception:
            dead_clients.append(client)
    for client in dead_clients:
        with suppress(ValueError):
            connected_clients.remove(client)


def _serialize_incident_state(state: dict, website_id: str):
    payload = {**state, "website_id": website_id}
    return serialize_document(payload)


def _persist_incident(website_id: str, state: dict):
    attack_id = state["simulation"]["attack_id"]
    now = utc_now()
    document = {
        "website_id": website_id,
        "attack_id": attack_id,
        "incident_id": attack_id,
        "current_stage": state.get("current_stage"),
        "simulation": state.get("simulation"),
        "telemetry": state.get("telemetry"),
        "anomaly": state.get("anomaly"),
        "correlation": state.get("correlation"),
        "classification": state.get("classification"),
        "investigation": state.get("investigation"),
        "mitigation_plan": state.get("mitigation_plan"),
        "policy_decision": state.get("policy_decision"),
        "approval_status": state.get("approval_status"),
        "action_result": state.get("action_result"),
        "incident_report": state.get("incident_report"),
        "agent_trace": state.get("agent_trace", []),
        "agent_messages": state.get("agent_messages", []),
        "agent_discussion": state.get("agent_discussion", []),
        "protocol_trace": state.get("protocol_trace", []),
        "tool_trace": state.get("tool_trace", []),
        "runtime_metadata": state.get("runtime_metadata", {}),
        "llm_usage": state.get("llm_usage", {}),
        "challenge_review": state.get("challenge_review"),
        "notes": state.get("notes", []),
        "assignee": state.get("assignee"),
        "created_at": now,
        "updated_at": now,
    }
    existing = db.incidents.find_one({"attack_id": attack_id})
    if existing:
        document["created_at"] = existing.get("created_at", now)
    db.incidents.update_one({"attack_id": attack_id}, {"$set": document}, upsert=True)


def _website_query(user_id: str, website_id: str):
    try:
        return {"_id": ObjectId(website_id), "user_id": user_id}
    except Exception as exc:
        raise HTTPException(status_code=404, detail="Website not found") from exc


def _get_website_or_404(user_id: str, website_id: str):
    website = db.websites.find_one(_website_query(user_id, website_id))
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")
    return serialize_document(website)


def _normalize_event(website: dict, attack_id: str | None, event: dict):
    timestamp = event.get("timestamp") or utc_now().isoformat()
    if isinstance(timestamp, datetime):
        event_time = timestamp
    else:
        event_time = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    return {
        "website_id": website["_id"],
        "user_id": website["user_id"],
        "attack_id": attack_id,
        "event_type": event.get("event_type"),
        "timestamp": event_time,
        "src_ip": event.get("src_ip"),
        "dst_ip": event.get("dst_ip"),
        "port": event.get("port"),
        "protocol": event.get("protocol"),
        "method": event.get("method"),
        "path": event.get("path"),
        "status_code": event.get("status_code"),
        "username": event.get("username"),
        "result": event.get("result"),
        "bytes_sent": event.get("bytes_sent"),
        "packets": event.get("packets"),
        "flags": event.get("flags"),
        "message": event.get("message"),
        "metadata": event.get("metadata", {}),
        "created_at": utc_now(),
    }


def _store_events(website: dict, attack_id: str | None, events: list[dict]):
    normalized = [_normalize_event(website, attack_id, event) for event in events]
    if normalized:
        db.events.insert_many(normalized)
        sources_seen = sorted({event.get("src_ip") for event in normalized if event.get("src_ip")})[:25]
        db.websites.update_one(
            {"_id": ObjectId(website["_id"])},
            {
                "$set": {
                    "telemetry_stats.events_ingested": db.events.count_documents({"website_id": website["_id"]}),
                    "telemetry_stats.last_event_at": max(event["timestamp"] for event in normalized),
                    "telemetry_stats.sources_seen": sources_seen,
                    "collector.last_seen_at": utc_now(),
                    "updated_at": utc_now(),
                }
            },
        )
    return normalized


def _build_collector_simulation(website_id: str, attack_id: str, source_label: str | None):
    events = _fetch_attack_events(website_id, attack_id)
    description = f"Collector telemetry received from {source_label or 'customer website'}."
    return {
        "attack_id": attack_id,
        "timestamp": events[0]["timestamp"] if events else utc_now().isoformat(),
        "description": description,
        "events": events,
        "source": source_label or "collector_agent",
    }


def _fetch_attack_events(website_id: str, attack_id: str):
    events = []
    for document in db.events.find({"website_id": website_id, "attack_id": attack_id}).sort("timestamp", 1):
        item = serialize_document(document)
        item.pop("_id", None)
        item.pop("user_id", None)
        item.pop("website_id", None)
        item.pop("created_at", None)
        if isinstance(item.get("timestamp"), datetime):
            item["timestamp"] = item["timestamp"].isoformat()
        events.append(item)
    return events


def _telemetry_snapshot(website_id: str):
    total_events = db.events.count_documents({"website_id": website_id})
    counts = {
        event_type: db.events.count_documents({"website_id": website_id, "event_type": event_type})
        for event_type in ["access", "auth", "network"]
    }
    recent_events = [
        serialize_document(document)
        for document in db.events.find({"website_id": website_id}).sort("timestamp", -1).limit(12)
    ]
    return {
        "total_events": total_events,
        "counts": counts,
        "recent_events": recent_events,
    }


def _create_job(website_id: str, job_type: str, metadata: dict | None = None):
    job = {
        "website_id": website_id,
        "job_type": job_type,
        "status": "queued",
        "retry_count": 0,
        "metadata": metadata or {},
        "error": None,
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }
    result = db.jobs.insert_one(job)
    return str(result.inserted_id)


def _update_job(job_id: str, status: str, error: str | None = None, metadata: dict | None = None):
    try:
        update_payload = {
            "status": status,
            "error": error,
            "updated_at": utc_now(),
            **({"metadata": metadata} if metadata is not None else {}),
        }
        update_ops = {"$set": update_payload}
        if status == "failed":
            update_ops["$inc"] = {"retry_count": 1}
        db.jobs.update_one(
            {"_id": ObjectId(job_id)},
            update_ops,
        )
    except Exception:
        return


def _observability_snapshot(website_id: str):
    return otel_runtime.snapshot(website_id)


async def _broadcast_trace(website_id: str, attack_id: str, state: dict):
    protocol_lookup = {
        item.get("to_agent"): item for item in state.get("protocol_trace", []) if item.get("to_agent")
    }
    stage_to_protocol_agent = {
        "normalization": "normalization_agent",
        "detection": "detection_agent",
        "correlation": "correlation_agent",
        "classification": "classification_agent",
        "investigation": "investigation_agent",
        "response_planning": "response_planning_agent",
        "policy_decision": "policy_agent",
        "action": "action_agent",
        "report": "reporting_agent",
    }
    discussion_entries = state.get("agent_discussion", [])
    for index, entry in enumerate(state.get("agent_trace", [])):
        public_name = stage_to_protocol_agent.get(entry["stage"])
        discussion_entry = discussion_entries[index] if index < len(discussion_entries) else None
        await broadcast(
            "agent_update",
            {
                "attack_id": attack_id,
                "website_id": website_id,
                "current_stage": entry["stage"],
                "message": discussion_entry.get("message") if discussion_entry else entry["summary"],
                "agent_trace_entry": entry,
                "agent_discussion_entry": discussion_entry,
                "agent_discussion": discussion_entries[: index + 1] if discussion_entry else discussion_entries,
                "protocol_trace_entry": protocol_lookup.get(public_name),
                "policy_decision": state.get("policy_decision"),
                "runtime_metadata": state.get("runtime_metadata", {}),
            },
        )
        await asyncio.sleep(0.3)


async def _run_detection_pipeline(website: dict, attack_id: str, simulation: dict, job_id: str | None = None):
    initial_state = {
        "website": website,
        "simulation": simulation,
        "telemetry": None,
        "anomaly": None,
        "correlation": None,
        "classification": None,
        "challenge_review": None,
        "investigation": None,
        "mitigation_plan": None,
        "policy_decision": None,
        "approval_status": None,
        "action_result": None,
        "incident_report": None,
        "agent_trace": [],
        "agent_messages": [],
        "agent_discussion": [],
        "llm_usage": {},
        "current_stage": "collector_ingested",
        "notes": [],
        "assignee": None,
    }

    await broadcast(
        "collector_ingested",
        {
            "attack_id": attack_id,
            "website_id": website["_id"],
            "simulation": simulation,
            "current_stage": "collector_ingested",
            "message": "Collector Agent forwarded fresh telemetry into the platform.",
        },
    )

    loop = asyncio.get_event_loop()
    if job_id:
        _update_job(job_id, "running", metadata={"attack_id": attack_id, "phase": "detection"})
    try:
        result = await loop.run_in_executor(None, mcp_coordinator.run_detection_pipeline, initial_state)
    except Exception as exc:
        if job_id:
            _update_job(job_id, "failed", error=str(exc), metadata={"attack_id": attack_id, "phase": "detection"})
        await broadcast(
            "agent_update",
            {
                "attack_id": attack_id,
                "website_id": website["_id"],
                "current_stage": "pipeline_failed",
                "message": f"Detection pipeline failed: {exc}",
            },
        )
        raise
    result["website_id"] = website["_id"]
    result.setdefault("runtime_metadata", {})["stage2"] = get_stage2_runtime_summary()
    if job_id:
        result.setdefault("runtime_metadata", {})["job_id"] = job_id

    await _broadcast_trace(website["_id"], attack_id, result)

    active_incidents[attack_id] = result
    _persist_incident(website["_id"], result)
    await broadcast(
        "incident_snapshot",
        {
            "attack_id": attack_id,
            "website_id": website["_id"],
            "simulation": result.get("simulation"),
            "telemetry": result.get("telemetry"),
            "anomaly": result.get("anomaly"),
            "correlation": result.get("correlation"),
            "classification": result.get("classification"),
            "challenge_review": result.get("challenge_review"),
            "investigation": result.get("investigation"),
            "mitigation_plan": result.get("mitigation_plan"),
            "policy_decision": result.get("policy_decision"),
            "approval_status": result.get("approval_status"),
            "action_result": result.get("action_result"),
            "incident_report": result.get("incident_report"),
            "agent_trace": result.get("agent_trace"),
            "agent_messages": result.get("agent_messages"),
            "agent_discussion": result.get("agent_discussion"),
            "protocol_trace": result.get("protocol_trace"),
            "tool_trace": result.get("tool_trace"),
            "runtime_metadata": result.get("runtime_metadata", {}),
            "llm_usage": result.get("llm_usage"),
            "current_stage": result.get("current_stage"),
            "message": "Detection pipeline completed. Full incident context is available.",
        },
    )
    await broadcast(
        "observability_update",
        {
            "website_id": website["_id"],
            "attack_id": attack_id,
            "observability": _observability_snapshot(website["_id"]),
            "message": "OpenTelemetry captured the latest multi-agent execution spans.",
        },
    )

    if result.get("policy_decision", {}).get("mode") == "auto_execute":
        await broadcast(
            "agent_update",
            {
                "attack_id": attack_id,
                "website_id": website["_id"],
                "current_stage": "action",
                "message": "Policy Agent auto-approved the response path. Action Agent is executing it now.",
                "policy_decision": result.get("policy_decision"),
                "tool_trace": result.get("tool_trace"),
                "runtime_metadata": result.get("runtime_metadata", {}),
            },
        )
        try:
            final_state = await loop.run_in_executor(
                None,
                mcp_coordinator.run_resolution_pipeline,
                {**result, "approval_status": "auto_approved"},
            )
        except Exception as exc:
            if job_id:
                _update_job(job_id, "failed", error=str(exc), metadata={"attack_id": attack_id, "phase": "auto_resolution"})
            await broadcast(
                "agent_update",
                {
                    "attack_id": attack_id,
                    "website_id": website["_id"],
                    "current_stage": "resolution_failed",
                    "message": f"Autonomous resolution failed: {exc}",
                },
            )
            raise
        final_state["website_id"] = website["_id"]
        final_state.setdefault("runtime_metadata", {})["stage2"] = get_stage2_runtime_summary()
        active_incidents[attack_id] = final_state
        _persist_incident(website["_id"], final_state)
        await broadcast(
            "observability_update",
            {
                "website_id": website["_id"],
                "attack_id": attack_id,
                "observability": _observability_snapshot(website["_id"]),
                "message": "OpenTelemetry recorded the autonomous response path.",
            },
        )
        if job_id:
            _update_job(job_id, "completed", metadata={"attack_id": attack_id, "phase": "resolved"})
        await broadcast(
            "incident_resolved",
            {
                "attack_id": attack_id,
                "website_id": website["_id"],
                "approval_status": final_state.get("approval_status"),
                "current_stage": final_state.get("current_stage"),
                "action_result": final_state.get("action_result"),
                "incident_report": final_state.get("incident_report"),
                "policy_decision": final_state.get("policy_decision"),
                "agent_trace": final_state.get("agent_trace"),
                "agent_messages": final_state.get("agent_messages"),
                "agent_discussion": final_state.get("agent_discussion"),
                "protocol_trace": final_state.get("protocol_trace"),
                "tool_trace": final_state.get("tool_trace"),
                "runtime_metadata": final_state.get("runtime_metadata", {}),
                "llm_usage": final_state.get("llm_usage"),
                "message": "Autonomous response completed and the incident report is ready.",
            },
        )
    elif result.get("policy_decision", {}).get("mode") == "approval_required":
        await broadcast(
            "agent_update",
            {
                "attack_id": attack_id,
                "website_id": website["_id"],
                "current_stage": "awaiting_approval",
                "message": "Policy Agent requires human approval before containment is executed.",
                "policy_decision": result.get("policy_decision"),
                "protocol_trace": result.get("protocol_trace"),
                "tool_trace": result.get("tool_trace"),
                "runtime_metadata": result.get("runtime_metadata", {}),
            },
        )
        if job_id:
            _update_job(job_id, "awaiting_approval", metadata={"attack_id": attack_id, "phase": "awaiting_approval"})
    else:
        try:
            final_state = await loop.run_in_executor(
                None,
                mcp_coordinator.run_resolution_pipeline,
                {**result, "approval_status": "manual_required"},
            )
        except Exception as exc:
            if job_id:
                _update_job(job_id, "failed", error=str(exc), metadata={"attack_id": attack_id, "phase": "manual_escalation"})
            await broadcast(
                "agent_update",
                {
                    "attack_id": attack_id,
                    "website_id": website["_id"],
                    "current_stage": "resolution_failed",
                    "message": f"Manual escalation path failed: {exc}",
                },
            )
            raise
        final_state["website_id"] = website["_id"]
        final_state.setdefault("runtime_metadata", {})["stage2"] = get_stage2_runtime_summary()
        active_incidents[attack_id] = final_state
        _persist_incident(website["_id"], final_state)
        await broadcast(
            "observability_update",
            {
                "website_id": website["_id"],
                "attack_id": attack_id,
                "observability": _observability_snapshot(website["_id"]),
                "message": "OpenTelemetry recorded the escalation and reporting path.",
            },
        )
        if job_id:
            _update_job(job_id, "completed", metadata={"attack_id": attack_id, "phase": "manual_escalation"})
        await broadcast(
            "incident_resolved",
            {
                "attack_id": attack_id,
                "website_id": website["_id"],
                "approval_status": final_state.get("approval_status"),
                "current_stage": final_state.get("current_stage"),
                "action_result": final_state.get("action_result"),
                "incident_report": final_state.get("incident_report"),
                "policy_decision": final_state.get("policy_decision"),
                "agent_trace": final_state.get("agent_trace"),
                "agent_messages": final_state.get("agent_messages"),
                "agent_discussion": final_state.get("agent_discussion"),
                "protocol_trace": final_state.get("protocol_trace"),
                "tool_trace": final_state.get("tool_trace"),
                "runtime_metadata": final_state.get("runtime_metadata", {}),
                "llm_usage": final_state.get("llm_usage"),
                "message": "Incident was escalated for manual follow-up with a completed AI report.",
            },
        )

    return attack_id


async def _auto_simulation_loop(website: dict):
    global attack_running
    while attack_running:
        scenario = simulate_attack()
        attack_id = scenario["attack_id"]
        _store_events(website, attack_id, scenario["events"])
        simulation = {
            "attack_id": attack_id,
            "timestamp": scenario["timestamp"],
            "description": scenario["description"],
            "events": _fetch_attack_events(website["_id"], attack_id),
            "attack_profile": scenario["attack_profile"],
            "source": "demo_collector",
        }
        job_id = _create_job(website["_id"], "auto_simulation_detection", {"attack_id": attack_id})
        await _run_detection_pipeline(website, attack_id, simulation, job_id)
        for _ in range(15):
            if not attack_running:
                break
            await asyncio.sleep(1)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    try:
        cursor = db.incidents.find(
            {},
            {
                "website_id": 1,
                "attack_id": 1,
                "incident_id": 1,
                "current_stage": 1,
                "simulation": 1,
                "telemetry": 1,
                "anomaly": 1,
                "correlation": 1,
                "classification": 1,
                "challenge_review": 1,
                "investigation": 1,
                "mitigation_plan": 1,
                "policy_decision": 1,
                "approval_status": 1,
                "notes": 1,
                "assignee": 1,
                "action_result": 1,
                "incident_report": 1,
                "agent_trace": 1,
                "agent_messages": 1,
                "agent_discussion": 1,
                "protocol_trace": 1,
                "tool_trace": 1,
                "runtime_metadata": 1,
                "llm_usage": 1,
                "created_at": 1,
                "updated_at": 1,
            },
        ).sort("created_at", -1).limit(50)
        incidents = [serialize_document(document) for document in cursor]
    except OperationFailure:
        incidents = []
    await websocket.send_json(
        {
            "type": "init",
            "data": {
                "incidents": incidents,
                "running": attack_running,
            },
        }
    )
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        with suppress(ValueError):
            connected_clients.remove(websocket)
    except Exception:
        with suppress(ValueError):
            connected_clients.remove(websocket)


@app.post("/collector/ingest")
async def ingest_collector_events(payload: CollectorIngestRequest, website=Depends(require_collector)):
    attack_id = payload.attack_id or (uuid.uuid4().hex[:8].upper() if payload.run_detection else None)
    job_id = _create_job(website["_id"], "collector_ingest", {"attack_id": attack_id, "run_detection": payload.run_detection})
    raw_events = [event.model_dump() for event in payload.events]
    normalized_events = _store_events(website, attack_id, raw_events)
    otel_runtime.record_collector_ingest(website["_id"], payload.source_label, raw_events, payload.run_detection)
    telemetry_snapshot = _telemetry_snapshot(website["_id"])
    observability_snapshot = _observability_snapshot(website["_id"])
    await broadcast(
        "telemetry_update",
        {
            "website_id": website["_id"],
            "attack_id": attack_id,
            "events_ingested": len(normalized_events),
            "source_label": payload.source_label,
            "run_detection": payload.run_detection,
            "telemetry": telemetry_snapshot,
            "observability": observability_snapshot,
            "recent_events": telemetry_snapshot["recent_events"][: min(4, len(telemetry_snapshot["recent_events"]))],
            "message": f"Collector received {len(normalized_events)} event(s) from {payload.source_label or 'customer website'}.",
        },
    )
    await broadcast(
        "observability_update",
        {
            "website_id": website["_id"],
            "attack_id": attack_id,
            "observability": observability_snapshot,
            "message": "OpenTelemetry captured a fresh collector ingest burst.",
        },
    )
    if payload.run_detection and attack_id:
        simulation = _build_collector_simulation(website["_id"], attack_id, payload.source_label)
        await _run_detection_pipeline(website, attack_id, simulation, job_id)
    else:
        _update_job(job_id, "completed", metadata={"attack_id": attack_id, "phase": "ingested_only"})
    return {
        "status": "accepted",
        "website_id": website["_id"],
        "attack_id": attack_id,
        "job_id": job_id,
        "events_ingested": len(normalized_events),
        "run_detection": payload.run_detection,
    }


@app.post("/websites/{website_id}/simulate")
async def simulate_for_website(website_id: str, user=Depends(require_user)):
    website = _get_website_or_404(user["_id"], website_id)
    scenario = simulate_attack()
    attack_id = scenario["attack_id"]
    _store_events(website, attack_id, scenario["events"])
    simulation = {
        "attack_id": attack_id,
        "timestamp": scenario["timestamp"],
        "description": scenario["description"],
        "events": _fetch_attack_events(website["_id"], attack_id),
        "attack_profile": scenario["attack_profile"],
        "source": "demo_collector",
    }
    job_id = _create_job(website["_id"], "manual_simulation", {"attack_id": attack_id})
    await _run_detection_pipeline(website, attack_id, simulation, job_id)
    return {"status": "pipeline_running", "incident_id": attack_id, "website_id": website_id, "job_id": job_id}


@app.get("/websites/{website_id}/incidents")
async def list_incidents_for_website(
    website_id: str,
    q: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    attack_class: str | None = Query(default=None),
    approval_status: str | None = Query(default=None),
    policy_mode: str | None = Query(default=None),
    user=Depends(require_user),
):
    _get_website_or_404(user["_id"], website_id)
    query = {"website_id": website_id}
    if severity:
        query["classification.attack.severity"] = severity.upper()
    if attack_class:
        query["classification.predicted_class"] = attack_class
    if approval_status:
        query["approval_status"] = approval_status
    if policy_mode:
        query["policy_decision.mode"] = policy_mode
    incidents = [
        serialize_document(document)
        for document in db.incidents.find(query).sort("created_at", -1)
    ]
    if q:
        q_lower = q.lower()
        incidents = [
            incident
            for incident in incidents
            if q_lower in json.dumps(
                {
                    "attack_id": incident.get("attack_id"),
                    "description": incident.get("simulation", {}).get("description"),
                    "predicted_class": incident.get("classification", {}).get("predicted_class"),
                    "source": incident.get("classification", {}).get("attack", {}).get("primary_src_ip"),
                    "target": incident.get("classification", {}).get("attack", {}).get("target_ip"),
                }
            ).lower()
        ]
    return incidents


@app.get("/websites/{website_id}/telemetry")
async def website_telemetry(website_id: str, user=Depends(require_user)):
    _get_website_or_404(user["_id"], website_id)
    return _telemetry_snapshot(website_id)


@app.get("/websites/{website_id}/observability")
async def website_observability(website_id: str, user=Depends(require_user)):
    _get_website_or_404(user["_id"], website_id)
    return _observability_snapshot(website_id)


@app.get("/websites/{website_id}/analytics")
async def website_analytics(website_id: str, user=Depends(require_user)):
    _get_website_or_404(user["_id"], website_id)
    incidents = [
        serialize_document(document)
        for document in db.incidents.find({"website_id": website_id}).sort("created_at", -1).limit(200)
    ]
    by_class = {}
    by_severity = {}
    by_status = {}
    for incident in incidents:
        attack_class = incident.get("classification", {}).get("predicted_class", "Unknown")
        sev = incident.get("classification", {}).get("attack", {}).get("severity", "UNKNOWN")
        status = incident.get("approval_status") or incident.get("current_stage") or "unknown"
        by_class[attack_class] = by_class.get(attack_class, 0) + 1
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_status[status] = by_status.get(status, 0) + 1
    return {
        "website_id": website_id,
        "totals": {
            "incidents": len(incidents),
            "notes": sum(len(incident.get("notes") or []) for incident in incidents),
        },
        "by_class": by_class,
        "by_severity": by_severity,
        "by_status": by_status,
    }


@app.get("/websites/{website_id}/jobs")
async def website_jobs(website_id: str, user=Depends(require_user)):
    _get_website_or_404(user["_id"], website_id)
    return [
        serialize_document(document)
        for document in db.jobs.find({"website_id": website_id}).sort("created_at", -1).limit(100)
    ]


@app.get("/incidents/{incident_id}")
async def get_incident(incident_id: str, user=Depends(require_user)):
    incident = db.incidents.find_one({"attack_id": incident_id})
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    website = db.websites.find_one(_website_query(user["_id"], incident["website_id"]))
    if not website:
        raise HTTPException(status_code=404, detail="Incident not found")
    return serialize_document(incident)


@app.get("/incidents/{incident_id}/notes")
async def get_incident_notes(incident_id: str, user=Depends(require_user)):
    incident = db.incidents.find_one({"attack_id": incident_id})
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    website = db.websites.find_one(_website_query(user["_id"], incident["website_id"]))
    if not website:
        raise HTTPException(status_code=404, detail="Incident not found")
    return serialize_document(incident).get("notes", [])


@app.post("/incidents/{incident_id}/notes")
async def add_incident_note(incident_id: str, body: IncidentNoteRequest, user=Depends(require_user)):
    incident = db.incidents.find_one({"attack_id": incident_id})
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    website = db.websites.find_one(_website_query(user["_id"], incident["website_id"]))
    if not website:
        raise HTTPException(status_code=404, detail="Incident not found")
    note = {
        "author": user.get("name") or user.get("email"),
        "author_role": user.get("role", "owner"),
        "note": body.note.strip(),
        "created_at": utc_now(),
    }
    db.incidents.update_one({"attack_id": incident_id}, {"$push": {"notes": note}, "$set": {"updated_at": utc_now()}})
    return serialize_document(db.incidents.find_one({"attack_id": incident_id})).get("notes", [])


@app.post("/incidents/{incident_id}/assign")
async def assign_incident(incident_id: str, body: IncidentAssignRequest, user=Depends(require_user)):
    incident = db.incidents.find_one({"attack_id": incident_id})
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    website = db.websites.find_one(_website_query(user["_id"], incident["website_id"]))
    if not website:
        raise HTTPException(status_code=404, detail="Incident not found")
    assignee = {
        "name": body.assignee.strip(),
        "assigned_by": user.get("name") or user.get("email"),
        "assigned_at": utc_now(),
    }
    db.incidents.update_one({"attack_id": incident_id}, {"$set": {"assignee": assignee, "updated_at": utc_now()}})
    return serialize_document(db.incidents.find_one({"attack_id": incident_id}))


@app.get("/stage2/runtime")
async def stage2_runtime():
    return get_stage2_runtime_summary("http://localhost:8000")


@app.get("/mcp/tools")
async def mcp_tools_list():
    return {
        "tools": mcp_coordinator.runtime.list_tools(),
        "runtime": mcp_coordinator.runtime_metadata(),
    }


@app.post("/mcp")
async def mcp_endpoint(payload: dict):
    method = payload.get("method")
    request_id = payload.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2025-11-25",
                "serverInfo": {
                    "name": "cyberagent-mcp",
                    "version": "0.2.0",
                },
                "capabilities": {
                    "tools": {
                        "listChanged": False,
                    }
                },
            },
        }

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "tools": mcp_coordinator.runtime.list_tools(),
            },
        }

    if method == "tools/call":
        params = payload.get("params") or {}
        tool_name = params.get("name")
        arguments = params.get("arguments") or {}
        try:
            result = mcp_coordinator.runtime.call_tool(tool_name, arguments)
        except KeyError:
            raise HTTPException(status_code=404, detail="Tool not found")
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": result,
        }

    raise HTTPException(status_code=400, detail="Unsupported MCP method")


@app.get("/stage2/a2a/{agent_name}/.well-known/agent-card.json")
async def stage2_agent_card(agent_name: str):
    card = get_stage2_agent_card(agent_name, "http://localhost:8000")
    if not card:
        raise HTTPException(status_code=404, detail="Stage 2 agent not found")
    return card


@app.post("/stage2/a2a/{agent_name}/invoke")
async def stage2_agent_invoke(agent_name: str, payload: Stage2InvokeRequest):
    agent_key = None
    if agent_name == "classification_agent":
        agent_key = "classification"
    elif agent_name == "investigation_agent":
        agent_key = "investigation"
    elif agent_name == "policy_agent":
        agent_key = "policy"
    if not agent_key:
        raise HTTPException(status_code=404, detail="Stage 2 agent not found")

    prompt = payload.prompt or json.dumps(payload.payload, ensure_ascii=False)
    result = run_stage2_review(agent_key, prompt)
    if result is None:
        raise HTTPException(status_code=503, detail="Stage 2 agent runtime unavailable")
    return {
        "agent": agent_name,
        "runtime": "google-adk",
        "result": result,
    }


@app.get("/a2a/agents")
async def list_a2a_agents():
    base_url = "http://localhost:8000"
    return {
        "root_agent": coordinator.root_card(base_url),
        "agents": coordinator.agent_cards(base_url),
        "stage2": get_stage2_runtime_summary(base_url),
        "mcp": mcp_coordinator.runtime_metadata(),
    }


@app.get("/a2a/soc_coordinator/agent-card.json")
async def get_root_agent_card():
    return coordinator.root_card("http://localhost:8000")


@app.get("/a2a/agents/{agent_name}/agent-card.json")
async def get_agent_card(agent_name: str):
    cards = {card["name"]: card for card in coordinator.agent_cards("http://localhost:8000")}
    card = cards.get(agent_name)
    if not card:
        raise HTTPException(status_code=404, detail="Agent card not found")
    return card


@app.post("/a2a/agents/{agent_name}/invoke")
async def invoke_a2a_agent(agent_name: str, payload: A2AInvokeRequest):
    if agent_name not in {card["name"] for card in coordinator.agent_cards("http://localhost:8000")}:
        raise HTTPException(status_code=404, detail="Agent not found")
    state = coordinator.invoke_agent(agent_name, payload.state, payload.caller)
    trace_entry = state.get("protocol_trace", [])[-1] if state.get("protocol_trace") else None
    return {
        "task_id": payload.task_id or (trace_entry or {}).get("task_id"),
        "agent": agent_name,
        "runtime": state.get("runtime_metadata", {}),
        "protocol_trace_entry": trace_entry,
        "state": serialize_document(state),
    }


@app.post("/a2a/soc_coordinator/run")
async def run_root_coordinator(payload: A2AInvokeRequest):
    state = coordinator.run_detection_pipeline(payload.state)
    return {
        "task_id": payload.task_id or uuid.uuid4().hex,
        "agent": "soc_coordinator",
        "runtime": state.get("runtime_metadata", {}),
        "state": serialize_document(state),
    }


@app.post("/agui/runs")
async def agui_run(payload: AGUIRunRequest, user=Depends(require_user)):
    incident = db.incidents.find_one({"attack_id": payload.incident_id})
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    website = db.websites.find_one(_website_query(user["_id"], incident["website_id"]))
    if not website:
        raise HTTPException(status_code=404, detail="Incident not found")

    serialized_incident = serialize_document(incident)
    run_id = payload.run_id or uuid.uuid4().hex
    events = build_agui_event_stream(serialized_incident, payload.thread_id, run_id)

    async def event_generator():
        for event in events:
            yield agui_sse(event)
            await asyncio.sleep(0.05)

    return StreamingResponse(event_generator(), media_type=AGUI_CONTENT_TYPE)


@app.post("/incidents/{incident_id}/approve")
async def approve_incident(incident_id: str, body: ApprovalRequest, user=Depends(require_user)):
    incident = db.incidents.find_one({"attack_id": incident_id})
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    website = db.websites.find_one(_website_query(user["_id"], incident["website_id"]))
    if not website:
        raise HTTPException(status_code=404, detail="Incident not found")
    if body.decision not in {"approved", "rejected"}:
        raise HTTPException(status_code=400, detail="Decision must be approved or rejected")
    job_id = _create_job(incident["website_id"], "incident_resolution", {"attack_id": incident_id, "decision": body.decision})

    state = {
        "website": serialize_document(website),
        "simulation": incident.get("simulation"),
        "telemetry": incident.get("telemetry"),
        "anomaly": incident.get("anomaly"),
        "correlation": incident.get("correlation"),
        "classification": incident.get("classification"),
        "challenge_review": incident.get("challenge_review"),
        "investigation": incident.get("investigation"),
        "mitigation_plan": incident.get("mitigation_plan"),
        "policy_decision": incident.get("policy_decision"),
        "approval_status": body.decision,
        "action_result": incident.get("action_result"),
        "incident_report": incident.get("incident_report"),
        "agent_trace": incident.get("agent_trace", []),
        "agent_messages": incident.get("agent_messages", []),
        "agent_discussion": incident.get("agent_discussion", []),
        "protocol_trace": incident.get("protocol_trace", []),
        "tool_trace": incident.get("tool_trace", []),
        "runtime_metadata": incident.get("runtime_metadata", {}),
        "llm_usage": incident.get("llm_usage", {}),
        "current_stage": incident.get("current_stage"),
        "notes": incident.get("notes", []),
        "assignee": incident.get("assignee"),
    }
    state.setdefault("runtime_metadata", {})["job_id"] = job_id
    active_incidents[incident_id] = state
    _update_job(job_id, "running", metadata={"attack_id": incident_id, "phase": "resolution"})

    await broadcast(
        "agent_update",
        {
            "attack_id": incident_id,
            "website_id": incident["website_id"],
            "approval_status": body.decision,
            "current_stage": "action",
            "message": "Human approval received. Action Agent is applying the selected response path.",
            "policy_decision": state.get("policy_decision"),
            "agent_trace": state.get("agent_trace"),
            "agent_messages": state.get("agent_messages"),
            "agent_discussion": state.get("agent_discussion"),
            "protocol_trace": state.get("protocol_trace"),
            "tool_trace": state.get("tool_trace"),
            "runtime_metadata": state.get("runtime_metadata", {}),
        },
    )

    loop = asyncio.get_event_loop()
    try:
        final_state = await loop.run_in_executor(None, mcp_coordinator.run_resolution_pipeline, state)
    except Exception as exc:
        _update_job(job_id, "failed", error=str(exc), metadata={"attack_id": incident_id, "phase": "resolution"})
        await broadcast(
            "agent_update",
            {
                "attack_id": incident_id,
                "website_id": incident["website_id"],
                "approval_status": body.decision,
                "current_stage": "resolution_failed",
                "message": f"Resolution pipeline failed after analyst decision: {exc}",
            },
        )
        raise
    final_state["website_id"] = incident["website_id"]
    final_state.setdefault("runtime_metadata", {})["stage2"] = get_stage2_runtime_summary()
    active_incidents[incident_id] = final_state
    _persist_incident(incident["website_id"], final_state)
    await broadcast(
        "incident_snapshot",
        {
            "attack_id": incident_id,
            "website_id": incident["website_id"],
            "simulation": final_state.get("simulation"),
            "telemetry": final_state.get("telemetry"),
            "anomaly": final_state.get("anomaly"),
            "correlation": final_state.get("correlation"),
            "classification": final_state.get("classification"),
            "challenge_review": final_state.get("challenge_review"),
            "investigation": final_state.get("investigation"),
            "mitigation_plan": final_state.get("mitigation_plan"),
            "policy_decision": final_state.get("policy_decision"),
            "approval_status": final_state.get("approval_status"),
            "notes": final_state.get("notes"),
            "assignee": final_state.get("assignee"),
            "action_result": final_state.get("action_result"),
            "incident_report": final_state.get("incident_report"),
            "agent_trace": final_state.get("agent_trace"),
            "agent_messages": final_state.get("agent_messages"),
            "agent_discussion": final_state.get("agent_discussion"),
            "protocol_trace": final_state.get("protocol_trace"),
            "tool_trace": final_state.get("tool_trace"),
            "runtime_metadata": final_state.get("runtime_metadata", {}),
            "llm_usage": final_state.get("llm_usage"),
            "current_stage": final_state.get("current_stage"),
            "message": "Human decision applied. The full resolved incident state is now available.",
        },
    )
    await broadcast(
        "observability_update",
        {
            "website_id": incident["website_id"],
            "attack_id": incident_id,
            "observability": _observability_snapshot(incident["website_id"]),
            "message": f"Approval flow completed with decision: {body.decision}.",
        },
    )
    _update_job(job_id, "completed", metadata={"attack_id": incident_id, "phase": "resolved"})

    await broadcast(
        "incident_resolved",
        {
            "attack_id": incident_id,
            "website_id": incident["website_id"],
            "approval_status": final_state.get("approval_status"),
            "current_stage": final_state.get("current_stage"),
            "action_result": final_state.get("action_result"),
            "incident_report": final_state.get("incident_report"),
            "policy_decision": final_state.get("policy_decision"),
            "agent_trace": final_state.get("agent_trace"),
            "agent_messages": final_state.get("agent_messages"),
            "agent_discussion": final_state.get("agent_discussion"),
            "protocol_trace": final_state.get("protocol_trace"),
            "tool_trace": final_state.get("tool_trace"),
            "runtime_metadata": final_state.get("runtime_metadata", {}),
            "llm_usage": final_state.get("llm_usage"),
            "message": "Reporting Agent generated the incident report.",
        },
    )
    return _serialize_incident_state(final_state, incident["website_id"])


@app.post("/websites/{website_id}/monitor/start")
async def start_auto_simulate(website_id: str, user=Depends(require_user)):
    global attack_running, auto_task, auto_website_id
    website = _get_website_or_404(user["_id"], website_id)
    if not attack_running:
        attack_running = True
        auto_website_id = website_id
        auto_task = asyncio.create_task(_auto_simulation_loop(website))
    return {"running": attack_running, "website_id": auto_website_id}


@app.post("/websites/{website_id}/monitor/stop")
async def stop_auto_simulate(website_id: str, user=Depends(require_user)):
    global attack_running, auto_task, auto_website_id
    _get_website_or_404(user["_id"], website_id)
    attack_running = False
    auto_website_id = None
    if auto_task:
        auto_task.cancel()
        with suppress(asyncio.CancelledError):
            await auto_task
        auto_task = None
    return {"running": attack_running, "website_id": website_id}
