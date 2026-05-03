import asyncio
from contextlib import suppress
from datetime import datetime, timezone
import json
import uuid

from bson import ObjectId
from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from agent_protocols import (
    AGUI_CONTENT_TYPE,
    SocA2ACoordinator,
    agui_sse,
    build_agui_event_stream,
)
from auth import require_collector, require_user
from db import db, init_db
from models import AGUIRunRequest, A2AInvokeRequest, ApprovalRequest, CollectorIngestRequest, serialize_document, utc_now
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

active_incidents = {}
connected_clients = []
attack_running = False
auto_task = None
auto_website_id = None
coordinator = SocA2ACoordinator()

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
        "protocol_trace": state.get("protocol_trace", []),
        "runtime_metadata": state.get("runtime_metadata", {}),
        "llm_usage": state.get("llm_usage", {}),
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
    for entry in state.get("agent_trace", []):
        public_name = stage_to_protocol_agent.get(entry["stage"])
        await broadcast(
            "agent_update",
            {
                "attack_id": attack_id,
                "website_id": website_id,
                "current_stage": entry["stage"],
                "message": entry["summary"],
                "agent_trace_entry": entry,
                "protocol_trace_entry": protocol_lookup.get(public_name),
                "policy_decision": state.get("policy_decision"),
                "runtime_metadata": state.get("runtime_metadata", {}),
            },
        )
        await asyncio.sleep(0.3)


async def _run_detection_pipeline(website: dict, attack_id: str, simulation: dict):
    initial_state = {
        "website": website,
        "simulation": simulation,
        "telemetry": None,
        "anomaly": None,
        "correlation": None,
        "classification": None,
        "investigation": None,
        "mitigation_plan": None,
        "policy_decision": None,
        "approval_status": None,
        "action_result": None,
        "incident_report": None,
        "agent_trace": [],
        "agent_messages": [],
        "llm_usage": {},
        "current_stage": "collector_ingested",
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
    result = await loop.run_in_executor(None, coordinator.run_detection_pipeline, initial_state)
    result["website_id"] = website["_id"]

    await _broadcast_trace(website["_id"], attack_id, result)

    active_incidents[attack_id] = result
    _persist_incident(website["_id"], result)

    if result.get("policy_decision", {}).get("mode") == "auto_execute":
        await broadcast(
            "agent_update",
            {
                "attack_id": attack_id,
                "website_id": website["_id"],
                "current_stage": "action",
                "message": "Policy Agent auto-approved the response path. Action Agent is executing it now.",
                "policy_decision": result.get("policy_decision"),
            },
        )
        final_state = await loop.run_in_executor(
            None,
            coordinator.run_resolution_pipeline,
            {**result, "approval_status": "auto_approved"},
        )
        final_state["website_id"] = website["_id"]
        active_incidents[attack_id] = final_state
        _persist_incident(website["_id"], final_state)
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
                "protocol_trace": final_state.get("protocol_trace"),
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
                "runtime_metadata": result.get("runtime_metadata", {}),
            },
        )
    else:
        final_state = await loop.run_in_executor(
            None,
            coordinator.run_resolution_pipeline,
            {**result, "approval_status": "manual_required"},
        )
        final_state["website_id"] = website["_id"]
        active_incidents[attack_id] = final_state
        _persist_incident(website["_id"], final_state)
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
                "protocol_trace": final_state.get("protocol_trace"),
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
        await _run_detection_pipeline(website, attack_id, simulation)
        for _ in range(15):
            if not attack_running:
                break
            await asyncio.sleep(1)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    incidents = [serialize_document(document) for document in db.incidents.find({}).sort("created_at", -1)]
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
    normalized_events = _store_events(website, attack_id, [event.model_dump() for event in payload.events])
    telemetry_snapshot = _telemetry_snapshot(website["_id"])
    await broadcast(
        "telemetry_update",
        {
            "website_id": website["_id"],
            "attack_id": attack_id,
            "events_ingested": len(normalized_events),
            "source_label": payload.source_label,
            "run_detection": payload.run_detection,
            "telemetry": telemetry_snapshot,
            "recent_events": telemetry_snapshot["recent_events"][: min(4, len(telemetry_snapshot["recent_events"]))],
            "message": f"Collector received {len(normalized_events)} event(s) from {payload.source_label or 'customer website'}.",
        },
    )
    if payload.run_detection and attack_id:
        simulation = _build_collector_simulation(website["_id"], attack_id, payload.source_label)
        await _run_detection_pipeline(website, attack_id, simulation)
    return {
        "status": "accepted",
        "website_id": website["_id"],
        "attack_id": attack_id,
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
    await _run_detection_pipeline(website, attack_id, simulation)
    return {"status": "pipeline_running", "incident_id": attack_id, "website_id": website_id}


@app.get("/websites/{website_id}/incidents")
async def list_incidents_for_website(website_id: str, user=Depends(require_user)):
    _get_website_or_404(user["_id"], website_id)
    incidents = [
        serialize_document(document)
        for document in db.incidents.find({"website_id": website_id}).sort("created_at", -1)
    ]
    return incidents


@app.get("/websites/{website_id}/telemetry")
async def website_telemetry(website_id: str, user=Depends(require_user)):
    _get_website_or_404(user["_id"], website_id)
    return _telemetry_snapshot(website_id)


@app.get("/incidents/{incident_id}")
async def get_incident(incident_id: str, user=Depends(require_user)):
    incident = db.incidents.find_one({"attack_id": incident_id})
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    website = db.websites.find_one(_website_query(user["_id"], incident["website_id"]))
    if not website:
        raise HTTPException(status_code=404, detail="Incident not found")
    return serialize_document(incident)


@app.get("/a2a/agents")
async def list_a2a_agents():
    base_url = "http://localhost:8000"
    return {
        "root_agent": coordinator.root_card(base_url),
        "agents": coordinator.agent_cards(base_url),
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

    state = {
        "website": serialize_document(website),
        "simulation": incident.get("simulation"),
        "telemetry": incident.get("telemetry"),
        "anomaly": incident.get("anomaly"),
        "correlation": incident.get("correlation"),
        "classification": incident.get("classification"),
        "investigation": incident.get("investigation"),
        "mitigation_plan": incident.get("mitigation_plan"),
        "policy_decision": incident.get("policy_decision"),
        "approval_status": body.decision,
        "action_result": incident.get("action_result"),
        "incident_report": incident.get("incident_report"),
        "agent_trace": incident.get("agent_trace", []),
        "agent_messages": incident.get("agent_messages", []),
        "protocol_trace": incident.get("protocol_trace", []),
        "runtime_metadata": incident.get("runtime_metadata", {}),
        "llm_usage": incident.get("llm_usage", {}),
        "current_stage": incident.get("current_stage"),
    }
    active_incidents[incident_id] = state

    await broadcast(
        "agent_update",
        {
            "attack_id": incident_id,
            "website_id": incident["website_id"],
            "approval_status": body.decision,
            "current_stage": "action",
            "message": "Human approval received. Action Agent is applying the selected response path.",
        },
    )

    loop = asyncio.get_event_loop()
    final_state = await loop.run_in_executor(None, coordinator.run_resolution_pipeline, state)
    final_state["website_id"] = incident["website_id"]
    active_incidents[incident_id] = final_state
    _persist_incident(incident["website_id"], final_state)

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
            "protocol_trace": final_state.get("protocol_trace"),
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
