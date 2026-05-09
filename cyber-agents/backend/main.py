import asyncio
import os
import uuid
from contextlib import suppress
from pathlib import Path
from typing import Optional

from bson import ObjectId
from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pymongo.errors import DuplicateKeyError

from agents import action_graph, detection_graph
from auth import require_user
from db import db, init_db
from log_collectors.normalizer import event_to_access_line, event_to_auth_line, normalize_event
from models import ApprovalRequest, CollectorIngestRequest, serialize_document, utc_now
from parsers import parse_log_line
from red_team import simulate_attack
from routes.auth import router as auth_router
from routes.websites import router as websites_router


BASE_DIR = Path(__file__).resolve().parent
RUNTIME_LOG_DIR = BASE_DIR / "runtime_logs"
RUNTIME_LOG_DIR.mkdir(parents=True, exist_ok=True)

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
real_pipeline_tasks = {}
real_pipeline_last_run = {}
REAL_PIPELINE_DEBOUNCE_SECONDS = int(os.getenv("REAL_PIPELINE_DEBOUNCE_SECONDS", "8"))
REAL_PIPELINE_MIN_EVENTS = int(os.getenv("REAL_PIPELINE_MIN_EVENTS", "5"))
COLLECTOR_API_KEY = os.getenv("COLLECTOR_API_KEY", "").strip()


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
        "current_stage": state.get("current_stage"),
        "simulation": state.get("simulation"),
        "telemetry": state.get("telemetry"),
        "anomaly": state.get("anomaly"),
        "classification": state.get("classification"),
        "mitigation_plan": state.get("mitigation_plan"),
        "approval_status": state.get("approval_status"),
        "action_result": state.get("action_result"),
        "incident_report": state.get("incident_report"),
        "created_at": now,
        "updated_at": now,
    }
    existing = db.incidents.find_one({"attack_id": attack_id})
    if existing:
        document["created_at"] = existing.get("created_at", now)
    db.incidents.update_one({"attack_id": attack_id}, {"$set": document}, upsert=True)


def _serialize_event(event: dict):
    return serialize_document(event)


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


async def _run_detection_pipeline(website: dict):
    runtime_log_paths = ((website.get("dummy_site") or {}).get("runtime_log_paths")) or {}
    if not runtime_log_paths:
        raise HTTPException(status_code=400, detail="Website is not connected to a demo source")

    simulation = simulate_attack(str(Path(runtime_log_paths["access"]).parent))
    attack_id = simulation["attack_id"]
    initial_state = {
        "simulation": simulation,
        "telemetry": None,
        "anomaly": None,
        "classification": None,
        "mitigation_plan": None,
        "approval_status": None,
        "action_result": None,
        "incident_report": None,
        "current_stage": "red_team_attacking",
    }

    await broadcast(
        "red_team_attack",
        {
            "attack_id": attack_id,
            "website_id": website["_id"],
            "simulation": simulation,
            "current_stage": "red_team_attacking",
            "message": f"Red Team Agent generated telemetry for {website['name']}.",
        },
    )
    await asyncio.sleep(0.8)
    await broadcast(
        "agent_update",
        {
            "attack_id": attack_id,
            "website_id": website["_id"],
            "current_stage": "log_monitoring",
            "message": "Log Monitor Agent is collecting fresh access, auth, and network logs.",
        },
    )
    await asyncio.sleep(0.8)

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, detection_graph.invoke, initial_state)
    result["website_id"] = website["_id"]

    await broadcast(
        "agent_update",
        {
            "attack_id": attack_id,
            "website_id": website["_id"],
            "telemetry": result.get("telemetry"),
            "current_stage": "log_monitoring",
            "message": "Log Monitor Agent ingested recent telemetry from the monitored log files.",
        },
    )
    await asyncio.sleep(0.8)
    await broadcast(
        "agent_update",
        {
            "attack_id": attack_id,
            "website_id": website["_id"],
            "anomaly": result.get("anomaly"),
            "current_stage": "anomaly_detected",
            "message": "Anomaly Detection Agent flagged suspicious behavior from the monitored logs.",
        },
    )
    await asyncio.sleep(0.8)
    await broadcast(
        "agent_update",
        {
            "attack_id": attack_id,
            "website_id": website["_id"],
            "classification": result.get("classification"),
            "current_stage": "classified",
            "message": "Classification Agent converted anomaly evidence into a structured incident.",
        },
    )
    await asyncio.sleep(0.8)
    await broadcast(
        "agent_update",
        {
            "attack_id": attack_id,
            "website_id": website["_id"],
            "mitigation_plan": result.get("mitigation_plan"),
            "approval_status": result.get("approval_status"),
            "current_stage": "awaiting_approval",
            "message": "Response Planning Agent generated a mitigation plan — awaiting admin approval.",
        },
    )

    active_incidents[attack_id] = result
    _persist_incident(website["_id"], result)
    return attack_id


def _build_real_simulation(website: dict, events: list[dict]):
    access_lines = [event_to_access_line(event) for event in events]
    auth_lines = [line for line in (event_to_auth_line(event) for event in events) if line]
    primary_ip = events[-1].get("ip", "unknown") if events else "unknown"
    attack_id = f"REAL-{uuid.uuid4().hex[:8].upper()}"
    now = utc_now().isoformat()
    target_port = 443 if str(website.get("domain", "")).startswith("https") else 80
    return {
        "attack_id": attack_id,
        "timestamp": now,
        "description": f"Real log telemetry ingested from {website.get('name', 'a monitored website')}.",
        "attack_profile": {
            "attack_type": "RealLogTelemetry",
            "severity": "MEDIUM",
            "src_ips": sorted({event.get("ip", "unknown") for event in events})[:20],
            "primary_src_ip": primary_ip,
            "target_ip": website.get("domain") or "local-service",
            "target_port": target_port,
            "protocol": "HTTP",
            "packet_rate": max(1, len(events)),
        },
        "telemetry": {
            "log_paths": {},
            "generated_logs": {
                "access": access_lines,
                "auth": auth_lines,
                "network": [],
            },
        },
        "source": "real_log_collector",
    }


async def _run_real_detection_pipeline(website_id: str):
    real_pipeline_tasks.pop(website_id, None)
    real_pipeline_last_run[website_id] = asyncio.get_event_loop().time()
    website = db.websites.find_one({"_id": ObjectId(website_id)})
    if not website:
        return

    events = [
        serialize_document(document)
        for document in db.telemetry_events.find({"website_id": website_id}).sort("received_at", -1).limit(80)
    ]
    events.reverse()
    if len(events) < REAL_PIPELINE_MIN_EVENTS:
        return

    simulation = _build_real_simulation(serialize_document(website), events)
    initial_state = {
        "simulation": simulation,
        "telemetry": None,
        "anomaly": None,
        "classification": None,
        "mitigation_plan": None,
        "approval_status": None,
        "action_result": None,
        "incident_report": None,
        "current_stage": "log_monitoring",
    }

    await broadcast(
        "agent_update",
        {
            "attack_id": simulation["attack_id"],
            "website_id": website_id,
            "simulation": simulation,
            "current_stage": "log_monitoring",
            "message": f"Real Log Collector batched {len(events)} events for analysis.",
        },
    )

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, detection_graph.invoke, initial_state)
    result["website_id"] = website_id
    active_incidents[simulation["attack_id"]] = result
    _persist_incident(website_id, result)

    await broadcast(
        "agent_update",
        {
            "attack_id": simulation["attack_id"],
            "website_id": website_id,
            "telemetry": result.get("telemetry"),
            "anomaly": result.get("anomaly"),
            "classification": result.get("classification"),
            "mitigation_plan": result.get("mitigation_plan"),
            "approval_status": result.get("approval_status"),
            "current_stage": result.get("current_stage"),
            "message": "CyberAgent analyzed real ingested logs and created an incident candidate.",
        },
    )


def _schedule_real_pipeline(website_id: str):
    if website_id in real_pipeline_tasks:
        return
    now = asyncio.get_event_loop().time()
    last_run = real_pipeline_last_run.get(website_id, 0)
    delay = max(REAL_PIPELINE_DEBOUNCE_SECONDS, REAL_PIPELINE_DEBOUNCE_SECONDS - int(now - last_run))
    real_pipeline_tasks[website_id] = asyncio.create_task(_delayed_real_pipeline(website_id, delay))


async def _delayed_real_pipeline(website_id: str, delay: int):
    await asyncio.sleep(delay)
    await _run_real_detection_pipeline(website_id)


async def _auto_simulation_loop(website: dict):
    global attack_running
    while attack_running:
        await _run_detection_pipeline(website)
        for _ in range(15):
            if not attack_running:
                break
            await asyncio.sleep(1)


def _validate_collector_key(x_collector_key: Optional[str]):
    if COLLECTOR_API_KEY and x_collector_key != COLLECTOR_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid collector key")


@app.post("/collector/ingest")
async def collector_ingest(payload: CollectorIngestRequest, x_collector_key: Optional[str] = Header(default=None)):
    _validate_collector_key(x_collector_key)
    try:
        website_object_id = ObjectId(payload.website_id)
    except Exception as exc:
        raise HTTPException(status_code=404, detail="Website not found") from exc

    website = db.websites.find_one({"_id": website_object_id})
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")

    try:
        parsed = payload.event or parse_log_line(payload.raw_line or "", payload.parser)
        normalized = normalize_event(parsed, payload.website_id, payload.source_type)
        db.telemetry_events.insert_one(normalized)
    except DuplicateKeyError:
        return {"status": "duplicate", "website_id": payload.website_id}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    db.websites.update_one(
        {"_id": website_object_id},
        {
            "$set": {
                "connection_type": "real_logs",
                "status": "connected",
                "last_event_at": normalized["received_at"],
                "updated_at": utc_now(),
            }
        },
    )

    event_payload = _serialize_event(normalized)
    await broadcast(
        "telemetry_event",
        {
            "website_id": payload.website_id,
            "event": event_payload,
            "message": f"{normalized['method']} {normalized['path']} returned {normalized['status']} from {normalized['ip']}.",
        },
    )
    _schedule_real_pipeline(payload.website_id)
    return {"status": "ingested", "website_id": payload.website_id, "event": event_payload}


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


@app.post("/websites/{website_id}/simulate")
async def simulate_for_website(website_id: str, user=Depends(require_user)):
    website = _get_website_or_404(user["_id"], website_id)
    attack_id = await _run_detection_pipeline(website)
    return {"status": "pipeline_running", "incident_id": attack_id, "website_id": website_id}


@app.get("/websites/{website_id}/incidents")
async def list_incidents_for_website(website_id: str, user=Depends(require_user)):
    _get_website_or_404(user["_id"], website_id)
    incidents = [
        serialize_document(document)
        for document in db.incidents.find({"website_id": website_id}).sort("created_at", -1)
    ]
    return incidents


@app.get("/incidents/{incident_id}")
async def get_incident(incident_id: str, user=Depends(require_user)):
    incident = db.incidents.find_one({"attack_id": incident_id})
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    website = db.websites.find_one(_website_query(user["_id"], incident["website_id"]))
    if not website:
        raise HTTPException(status_code=404, detail="Incident not found")
    return serialize_document(incident)


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
        "simulation": incident.get("simulation"),
        "telemetry": incident.get("telemetry"),
        "anomaly": incident.get("anomaly"),
        "classification": incident.get("classification"),
        "mitigation_plan": incident.get("mitigation_plan"),
        "approval_status": body.decision,
        "action_result": incident.get("action_result"),
        "incident_report": incident.get("incident_report"),
        "current_stage": incident.get("current_stage"),
        "website_id": incident.get("website_id"),
    }
    active_incidents[incident_id] = state

    await broadcast(
        "agent_update",
        {
            "attack_id": incident_id,
            "website_id": incident["website_id"],
            "approval_status": body.decision,
            "current_stage": "action_executing",
            "message": "Action Agent is applying the approved response path.",
        },
    )
    await asyncio.sleep(0.8)

    loop = asyncio.get_event_loop()
    final_state = await loop.run_in_executor(None, action_graph.invoke, state)
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
