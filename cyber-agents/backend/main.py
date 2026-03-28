import asyncio
from contextlib import suppress
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from agents import action_graph, detection_graph
from red_team import simulate_attack


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

active_incidents = {}
connected_clients = []
attack_running = False
auto_task = None


class ApprovalRequest(BaseModel):
    decision: str


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


async def _run_detection_pipeline():
    simulation = simulate_attack(str(RUNTIME_LOG_DIR))
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
            "simulation": simulation,
            "current_stage": "red_team_attacking",
            "message": "Red Team Agent generated raw access, auth, and network telemetry.",
        },
    )
    await asyncio.sleep(0.8)
    await broadcast(
        "agent_update",
        {
            "attack_id": attack_id,
            "current_stage": "log_monitoring",
            "message": "Log Monitor Agent is collecting fresh access, auth, and network logs.",
        },
    )
    await asyncio.sleep(0.8)

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, detection_graph.invoke, initial_state)

    await broadcast(
        "agent_update",
        {
            "attack_id": attack_id,
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
            "mitigation_plan": result.get("mitigation_plan"),
            "approval_status": result.get("approval_status"),
            "current_stage": "awaiting_approval",
            "message": "Response Planning Agent generated a mitigation plan — awaiting admin approval.",
        },
    )

    active_incidents[attack_id] = result
    return attack_id


async def _auto_simulation_loop():
    global attack_running
    while attack_running:
        await _run_detection_pipeline()
        for _ in range(15):
            if not attack_running:
                break
            await asyncio.sleep(1)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    await websocket.send_json(
        {
            "type": "init",
            "data": {
                "incidents": list(active_incidents.values()),
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


@app.post("/simulate")
async def simulate():
    attack_id = await _run_detection_pipeline()
    return {"status": "pipeline_running", "incident_id": attack_id}


@app.get("/incidents")
async def list_incidents():
    return list(active_incidents.values())


@app.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):
    incident = active_incidents.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.post("/incidents/{incident_id}/approve")
async def approve_incident(incident_id: str, body: ApprovalRequest):
    incident = active_incidents.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if body.decision not in {"approved", "rejected"}:
        raise HTTPException(status_code=400, detail="Decision must be approved or rejected")

    incident["approval_status"] = body.decision
    active_incidents[incident_id] = incident

    await broadcast(
        "agent_update",
        {
            "attack_id": incident_id,
            "approval_status": body.decision,
            "current_stage": "action_executing",
            "message": "Action Agent is applying the approved response path.",
        },
    )
    await asyncio.sleep(0.8)

    loop = asyncio.get_event_loop()
    final_state = await loop.run_in_executor(None, action_graph.invoke, incident)
    active_incidents[incident_id] = final_state

    await broadcast(
        "incident_resolved",
        {
            "attack_id": incident_id,
            "approval_status": final_state.get("approval_status"),
            "current_stage": final_state.get("current_stage"),
            "action_result": final_state.get("action_result"),
            "incident_report": final_state.get("incident_report"),
            "message": "Reporting Agent generated the incident report.",
        },
    )
    return final_state


@app.post("/auto-simulate")
async def start_auto_simulate():
    global attack_running, auto_task
    if not attack_running:
        attack_running = True
        auto_task = asyncio.create_task(_auto_simulation_loop())
    return {"running": attack_running}


@app.post("/auto-simulate/stop")
async def stop_auto_simulate():
    global attack_running, auto_task
    attack_running = False
    if auto_task:
        auto_task.cancel()
        with suppress(asyncio.CancelledError):
            await auto_task
        auto_task = None
    return {"running": attack_running}
