# CyberAgent — Autonomous AI SOC for Startups

CyberAgent is a multi-agent cybersecurity SaaS prototype for startup web applications. A startup creates a protected project, installs a lightweight collector, streams `access`, `auth`, and `network` telemetry, and lets AI/security agents detect, investigate, classify, and respond to threats with a `70% automation / 30% human oversight` model.

The project now includes:
- `MCP tools` as the primary tool/runtime architecture
- `A2A` for agent-to-agent invocation contracts
- `AG-UI` for frontend-facing event streams
- a `Google ADK-compatible coordinator runtime` pattern for the root SOC orchestrator
- a `Stage 2 Google ADK native reasoning slice` for classification, investigation, and policy review

This is intentionally a practical migration step, not a risky full rewrite. The current backend still uses the working CyberAgent logic, but it now exposes:
- an `MCP` tool registry and `tools/call` execution surface as the primary orchestration runtime
- named agent services and A2A-style agent cards as optional protocol surfaces
- AG-UI event streams over the same incident pipeline

## What makes this a major-project style build
- Multi-tenant startup/project onboarding
- Collector-token based customer integration
- Normalized telemetry ingestion API
- Multi-agent orchestration for detection, correlation, classification, investigation, response, policy, action, and reporting
- A2A-style coordinator and per-agent invoke surface
- AG-UI compatible incident event streaming
- Human-in-the-loop approvals for risky actions
- Standalone dummy customer website integration lab for end-to-end demo

## Architecture
Collector Agent
        ↓
SOC Coordinator Agent (ADK-compatible root runtime)
        ↓
Normalization Agent
        ↓
Detection Agent
        ↓
Correlation Agent
        ↓
Threat Classification Agent
        ↓
Investigation Agent
        ↓
Response Planning Agent
        ↓
Policy Agent
        ↓
Action Agent
        ↓
Reporting Agent

## Protocol surfaces

### MCP
CyberAgent now exposes:
- `POST /mcp`
- `GET /mcp/tools`

Supported JSON-RPC methods:
- `initialize`
- `tools/list`
- `tools/call`

The primary multi-agent runtime now uses MCP-style tools for:
- telemetry normalization
- detection
- correlation
- classification
- investigation
- mitigation planning
- policy review
- action execution
- report generation

### A2A
CyberAgent now exposes:
- `GET /a2a/agents`
- `GET /a2a/soc_coordinator/agent-card.json`
- `GET /a2a/agents/{agent_name}/agent-card.json`
- `POST /a2a/agents/{agent_name}/invoke`
- `POST /a2a/soc_coordinator/run`

These endpoints let you inspect the available agents, their contracts, and invoke them through a standardized agent-to-agent style envelope.

### AG-UI
CyberAgent also exposes:
- `POST /agui/runs`

This returns an `AG-UI` event stream with:
- `RUN_STARTED`
- `STATE_SNAPSHOT`
- `TOOL_CALL_START / TOOL_CALL_ARGS / TOOL_CALL_END / TOOL_CALL_RESULT`
- `STATE_DELTA`
- `TEXT_MESSAGE_*`
- `RUN_FINISHED`

For this project, AG-UI is used to stream incident execution state for the SOC UI layer.

## Stage 2 runtime

CyberAgent now also exposes a Stage 2 runtime based on the official `google-adk` package.

What Stage 2 changes:
- `Threat Classification Agent` now prefers a native ADK runner
- `Investigation Agent` now prefers a native ADK runner
- `Policy Agent` now prefers a native ADK runner
- those same agents are also mounted as real ADK A2A apps

Stage 2 runtime discovery:
- `GET /stage2/runtime`

Mounted Stage 2 A2A apps:
- `/stage2/a2a/classification`
- `/stage2/a2a/investigation`
- `/stage2/a2a/policy`

This means the project now has:
- MCP tools as the active orchestration runtime
- Stage 1 coordinator/protocol tracing across the full pipeline
- optional Stage 2 native ADK reasoning surfaces for experimentation

## Setup

### 1. Backend prerequisites
- Python virtual environment
- MongoDB connection in `.env`
- Gemini API key if you want LLM-generated plans/reports

Example `.env`:

```env
GEMINI_API_KEY=your_key_here
GOOGLE_API_KEY=your_key_here
MONGO_URI=mongodb://localhost:27017
MONGO_DB_NAME=cyberagent
```

If `GOOGLE_API_KEY` is not set, the backend will try to reuse `GEMINI_API_KEY` for the Stage 2 ADK runtime.

### 2. Run backend
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### 3. Run frontend
```bash
cd frontend
npm install
npm start
```

Frontend: [http://localhost:3000](http://localhost:3000)  
Backend: [http://localhost:8000](http://localhost:8000)

### 4. Run the standalone dummy customer website
```bash
cd dummy-site
python3 -m http.server 3001
```

Dummy customer website: [http://localhost:3001](http://localhost:3001)

## Collector integration model
Each protected project gets a unique collector token.

The customer-side collector sends:
- `POST /collector/ingest`
- header: `X-Collector-Token: <project-token>`
- body: normalized event batch containing `access`, `auth`, or `network` events

Sample customer collector script:
- [backend/collector_agent.py](/Users/rohithborana/stuf/MajProj/cyber-agents/backend/collector_agent.py)

Environment variables for the sample collector:

```bash
export CYBERAGENT_API_BASE=http://localhost:8000
export CYBERAGENT_COLLECTOR_TOKEN=<paste-dashboard-token>
export CYBERAGENT_SOURCE_LABEL="NovaCart demo collector"
python backend/collector_agent.py
```

The project integration endpoint also includes protocol discovery metadata:
- `GET /websites/{website_id}/integration`

## Dummy website demo flow
CyberAgent includes a separate standalone startup website in `dummy-site/` called `NovaCart`.

Use it to demonstrate:
1. normal user browsing
2. failed login bursts
3. suspicious recon against sensitive paths
4. traffic spikes / DDoS-like behavior

Those actions send real collector telemetry into the backend using the project token, so the demo website is not just visual: it is connected to the platform.

## Recommended presentation flow
1. Create a protected project in the dashboard
2. Copy the collector token
3. Start the standalone dummy website on port `3001`
4. Paste the token into the NovaCart setup panel and click `Save config`
5. Trigger `Send normal traffic` or `Login as customer` to show healthy telemetry
6. Trigger `Simulate brute force`, `Simulate recon`, or `Simulate traffic spike`
7. Switch back to the dashboard and show the incident queue, policy decision, A2A-style agent trace, and final report
8. Optionally open the A2A registry or AG-UI stream endpoint to demonstrate that the same incident is also exposed through agent protocols
9. Explain which threats were auto-contained and which required approval

## Core demo story
CyberAgent is not just a dashboard. It is a startup-focused AI SOC prototype where:
- collectors bring telemetry into the platform
- specialized agents collaborate on security decisions through explicit agent contracts
- automation handles repetitive response work
- humans stay in control for higher-risk actions
