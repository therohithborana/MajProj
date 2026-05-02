# CyberAgent — Autonomous AI SOC for Startups

CyberAgent is a multi-agent cybersecurity SaaS prototype for startup web applications. A startup creates a protected project, installs a lightweight collector, streams `access`, `auth`, and `network` telemetry, and lets AI/security agents detect, investigate, classify, and respond to threats with a `70% automation / 30% human oversight` model.

## What makes this a major-project style build
- Multi-tenant startup/project onboarding
- Collector-token based customer integration
- Normalized telemetry ingestion API
- Multi-agent orchestration for detection, correlation, classification, investigation, response, policy, action, and reporting
- Human-in-the-loop approvals for risky actions
- Dummy customer website integration lab for end-to-end demo

## Architecture
Collector Agent
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

## Setup

### 1. Backend prerequisites
- Python virtual environment
- MongoDB connection in `.env`
- Gemini API key if you want LLM-generated plans/reports

Example `.env`:

```env
GEMINI_API_KEY=your_key_here
MONGO_URI=mongodb://localhost:27017
MONGO_DB_NAME=cyberagent
```

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

## Dummy website demo flow
CyberAgent now includes two customer-side demo options:
- an embedded integration simulator in the main dashboard
- a separate standalone startup website in `dummy-site/` called `NovaCart`

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
7. Switch back to the dashboard and show the incident queue, policy decision, agent trace, and final report
8. Explain which threats were auto-contained and which required approval

## Core demo story
CyberAgent is not just a dashboard. It is a startup-focused AI SOC prototype where:
- collectors bring telemetry into the platform
- specialized agents collaborate on security decisions
- automation handles repetitive response work
- humans stay in control for higher-risk actions
