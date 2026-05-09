# CyberAgent — Multi-Agent Cybersecurity Orchestration

## Architecture
Red Team Agent (writes raw logs)
        ↓
Log Monitor Agent
        ↓
Anomaly Detection Agent
        ↓
Classification Agent
        ↓
Response Planning Agent (Gemini)
        ↓
Human Approval (Dashboard)
        ↓
Action Agent
        ↓
Reporting Agent (Gemini)

## Setup

### Prerequisites
- MongoDB running locally on `mongodb://localhost:27017`

### 1. Get Gemini API Key
Go to [https://aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)
Create a key and paste it in `.env`:

`GEMINI_API_KEY=your_key_here`

Mongo configuration:

`MONGO_URI=mongodb://localhost:27017`  
`MONGO_DB_NAME=cyberagent`

### 2. Backend
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### 3. Frontend
```bash
cd frontend
npm install
npm start
```

App: [http://localhost:3000](http://localhost:3000)  
API: [http://localhost:8000](http://localhost:8000)

## Real Log Ingestion

CyberAgent can now ingest real local web logs through `/collector/ingest`.

Supported inputs:
- nginx/apache combined access logs
- JSON request logs (`.jsonl`)
- live appended files on Windows

The real collector path is:

Local log file -> `backend/watchers/file_tailer.py` -> `/collector/ingest` -> MongoDB `telemetry_events` -> WebSocket `telemetry_event` -> existing incident pipeline.

### Collector Setup

1. Start MongoDB, backend, and frontend as usual.
2. Create or select a website in the dashboard.
3. Copy that website `_id` from the `/websites` API response or browser network response.
4. Create a collector config:

```powershell
cd backend
Copy-Item log_collectors\collector_config.example.json log_collectors\collector_config.json
```

Edit `log_collectors/collector_config.json` and set:

```json
{
  "api_base": "http://localhost:8000",
  "website_id": "your_website_id",
  "collector_key": "",
  "poll_seconds": 1,
  "offset_store": "log_collectors/.collector_offsets.json",
  "sources": [
    {
      "path": "C:/nginx/logs/access.log",
      "source_type": "access",
      "parser": "access"
    },
    {
      "path": "C:/path/to/request.jsonl",
      "source_type": "access",
      "parser": "json"
    }
  ]
}
```

Optional API key safety:

```powershell
$env:COLLECTOR_API_KEY="dev-secret"
```

If this is set on the backend, put the same value in `collector_key`.

### Run The Tailer

```powershell
cd backend
python -m watchers.file_tailer --config log_collectors\collector_config.json
```

Use `--from-start` when you want to ingest existing lines in the file:

```powershell
python -m watchers.file_tailer --config log_collectors\collector_config.json --from-start
```

The tailer stores byte offsets in `.collector_offsets.json`, so restarting it does not resend already-ingested lines. If a log rotates or shrinks, it safely resumes from the start of the new file.

### Direct Ingest Test

```powershell
Invoke-RestMethod -Method Post `
  -Uri http://localhost:8000/collector/ingest `
  -ContentType "application/json" `
  -Body '{"website_id":"YOUR_WEBSITE_ID","source_type":"access","parser":"json","raw_line":"{\"ip\":\"192.168.1.10\",\"endpoint\":\"/login\",\"status\":401,\"method\":\"POST\",\"user_agent\":\"demo-client\"}"}'
```

### Example Logs

nginx/apache access:

```text
192.168.1.10 - - [09/May/2026:00:00:03 +0530] "POST /login HTTP/1.1" 401 231 "-" "curl/8.0"
```

JSON request log:

```json
{"ip":"192.168.1.10","endpoint":"/login","status":401,"method":"POST","user_agent":"demo-json-client"}
```

Append several failed `/login` requests or a burst of mixed requests. The dashboard will first show realtime telemetry, then the backend debounces the batch and creates an incident candidate through the existing Log Monitor, Anomaly Detection, Classification, and Response Planning agents.

## Demo Flow
1. Create an account or log in
2. Create a website project and connect the demo website
3. Open the dashboard for that website
4. Click `Simulate attack`
5. Red Team writes synthetic access, auth, and network log entries
6. Log Monitor Agent reads the latest telemetry from monitored log files
7. Anomaly Detection Agent flags suspicious behavior
8. Classification Agent converts that evidence into a structured incident
9. Gemini generates a mitigation plan
10. Admin approves or rejects on dashboard
11. Action Agent executes or escalates
12. Gemini writes the final incident report

## Real Log Demo Flow

1. Start backend and frontend.
2. Create a website in the dashboard.
3. Put that website id into `backend/log_collectors/collector_config.json`.
4. Run `python -m watchers.file_tailer --config log_collectors\collector_config.json --from-start`.
5. Append real nginx/apache lines or JSON request lines to the configured files.
6. Watch `Realtime telemetry` update in the dashboard.
7. After a short debounce window, CyberAgent creates an incident candidate using the same existing pipeline.
