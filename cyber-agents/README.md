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

### 1. Get Gemini API Key
Go to [https://aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)
Create a key and paste it in `.env`:

`GEMINI_API_KEY=your_key_here`

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

## Demo Flow
1. Click `SIMULATE ATTACK`
2. Red Team writes synthetic access, auth, and network log entries
3. Log Monitor Agent reads the latest telemetry from monitored log files
4. Anomaly Detection Agent flags suspicious behavior
5. Classification Agent converts that evidence into a structured incident
6. Gemini generates a mitigation plan
7. Admin approves or rejects on dashboard
8. Action Agent executes or escalates
9. Gemini writes the final incident report
