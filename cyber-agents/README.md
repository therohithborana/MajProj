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
