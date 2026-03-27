# CyberAgent — Multi-Agent Cybersecurity Orchestration

## Architecture
Red Team Agent → Threat Detection Agent → Threat Resolve Agent (Gemini)
                                                 ↓
                                      Human Approval (Dashboard)
                                                 ↓
                              Action Agent → Incident Report (Gemini)

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
2. Red Team generates attack
3. Threat Detection classifies with ML model
4. Gemini generates dynamic mitigation plan
5. Admin approves or rejects on dashboard
6. Action Agent executes response
7. Gemini writes incident report
