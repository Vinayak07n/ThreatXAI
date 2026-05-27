# ThreatXAI

ThreatXAI is an explainable intrusion detection system (XAI-IDS) with a full-stack dashboard, live packet capture, model explainability, campaign clustering, and SOC analyst chat support.

## Features

- Multi-model IDS inference: `xgboost`, `rf`, `dnn`, `hybrid`
- Explainability with SHAP/LIME
- EDAC (Explanation-Driven Alert Clustering) for attack campaign grouping
- Live packet capture + inference pipeline using Scapy
- Analyst Chat with persistent sessions (Groq-backed)
- PDF report export for alerts and chat sessions
- React dashboard for alerts, clusters, metrics, and model comparison

## Tech Stack

- Backend: FastAPI, SQLAlchemy, SQLite
- Frontend: React + Vite
- ML: scikit-learn, XGBoost, TensorFlow/Keras, SHAP, LIME
- Networking: Scapy
- LLM: Groq API

## Project Structure

```text
threatxai_8thsem/
├── backend/
│   ├── main.py
│   ├── config.json
│   ├── db/
│   ├── routers/
│   └── services/
├── frontend/
│   ├── src/
│   └── package.json
├── ml/
│   ├── preprocess.py
│   ├── train.py
│   ├── evaluate.py
│   ├── edac.py
│   ├── hybrid_model.py
│   ├── synthetic_dataset.py
│   └── models/
├── requirements.txt
├── run.sh
└── run_backend.py
```

## Prerequisites

- Python 3.10+
- Node.js 18+
- npm
- (Optional for live capture) `sudo` privileges on macOS/Linux
- (Optional for analyst chat) Groq API key

## Installation

```bash
git clone https://github.com/DharaneeshKuruba/ThreatXAI.git
cd ThreatXAI

python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

pip install -r requirements.txt
cd frontend && npm install && cd ..
```

## Environment Variables

Create a `.env` file in project root:

```env
GROQ_API_KEY=your_groq_api_key
GROQ_API_BASE=https://api.groq.com/openai/v1
GROQ_MODEL=llama-3.3-70b-versatile
GROQ_FALLBACK_MODELS=llama-3.1-8b-instant
```

## Run the App

### Option 1: One-command startup

```bash
bash run.sh
```

- Backend: `http://localhost:8000`
- Frontend: `http://localhost:5173`
- API docs: `http://localhost:8000/docs`

### Option 2: Manual startup

Terminal 1 (backend):
```bash
source .venv/bin/activate
python run_backend.py
```

Terminal 2 (frontend):
```bash
cd frontend
npm run dev
```

## ML Pipeline (Train / Retrain)

```bash
source .venv/bin/activate
python ml/preprocess.py
python ml/train.py
python ml/evaluate.py
python ml/edac.py
```

Or with the quick script:
```bash
bash run.sh --train
```

## Core API Endpoints

### Health & Metrics

- `GET /` - API info
- `GET /health` - model/service health
- `GET /metrics` - current dataset model metrics
- `GET /metrics/comparison` - current vs CICIDS metrics

### Prediction & Explainability

- `POST /predict`
- `POST /explain/shap`
- `POST /explain/lime`

Example prediction request:
```bash
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{
    "features": [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9],
    "src_ip": "10.0.0.5",
    "dst_ip": "8.8.8.8",
    "protocol": "TCP",
    "model_type": "xgboost"
  }'
```

### Alerts & Campaign Clusters

- `GET /alerts`
- `GET /alerts/{alert_id}`
- `GET /clusters`
- `GET /clusters/stats/summary`
- `GET /clusters/{cluster_id}`

### Packet Capture

- `POST /capture/start`
- `POST /capture/stop`
- `GET /capture/status`
- `GET /capture/info`

### Analyst Chat

- `GET /analyst/sessions`
- `POST /analyst/sessions`
- `GET /analyst/sessions/{session_id}/messages`
- `DELETE /analyst/sessions/{session_id}`
- `POST /analyst/chat`

### Reports

- `GET /reports/alerts/pdf`
- `GET /reports/chat/{session_id}/pdf`

## Notes

- Trained models and artifacts are expected in `ml/models/`.
- If no trained model exists, inference endpoints may return service/model load errors.
- Live packet capture may require elevated privileges and can fall back to demo behavior depending on host permissions.

## License

Add your preferred license here (MIT/Apache-2.0/etc.).
