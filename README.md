# ThreatXAI

## Explainable AI for Threat Detection

ThreatXAI is an Explainable Intrusion Detection System (XAI-IDS) designed to combine machine-learning-based network threat detection with transparent and interpretable security analysis.

The system integrates multiple machine learning models, SHAP and LIME explainability, attack campaign clustering, live packet capture, and a full-stack security dashboard to help security analysts understand and investigate detected threats.

---

## 🚀 Features

- **Multi-Model Intrusion Detection**
  - XGBoost
  - Random Forest
  - Deep Neural Network (DNN)
  - Hybrid/Ensemble model

- **Explainable AI**
  - SHAP-based global and local explanations
  - LIME-based local explanations
  - Feature-level contribution analysis

- **Attack Campaign Clustering**
  - EDAC (Explanation-Driven Alert Clustering)
  - Groups related security alerts into attack campaigns
  - Helps reduce alert fatigue during security analysis

- **Live Network Monitoring**
  - Live packet capture using Scapy
  - Packet preprocessing and model inference
  - Real-time threat detection pipeline

- **SOC Analyst Assistance**
  - Analyst Chat
  - Persistent chat sessions
  - AI-assisted security analysis using Groq API

- **Security Dashboard**
  - Threat alerts
  - Campaign clusters
  - Model performance metrics
  - Prediction results
  - Explainability visualizations

- **Report Generation**
  - PDF reports for security alerts
  - PDF reports for analyst chat sessions

---

# 🏗️ System Architecture

The ThreatXAI system consists of several major components:

```text
                    ┌──────────────────────┐
                    │   Network Traffic    │
                    │   / Packet Capture   │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │   Preprocessing &    │
                    │   Feature Extraction │
                    └──────────┬───────────┘
                               │
                               ▼
                 ┌─────────────────────────────┐
                 │     ML-Based IDS Models     │
                 │                             │
                 │  XGBoost | Random Forest   │
                 │  DNN     | Hybrid Model    │
                 └─────────────┬───────────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Threat Classification│
                    │  Benign / Malicious   │
                    └──────────┬───────────┘
                               │
                 ┌─────────────┴─────────────┐
                 │                           │
                 ▼                           ▼
       ┌──────────────────┐       ┌────────────────────┐
       │ SHAP / LIME      │       │ Alert Generation   │
       │ Explainability   │       │ & Campaign         │
       │                  │       │ Clustering (EDAC)  │
       └────────┬─────────┘       └──────────┬─────────┘
                │                            │
                └─────────────┬──────────────┘
                              ▼
                   ┌─────────────────────┐
                   │   ThreatXAI Web     │
                   │     Dashboard       │
                   └─────────┬───────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
              ▼                             ▼
      ┌────────────────┐          ┌──────────────────┐
      │ SOC Analyst    │          │ PDF Reports      │
      │ Chat Assistant  │          │ & Documentation  │
      └────────────────┘          └──────────────────┘
🧠 Machine Learning Models

ThreatXAI supports multiple machine learning approaches for intrusion detection:

XGBoost

Gradient-boosted decision trees used for high-performance classification of network traffic.

Random Forest

An ensemble of decision trees used for robust classification and feature analysis.

Deep Neural Network

A neural-network-based model for learning complex relationships within network traffic features.

Hybrid Model

Combines predictions from multiple models to improve robustness and provide a consolidated threat detection result.

🔍 Explainable AI

One of the main objectives of ThreatXAI is to make machine-learning-based intrusion detection more transparent.

SHAP

SHAP (SHapley Additive exPlanations) is used to determine how individual features contribute to a model's prediction.

ThreatXAI uses SHAP for:

Global feature importance
Local prediction explanations
Feature contribution analysis
Understanding why a network flow was classified as malicious or benign
LIME

LIME (Local Interpretable Model-Agnostic Explanations) provides local explanations for individual predictions.

LIME helps analysts understand the important features influencing a particular threat detection decision.

Using SHAP and LIME together provides complementary explanations of machine-learning predictions.

🚨 EDAC - Explanation-Driven Alert Clustering

ThreatXAI includes an alert clustering component called:

EDAC — Explanation-Driven Alert Clustering

EDAC groups related alerts into potential attack campaigns based on available alert and explanation information.

This helps:

Correlate related alerts
Identify potential attack campaigns
Reduce alert fatigue
Provide analysts with a higher-level view of related security events
Support faster investigation of multiple alerts
🌐 Live Packet Capture

ThreatXAI can capture network packets using Scapy.

The packet capture pipeline can:

Capture network traffic
Extract relevant information
Preprocess the traffic
Generate model predictions
Produce security alerts
Generate explanations for predictions
Display results through the dashboard

Live packet capture may require elevated privileges depending on the operating system and network configuration.

💬 SOC Analyst Chat

ThreatXAI provides an analyst assistance interface using an LLM-backed chat system.

The analyst chat provides:

Persistent chat sessions
Security-focused interaction
Threat analysis assistance
Alert investigation support
Session history
PDF report generation

The current implementation uses the Groq API for LLM inference.

📊 Dashboard

The React-based dashboard provides a centralized interface for security monitoring.

It includes:

Threat alerts
Alert details
Campaign clusters
Cluster statistics
Model performance metrics
Model comparison
Prediction results
SHAP/LIME explanations
Packet capture controls
Analyst Chat
PDF report generation
📚 Datasets

The project and research work considered established intrusion-detection datasets including:

CIC-IDS2017
CIC-IDS2019
UNSW-NB15
NSL-KDD

The project also used an internally generated synthetic dataset for development and evaluation:

ThreatXAI-SynthShield-v1

ThreatXAI-SynthShield-v1
Approximately 90,000 samples
68 features
80/20 stratified train-test split

The dataset was designed to support development and comparison of the ThreatXAI detection pipeline.

📈 Model Performance

The machine learning models demonstrated high classification performance during project evaluation.

Example results from the project evaluation include:

Model	Accuracy	Precision	Recall	F1-Score
XGBoost	99.87%	99.89%	99.79%	99.84%
Random Forest	99.74%	—	—	—

Performance values depend on the dataset, preprocessing pipeline, train/test split, and experimental configuration.

🛠️ Tech Stack
Backend
Python
FastAPI
SQLAlchemy
SQLite
Frontend
React
Vite
JavaScript
Machine Learning
Scikit-learn
XGBoost
TensorFlow
Keras
Explainable AI
SHAP
LIME
Network Security
Scapy
AI / LLM
Groq API
Development
Git
GitHub
REST APIs
📁 Project Structure
ThreatXAI/
│
├── backend/
│   ├── main.py
│   ├── config.json
│   ├── db/
│   ├── routers/
│   └── services/
│
├── frontend/
│   ├── src/
│   └── package.json
│
├── ml/
│   ├── preprocess.py
│   ├── train.py
│   ├── evaluate.py
│   ├── edac.py
│   ├── hybrid_model.py
│   ├── synthetic_dataset.py
│   └── models/
│
├── generate_attack_demo.py
├── requirements.txt
├── run.sh
├── run_backend.py
├── .gitignore
└── README.md
⚙️ Prerequisites

Before running ThreatXAI, install:

Python 3.10+
Node.js 18+
npm
Git

For live packet capture:

Appropriate network permissions
Elevated privileges may be required depending on the operating system

For the analyst chat:

Groq API key
📥 Installation

Clone the repository:

git clone https://github.com/Vinayak07n/ThreatXAI.git
cd ThreatXAI

Create a Python virtual environment:

Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
Windows
python -m venv .venv
.venv\Scripts\activate

Install Python dependencies:

pip install -r requirements.txt

Install frontend dependencies:

cd frontend
npm install
cd ..
🔐 Environment Variables

Create a .env file in the project root.

GROQ_API_KEY=your_groq_api_key
GROQ_API_BASE=https://api.groq.com/openai/v1
GROQ_MODEL=llama-3.3-70b-versatile
GROQ_FALLBACK_MODELS=llama-3.1-8b-instant

Do not commit your actual API key to GitHub.

▶️ Running the Application
Option 1 — One-Command Startup
bash run.sh

The application provides:

Backend:   http://localhost:8000
Frontend:  http://localhost:5173
API Docs:  http://localhost:8000/docs
Option 2 — Manual Startup
Start Backend

Activate the virtual environment:

source .venv/bin/activate

Run:

python run_backend.py
Start Frontend

Open another terminal:

cd frontend
npm run dev
🧪 Machine Learning Pipeline

The ML pipeline can be executed using the following commands:

python ml/preprocess.py
python ml/train.py
python ml/evaluate.py
python ml/edac.py

Or use:

bash run.sh --train
🔌 API Endpoints
Health & Metrics
GET /
GET /health
GET /metrics
GET /metrics/comparison
Prediction & Explainability
POST /predict
POST /explain/shap
POST /explain/lime

Example:

curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{
    "features": [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9],
    "src_ip": "10.0.0.5",
    "dst_ip": "8.8.8.8",
    "protocol": "TCP",
    "model_type": "xgboost"
  }'
Alerts & Campaign Clusters
GET /alerts
GET /alerts/{alert_id}
GET /clusters
GET /clusters/stats/summary
GET /clusters/{cluster_id}
Packet Capture
POST /capture/start
POST /capture/stop
GET /capture/status
GET /capture/info
Analyst Chat
GET /analyst/sessions
POST /analyst/sessions
GET /analyst/sessions/{session_id}/messages
DELETE /analyst/sessions/{session_id}
POST /analyst/chat
Reports
GET /reports/alerts/pdf
GET /reports/chat/{session_id}/pdf
👨‍💻 My Contribution

I contributed to ThreatXAI as a member of the project team.

My major contributions included:

Conducted and contributed to the literature survey on Explainable AI, Intrusion Detection Systems, and XAI-based cybersecurity.
Contributed to the initial development and implementation of the ThreatXAI project.
Assisted with the development of the machine-learning-based threat detection pipeline.
Contributed to the integration and understanding of SHAP and LIME explainability techniques.
Assisted with project documentation and technical presentation preparation.
Contributed to the preparation and refinement of the research paper.
Assisted with the research paper publication process.
Participated in project discussions, testing, and refinement.

The project was developed collaboratively as a team project. This repository is a fork of the team's original repository and retains the original project attribution.

👥 Team

Team Size: 4 members

The project was developed as a collaborative academic project in the field of:

Cybersecurity
Intrusion Detection
Machine Learning
Explainable AI
⏱️ Project Duration

Approximately 7–8 months, covering:

Literature survey
Research and requirement analysis
System design
Machine learning development
XAI integration
Full-stack implementation
Testing and evaluation
Documentation
Presentation
Research paper preparation and publication
📄 Research Publication

The research work associated with ThreatXAI was published as:

"Transparent Threat Detection Using SHAP and LIME to build an Explainable Intrusion Detection System"

Authors
Vinayak Naik
Dharaneesh Kuruba
Gowtham R
Monish V
Dr. Deepthi VS
Publication Details
Journal: Journal of Emerging Technologies and Innovative Research (JETIR)
Volume: 12
Issue: 11
Publication: November 2025
Paper ID: JETIR2511250
Registration ID: 571399
Pages: c392–c399
DOI: 10.56975/jetir.v12i11.571399

📄 Read the Published Paper

🔬 Research Focus

The research focused on improving the transparency of machine-learning-based intrusion detection systems.

Key areas included:

Explainable Intrusion Detection Systems
Explainable Artificial Intelligence
SHAP
LIME
XGBoost
Machine Learning for Cybersecurity
Intrusion Detection
SOC analyst support
Alert interpretation
Attack campaign analysis
🎯 Project Objectives

The major objectives of ThreatXAI were:

Develop a high-performance machine-learning-based intrusion detection system.
Integrate SHAP and LIME for model explainability.
Provide human-readable explanations for security predictions.
Group related security alerts into attack campaigns.
Reduce the complexity of analyzing large numbers of security alerts.
Provide an interactive security monitoring dashboard.
Support analysts with AI-assisted threat investigation.
Generate reports that can be used during security analysis.
📝 Notes
Trained models and model artifacts are expected in ml/models/.
If trained models are unavailable, inference endpoints may return model-loading or service errors.
Live packet capture may require elevated privileges.
Network capture behavior depends on the operating system and available network interfaces.
The Groq API requires a valid API key for analyst chat functionality.
Dataset files and trained model artifacts may not be included in the repository because of size and distribution considerations.
🔒 Security Notice

This project is intended for:

Academic research
Cybersecurity education
Controlled laboratory environments
Intrusion detection research
Machine learning experimentation

Do not use live packet capture or security testing features against networks or systems without appropriate authorization.

Never commit:

API keys
Passwords
Authentication tokens
Private certificates
Sensitive network information
Confidential datasets

to the repository.

📌 Future Improvements

Potential future enhancements include:

Real-time streaming threat detection
Additional IDS datasets
Additional ML and deep-learning models
Improved alert correlation
Advanced attack campaign visualization
Automated incident-response recommendations
Enhanced analyst workflow integration
Containerized deployment
Cloud deployment
Authentication and role-based access control
Improved model monitoring and drift detection
📜 License

This repository is maintained as a fork of the original ThreatXAI team project.

Please refer to the original repository and project contributors for licensing and attribution information.

⭐ Acknowledgements

Special thanks to the ThreatXAI project team and faculty guidance for their contributions to the research, development, documentation, and publication of this work.
