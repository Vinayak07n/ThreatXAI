// api/client.js — Axios API client for ThreatXAI backend

import axios from 'axios';

const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const api = axios.create({
    baseURL: BASE_URL,
    timeout: 30000,
    headers: { 'Content-Type': 'application/json' },
});

// Prediction
export const predict = (features, modelType = 'xgboost') =>
    api.post('/predict', { features, model_type: modelType }).then(r => r.data);

// Explanations
export const explainSHAP = (features, alertId = null, modelType = 'xgboost') =>
    api.post('/explain/shap', { features, alert_id: alertId, model_type: modelType }).then(r => r.data);

export const explainLIME = (features, alertId = null, modelType = 'xgboost') =>
    api.post('/explain/lime', { features, alert_id: alertId, model_type: modelType }).then(r => r.data);

export const getGlobalSHAP = (modelType = 'xgboost') =>
    api.get(`/explain/global/shap?model_type=${modelType}`).then(r => r.data);

// Alerts
export const getAlerts = (skip = 0, limit = 10000, prediction = null) => {
    const params = { skip, limit };
    if (prediction !== null) params.prediction = prediction;
    return api.get('/alerts', { params }).then(r => r.data);
};

export const getAlertDetail = (alertId) =>
    api.get(`/alerts/${alertId}`).then(r => r.data);

export const deleteAlert = (alertId) =>
    api.delete(`/alerts/${alertId}`).then(r => r.data);

export const getAlertStats = () =>
    api.get('/alerts/stats/summary').then(r => r.data);

// EDAC Clusters
export const getClusters = () =>
    api.get('/clusters').then(r => r.data);

export const getClusterDetail = (clusterId) =>
    api.get(`/clusters/${clusterId}`).then(r => r.data);

export const getClusterStats = () =>
    api.get('/clusters/stats/summary').then(r => r.data);

// Capture
export const startCapture = () =>
    api.post('/capture/start').then(r => r.data);

export const stopCapture = () =>
    api.post('/capture/stop').then(r => r.data);

export const getCaptureStatus = () =>
    api.get('/capture/status').then(r => r.data);

// Metrics
export const getMetrics = () =>
    api.get('/metrics').then(r => r.data);

export const getMetricsComparison = () =>
    api.get('/metrics/comparison').then(r => r.data);

export const getHealth = () =>
    api.get('/health').then(r => r.data);

// Analyst chat (RAG + Groq)
export const listChatSessions = (limit = 50) =>
    api.get(`/analyst/sessions?limit=${limit}`).then(r => r.data);

export const createChatSession = (title = 'SOC Analyst Session') =>
    api.post('/analyst/sessions', { title }).then(r => r.data);

export const getChatMessages = (sessionId) =>
    api.get(`/analyst/sessions/${sessionId}/messages`).then(r => r.data);

export const deleteChatSession = (sessionId) =>
    api.delete(`/analyst/sessions/${sessionId}`).then(r => r.data);

export const askAnalyst = ({ sessionId = null, question, alertId = null, clusterId = null, modelType = 'xgboost' }) =>
    api.post('/analyst/chat', {
        session_id: sessionId,
        question,
        alert_id: alertId,
        cluster_id: clusterId,
        model_type: modelType,
    }).then(r => r.data);

// Configuration
export const getConfig = () =>
    api.get('/config').then(r => r.data);

export const updateConfig = (updates) =>
    api.post('/config', updates).then(r => r.data);

function downloadBlob(blob, filename) {
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
}

export const downloadAlertsReport = ({ prediction = null, clusterId = null, limit = 1000 } = {}) =>
    api.get('/reports/alerts/pdf', {
        params: {
            prediction,
            cluster_id: clusterId,
            limit,
        },
        responseType: 'blob',
    }).then(r => {
        const ts = new Date().toISOString().replace(/[:.]/g, '-');
        downloadBlob(r.data, `threatxai-alerts-${ts}.pdf`);
    });

export const downloadChatReport = (sessionId) =>
    api.get(`/reports/chat/${sessionId}/pdf`, { responseType: 'blob' }).then(r => {
        const ts = new Date().toISOString().replace(/[:.]/g, '-');
        downloadBlob(r.data, `threatxai-chat-${sessionId}-${ts}.pdf`);
    });

export default api;
