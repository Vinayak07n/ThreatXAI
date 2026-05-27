// pages/ModelPerf.jsx — Model Performance: loads real metrics from backend
import { useState, useEffect } from 'react';
import { getMetrics } from '../api/client';
import {
    BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend
} from 'recharts';

const MODEL_COLORS = {
    XGBoost: '#6366f1',
    'Random Forest': '#22c55e',
    DNN: '#f59e0b',
    'Hybrid Ensemble': '#8b5cf6',
};

function MetricCard({ label, value, color }) {
    const pct = Math.round(value * 100 * 100) / 100;
    return (
        <div className="card" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 36, fontWeight: 800, color }}>
                {pct}<span style={{ fontSize: 18 }}>%</span>
            </div>
            <div className="stat-label" style={{ marginTop: 6 }}>{label}</div>
            <div style={{ marginTop: 10, height: 4, background: 'var(--bg-secondary)', borderRadius: 2 }}>
                <div style={{ height: '100%', borderRadius: 2, width: `${Math.round(value * 100)}%`, background: color }} />
            </div>
        </div>
    );
}

export default function ModelPerf() {
    const [metrics, setMetrics] = useState([]);
    const [selectedModel, setSelectedModel] = useState('XGBoost');
    const [loading, setLoading] = useState(true);
    const [isRealData, setIsRealData] = useState(false);

    useEffect(() => {
        getMetrics()
            .then(data => {
                const m = data.metrics || data;
                if (m && m.length > 0) {
                    setMetrics(m);
                    setIsRealData(true);
                    setSelectedModel(m[0].model);
                }
            })
            .catch(() => {
                setMetrics([]);
                setIsRealData(false);
            })
            .finally(() => setLoading(false));
    }, []);

    if (loading) {
        return (
            <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh' }}>
                <div className="spinner" />
            </div>
        );
    }

    if (!isRealData || metrics.length === 0) {
        return (
            <>
                <div className="page-header">
                    <div>
                        <h1 className="page-title">📊 Model Performance</h1>
                        <p className="page-subtitle">ThreatXAI synthetic dataset evaluation results</p>
                    </div>
                </div>
                <div className="page-content">
                    <div className="empty-state">
                        <div className="empty-state-icon">📊</div>
                        <div className="empty-state-text">Awaiting Model Evaluation</div>
                        <div className="empty-state-sub">Metrics will populate once models are trained and evaluated on the test set.</div>
                    </div>
                </div>
            </>
        );
    }

    const modelData = metrics.find(m => m.model === selectedModel) || metrics[0];

    const comparisonData = [
        { metric: 'Accuracy', ...Object.fromEntries(metrics.map(m => [m.model, +(m.accuracy * 100).toFixed(2)])) },
        { metric: 'Precision', ...Object.fromEntries(metrics.map(m => [m.model, +(m.precision * 100).toFixed(2)])) },
        { metric: 'Recall', ...Object.fromEntries(metrics.map(m => [m.model, +(m.recall * 100).toFixed(2)])) },
        { metric: 'F1 Score', ...Object.fromEntries(metrics.map(m => [m.model, +(m.f1 * 100).toFixed(2)])) },
        { metric: 'ROC-AUC', ...Object.fromEntries(metrics.map(m => [m.model, +(m.roc_auc * 100).toFixed(2)])) },
    ];

    const bestModel = [...metrics].sort((a, b) => b.f1 - a.f1)[0];

    return (
        <>
            <div className="page-header">
                <div>
                    <h1 className="page-title">📊 Model Performance</h1>
                    <p className="page-subtitle">Evaluated on ThreatXAI-SynthShield-v1 test split (20% stratified)</p>
                </div>
                <div className="tabs" style={{ marginBottom: 0 }}>
                    {metrics.map(m => (
                        <button key={m.model} className={`tab ${selectedModel === m.model ? 'active' : ''}`}
                            onClick={() => setSelectedModel(m.model)}>
                            {m.model}
                        </button>
                    ))}
                </div>
            </div>

            <div className="page-content">
                {modelData && (
                    <>
                        <div style={{ fontWeight: 700, color: 'var(--text-secondary)', fontSize: 12, textTransform: 'uppercase', letterSpacing: '0.8px', marginBottom: 12 }}>
                            {modelData.model} — Test Set Results
                        </div>
                        <div className="stats-grid" style={{ marginBottom: 24 }}>
                            <MetricCard label="Accuracy" value={modelData.accuracy} color={MODEL_COLORS[modelData.model] || 'var(--accent)'} />
                            <MetricCard label="Precision" value={modelData.precision} color="#22c55e" />
                            <MetricCard label="Recall" value={modelData.recall} color="#f59e0b" />
                            <MetricCard label="F1 Score" value={modelData.f1} color="#06b6d4" />
                        </div>
                    </>
                )}

                <div className="grid-2">
                    <div className="card">
                        <div className="card-title">All Models Comparison</div>
                        <ResponsiveContainer width="100%" height={260}>
                            <BarChart data={comparisonData} margin={{ top: 8, right: 8, left: 0, bottom: 24 }}>
                                <XAxis dataKey="metric" tick={{ fontSize: 10, fill: 'var(--text-muted)' }} />
                                <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: 'var(--text-muted)' }} unit="%" tickCount={6} />
                                <Tooltip
                                    formatter={v => [`${v.toFixed(2)}%`]}
                                    contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8 }}
                                />
                                <Legend wrapperStyle={{ fontSize: 11, color: 'var(--text-secondary)' }} />
                                {metrics.map(m => (
                                    <Bar key={m.model} dataKey={m.model} fill={MODEL_COLORS[m.model] || 'var(--accent)'}
                                        radius={[4, 4, 0, 0]} fillOpacity={0.85} />
                                ))}
                            </BarChart>
                        </ResponsiveContainer>
                    </div>

                    <div className="card">
                        <div className="card-title">ROC-AUC Summary</div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 16, marginTop: 16 }}>
                            {metrics.map(m => (
                                <div key={m.model}>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                                        <span style={{ fontSize: 13, fontWeight: 600 }}>{m.model}</span>
                                        <span style={{ fontFamily: 'JetBrains Mono', fontSize: 13, color: MODEL_COLORS[m.model] }}>
                                            {m.roc_auc.toFixed(4)}
                                        </span>
                                    </div>
                                    <div style={{ height: 8, background: 'var(--bg-secondary)', borderRadius: 4 }}>
                                        <div style={{
                                            height: '100%', borderRadius: 4,
                                            width: `${m.roc_auc * 100}%`,
                                            background: MODEL_COLORS[m.model] || 'var(--accent)',
                                            transition: 'width 0.8s ease'
                                        }} />
                                    </div>
                                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                                        F1: {(m.f1 * 100).toFixed(2)}% | Recall: {(m.recall * 100).toFixed(2)}%
                                    </div>
                                </div>
                            ))}
                        </div>

                        <div style={{ marginTop: 24, padding: 12, background: 'var(--bg-secondary)', borderRadius: 8 }}>
                            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4, fontWeight: 600 }}>
                                📌 Primary Model
                            </div>
                            <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--accent-light)' }}>
                                {bestModel.model} — F1: {(bestModel.f1 * 100).toFixed(2)}%
                            </div>
                            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>
                                Selected for live inference and SHAP explanation generation
                            </div>
                        </div>
                    </div>
                </div>

                <div className="card" style={{ marginTop: 16 }}>
                    <div className="card-title">📁 Dataset — ThreatXAI-SynthShield-v1</div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
                        {[
                            { label: 'Attack Classes', value: '7' },
                            { label: 'Features', value: '68' },
                            { label: 'Train Split', value: '80%' },
                            { label: 'Test Split', value: '20%' },
                        ].map(item => (
                            <div key={item.label} style={{ textAlign: 'center' }}>
                                <div style={{ fontSize: 24, fontWeight: 800, color: 'var(--accent-light)' }}>{item.value}</div>
                                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>{item.label}</div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </>
    );
}
