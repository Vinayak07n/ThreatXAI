// pages/Settings.jsx — System configuration with working controls
import { useState, useEffect } from 'react';
import { getConfig, updateConfig } from '../api/client';

const MODEL_MAP = {
    'xgboost': 'XGBoost (Recommended)',
    'rf': 'Random Forest',
    'dnn': 'DNN',
    'hybrid': 'Hybrid Ensemble',
};
const MODEL_KEYS = Object.keys(MODEL_MAP);

export default function Settings({ pollingInterval, setPollingInterval }) {
    const [localInterval, setLocalInterval] = useState(pollingInterval || 3);
    const [savedConn, setSavedConn] = useState(false);

    const [selectedModel, setSelectedModel] = useState('xgboost');
    const [edacThreshold, setEdacThreshold] = useState(80);
    const [minCampaignSize, setMinCampaignSize] = useState(2);
    const [savedModel, setSavedModel] = useState(false);
    const [loadingConfig, setLoadingConfig] = useState(true);

    const [alertLimit, setAlertLimit] = useState(500);
    const [savedAlertLimit, setSavedAlertLimit] = useState(false);

    // Load current config from backend on mount
    useEffect(() => {
        getConfig()
            .then(cfg => {
                if (cfg.default_model) setSelectedModel(cfg.default_model);
                if (cfg.edac_similarity_threshold != null)
                    setEdacThreshold(Math.round(cfg.edac_similarity_threshold * 100));
                if (cfg.min_campaign_size != null)
                    setMinCampaignSize(Number(cfg.min_campaign_size));
                if (cfg.max_alerts != null) setAlertLimit(cfg.max_alerts);
            })
            .catch(() => {})
            .finally(() => setLoadingConfig(false));
    }, []);

    const handleSaveConnection = () => {
        const val = Math.max(1, Math.min(60, Number(localInterval) || 3));
        setPollingInterval(val);
        setLocalInterval(val);
        setSavedConn(true);
        setTimeout(() => setSavedConn(false), 2500);
    };

    const handleSaveModelConfig = async () => {
        try {
            await updateConfig({
                default_model: selectedModel,
                edac_similarity_threshold: edacThreshold / 100,
                min_campaign_size: minCampaignSize,
            });
            setSavedModel(true);
            setTimeout(() => setSavedModel(false), 2500);
        } catch {
            alert('Failed to update model config');
        }
    };

    const handleSaveAlertLimit = async () => {
        try {
            const clamped = Math.max(50, Math.min(10000, Number(alertLimit) || 500));
            setAlertLimit(clamped);
            await updateConfig({ max_alerts: clamped });
            setSavedAlertLimit(true);
            setTimeout(() => setSavedAlertLimit(false), 2500);
        } catch {
            alert('Failed to update alert limit');
        }
    };

    const inputStyle = {
        width: '100%', padding: '8px 12px',
        background: 'var(--bg-secondary)', border: '1px solid var(--border)',
        borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)',
        fontFamily: 'JetBrains Mono, monospace', fontSize: 13,
    };

    return (
        <>
            <div className="page-header">
                <div>
                    <h1 className="page-title">⚙️ Settings</h1>
                    <p className="page-subtitle">Configure ThreatXAI system parameters</p>
                </div>
            </div>

            <div className="page-content">
                <div className="grid-2">
                    {/* Backend Connection */}
                    <div className="card">
                        <div className="card-title">🔌 Backend Connection</div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                            <div>
                                <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 6 }}>API Base URL</div>
                                <input defaultValue="http://localhost:8000" type="text" style={inputStyle} />
                            </div>
                            <div>
                                <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 6 }}>Polling Interval (seconds)</div>
                                <input
                                    value={localInterval}
                                    onChange={e => setLocalInterval(e.target.value)}
                                    type="number" min="1" max="60"
                                    style={inputStyle}
                                />
                                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                                    How often the dashboard refreshes during live capture (1–60s)
                                </div>
                            </div>
                            <button className="btn btn-primary" style={{ marginTop: 4 }} onClick={handleSaveConnection}>
                                {savedConn ? '✓ Saved!' : 'Save Connection'}
                            </button>
                            {savedConn && (
                                <div style={{ padding: '8px 12px', background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.2)', borderRadius: 8, fontSize: 12, color: 'var(--success)' }}>
                                    ✓ Polling interval updated to {pollingInterval}s
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Model Config */}
                    <div className="card">
                        <div className="card-title">🤖 Model Config</div>
                        {loadingConfig ? (
                            <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: 12 }}>Loading config...</div>
                        ) : (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                                <div>
                                    <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 6 }}>Default Model for Live Capture</div>
                                    <select
                                        value={selectedModel}
                                        onChange={e => setSelectedModel(e.target.value)}
                                        style={inputStyle}
                                    >
                                        {MODEL_KEYS.map(key => (
                                            <option key={key} value={key}>{MODEL_MAP[key]}</option>
                                        ))}
                                    </select>
                                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                                        Changes take effect immediately for new captures
                                    </div>
                                </div>
                                <div>
                                    <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 6 }}>EDAC Similarity Threshold</div>
                                    <input
                                        type="range" min="50" max="99"
                                        value={edacThreshold}
                                        onChange={e => setEdacThreshold(Number(e.target.value))}
                                        style={{ width: '100%', accentColor: 'var(--accent)' }}
                                    />
                                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                                        <span>50% (Broad)</span>
                                        <span style={{ color: 'var(--accent-light)', fontWeight: 700, fontSize: 13 }}>{edacThreshold}%</span>
                                        <span>99% (Tight)</span>
                                    </div>
                                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                                        Higher = tighter clusters (fewer, more specific campaigns). Lower = broader clusters.
                                    </div>
                                </div>
                                <div>
                                    <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 6 }}>Minimum Campaign Size</div>
                                    <input
                                        value={minCampaignSize}
                                        onChange={e => setMinCampaignSize(Math.max(1, Math.min(20, Number(e.target.value) || 2)))}
                                        type="number" min="1" max="20"
                                        style={inputStyle}
                                    />
                                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                                        Campaigns with fewer alerts are hidden from the campaigns view to reduce noise.
                                    </div>
                                </div>
                                <button className="btn btn-primary" style={{ marginTop: 4 }} onClick={handleSaveModelConfig}>
                                    {savedModel ? '✓ Saved!' : 'Save Model Config'}
                                </button>
                                {savedModel && (
                                    <div style={{ padding: '8px 12px', background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.2)', borderRadius: 8, fontSize: 12, color: 'var(--success)' }}>
                                        ✓ Model set to <strong>{MODEL_MAP[selectedModel]}</strong>, EDAC threshold <strong>{edacThreshold}%</strong>, Min campaign size <strong>{minCampaignSize}</strong>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>

                    {/* Database Alert Limit */}
                    <div className="card">
                        <div className="card-title">📊 Database Alert Limit</div>
                        {loadingConfig ? (
                            <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: 12 }}>Loading config...</div>
                        ) : (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                                <div>
                                    <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 6 }}>Max Alerts in Database</div>
                                    <input
                                        value={alertLimit}
                                        onChange={e => setAlertLimit(e.target.value)}
                                        type="number" min="50" max="10000" step="50"
                                        style={inputStyle}
                                    />
                                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                                        Maximum number of alerts stored in the database (50–10,000).
                                    </div>
                                </div>
                                <div style={{ padding: 10, background: 'rgba(139,92,246,0.08)', border: '1px solid rgba(139,92,246,0.15)', borderRadius: 8, fontSize: 12, color: '#a78bfa' }}>
                                    💡 When this limit is exceeded, the oldest <strong>benign</strong> alerts are purged first, then oldest attack alerts — ensuring recent attacks are always preserved.
                                </div>
                                <button className="btn btn-primary" style={{ marginTop: 4 }} onClick={handleSaveAlertLimit}>
                                    {savedAlertLimit ? '✓ Saved!' : 'Save Alert Limit'}
                                </button>
                                {savedAlertLimit && (
                                    <div style={{ padding: '8px 12px', background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.2)', borderRadius: 8, fontSize: 12, color: 'var(--success)' }}>
                                        ✓ Alert limit updated to <strong>{alertLimit}</strong>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>

                    {/* ML Pipeline */}
                    <div className="card">
                        <div className="card-title">📦 ML Pipeline</div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                            {[
                                { label: 'Preprocess Dataset', cmd: 'python ml/preprocess.py', icon: '⚙️' },
                                { label: 'Train All Models', cmd: 'python ml/train.py', icon: '🏋️' },
                                { label: 'Evaluate Models', cmd: 'python ml/evaluate.py', icon: '📊' },
                                { label: 'Seed EDAC Engine', cmd: 'python ml/edac.py', icon: '🔗' },
                            ].map(item => (
                                <div key={item.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 12px', background: 'var(--bg-secondary)', borderRadius: 'var(--radius-sm)' }}>
                                    <div>
                                        <div style={{ fontWeight: 600, fontSize: 13 }}>{item.icon} {item.label}</div>
                                        <div className="mono" style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{item.cmd}</div>
                                    </div>
                                </div>
                            ))}
                            <div style={{ padding: 10, background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.2)', borderRadius: 8, fontSize: 12, color: 'var(--warning)' }}>
                                ⚠️ Run these commands from the <code style={{ background: 'rgba(0,0,0,0.3)', padding: '1px 6px', borderRadius: 4 }}>threatxai/</code> directory
                            </div>
                        </div>
                    </div>

                    {/* About */}
                    <div className="card">
                        <div className="card-title">ℹ️ About ThreatXAI</div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 13 }}>
                            {[
                                ['Version', '1.0.0'],
                                ['Dataset', 'ThreatXAI-SynthShield-v1'],
                                ['Primary Model', 'XGBoost / Hybrid'],
                                ['Explainability', 'SHAP + LIME'],
                                ['Novel Feature', 'EDAC (SHAP Vector Clustering)'],
                                ['Backend', 'FastAPI + SQLite'],
                                ['Frontend', 'React + Vite'],
                            ].map(([key, val]) => (
                                <div key={key} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
                                    <span style={{ color: 'var(--text-muted)' }}>{key}</span>
                                    <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{val}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </div>
        </>
    );
}
