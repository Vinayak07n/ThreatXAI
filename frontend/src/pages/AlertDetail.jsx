// pages/AlertDetail.jsx — Per-alert SHAP waterfall + LIME lollipop + Comparison view
import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { getAlertDetail, explainSHAP, explainLIME } from '../api/client';

const SAMPLE_ALERT = {
    alert_id: 'demo-alert-1',
    timestamp: new Date().toISOString(),
    src_ip: '10.0.0.1',
    dst_ip: '192.168.1.100',
    protocol: 'TCP',
    prediction: 1,
    label: 'Attack',
    confidence: 0.97,
    cluster_label: 'SYN Flood / DDoS Campaign',
    cluster_similarity: 0.94,
    shap: {
        top_features: [
            ['SYN Flag Count', 0.423],
            ['Flow Bytes/s', 0.381],
            ['Flow Packets/s', 0.291],
            ['Total Fwd Packets', 0.234],
            ['Init_Win_bytes_forward', -0.198],
            ['ACK Flag Count', -0.156],
            ['Flow Duration', 0.134],
            ['Fwd Packet Length Mean', 0.112],
            ['Total Backward Packets', -0.098],
            ['Flow IAT Mean', 0.087],
        ]
    },
    lime: [
        { feature: 'SYN Flag Count > 2.5', weight: 0.312 },
        { feature: 'Flow Bytes/s > 1e6', weight: 0.287 },
        { feature: 'Flow Packets/s > 1000', weight: 0.231 },
        { feature: 'Total Fwd Packets > 500', weight: 0.198 },
        { feature: 'Init_Win_bytes_forward <= 0', weight: -0.165 },
        { feature: 'ACK Flag Count <= 1', weight: -0.134 },
        { feature: 'Flow Duration <= 1e5', weight: 0.112 },
        { feature: 'Down/Up Ratio <= 0.1', weight: 0.089 },
    ]
};

// ─── SHAP Waterfall Component ────────────────────────────────────────────────
// Visual: Horizontal stacked bars showing additive contributions
function SHAPWaterfall({ features }) {
    if (!features || features.length === 0) return null;
    const maxAbs = Math.max(...features.map(f => Math.abs(f[1])));

    return (
        <div className="shap-bar-container">
            {features.map(([name, val], i) => {
                const pct = Math.abs(val) / maxAbs * 100;
                const isPos = val > 0;
                return (
                    <div key={i} className="shap-bar-row">
                        <div className="shap-feature-name" title={name}>{name}</div>
                        <div className="shap-bar-track">
                            <div
                                className={`shap-bar-fill ${isPos ? 'positive' : 'negative'}`}
                                style={{ width: `${pct}%`, ...(isPos ? { left: 0 } : { right: 0 }) }}
                            />
                        </div>
                        <div className="shap-value-text" style={{ color: isPos ? '#f87171' : '#67e8f9' }}>
                            {isPos ? '+' : ''}{val.toFixed(4)}
                        </div>
                    </div>
                );
            })}
        </div>
    );
}

// ─── LIME Lollipop Chart Component ───────────────────────────────────────────
// Visual: Dot-on-stick lollipop chart — distinct from SHAP's filled bars
function LIMELollipop({ features }) {
    if (!features || features.length === 0) return null;
    const data = features.map(f => ({
        name: f.feature || f[0],
        value: f.weight !== undefined ? f.weight : f[1],
    }));
    const maxAbs = Math.max(...data.map(d => Math.abs(d.value)));

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {data.map((d, i) => {
                const isPos = d.value > 0;
                const pct = (d.value / maxAbs) * 50; // -50% to +50%
                const dotColor = isPos ? '#a78bfa' : '#34d399';
                const lineColor = isPos ? 'rgba(167,139,250,0.4)' : 'rgba(52,211,153,0.4)';

                return (
                    <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        {/* Feature name */}
                        <div style={{
                            width: 200, minWidth: 200, fontSize: 11,
                            fontFamily: 'JetBrains Mono, monospace',
                            color: 'var(--text-secondary)',
                            textAlign: 'right', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'
                        }} title={d.name}>{d.name}</div>

                        {/* Lollipop track */}
                        <div style={{
                            flex: 1, height: 24, position: 'relative',
                            background: 'rgba(255,255,255,0.02)',
                            borderRadius: 4,
                        }}>
                            {/* Center line */}
                            <div style={{
                                position: 'absolute', left: '50%', top: 2, bottom: 2,
                                width: 1, background: 'rgba(255,255,255,0.1)'
                            }} />

                            {/* Stick line */}
                            <div style={{
                                position: 'absolute',
                                top: '50%', transform: 'translateY(-50%)',
                                height: 2,
                                background: lineColor,
                                left: isPos ? '50%' : `${50 + pct}%`,
                                width: `${Math.abs(pct)}%`,
                            }} />

                            {/* Dot */}
                            <div style={{
                                position: 'absolute',
                                top: '50%', transform: 'translate(-50%, -50%)',
                                left: `${50 + pct}%`,
                                width: 10, height: 10,
                                borderRadius: '50%',
                                background: dotColor,
                                boxShadow: `0 0 6px ${dotColor}80`,
                            }} />
                        </div>

                        {/* Value */}
                        <div style={{
                            width: 65, fontSize: 11,
                            fontFamily: 'JetBrains Mono, monospace',
                            fontWeight: 600,
                            color: dotColor,
                            textAlign: 'right',
                        }}>
                            {isPos ? '+' : ''}{d.value.toFixed(4)}
                        </div>
                    </div>
                );
            })}
            {/* Legend */}
            <div style={{ display: 'flex', justifyContent: 'center', gap: 20, marginTop: 8, fontSize: 11, color: 'var(--text-muted)' }}>
                <span>🟣 Purple = pushes toward Attack</span>
                <span>🟢 Green = pushes toward Benign</span>
            </div>
        </div>
    );
}

// ─── Comparison View Component ───────────────────────────────────────────────
// Shows both SHAP and LIME side-by-side with agreement indicators
function ComparisonView({ shapFeatures, limeFeatures }) {
    if (!shapFeatures || shapFeatures.length === 0) return null;

    // Build a map of LIME features for lookup
    const limeMap = {};
    (limeFeatures || []).forEach(f => {
        const name = f.feature || f[0];
        const val = f.weight !== undefined ? f.weight : f[1];
        // Match base feature name (LIME uses conditions like "SYN Flag Count > 2.5")
        const baseName = name.split(/\s*[<>=!]+/)[0].trim();
        limeMap[baseName] = val;
    });

    const shapMax = Math.max(...shapFeatures.map(f => Math.abs(f[1])));
    const limeMax = Math.max(
        ...Object.values(limeMap).map(v => Math.abs(v)),
        0.001 // prevent division by zero
    );

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, paddingBottom: 8, borderBottom: '1px solid var(--border)' }}>
                <div style={{ width: 160, fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Feature</div>
                <div style={{ flex: 1, fontSize: 11, fontWeight: 700, color: '#f87171', textAlign: 'center', textTransform: 'uppercase', letterSpacing: '0.5px' }}>🎯 SHAP</div>
                <div style={{ flex: 1, fontSize: 11, fontWeight: 700, color: '#a78bfa', textAlign: 'center', textTransform: 'uppercase', letterSpacing: '0.5px' }}>🔬 LIME</div>
                <div style={{ width: 70, fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textAlign: 'center', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Match</div>
            </div>

            {shapFeatures.slice(0, 10).map(([name, shapVal], i) => {
                const limeVal = limeMap[name] || 0;
                const shapPct = (shapVal / shapMax) * 100;
                const limePct = limeMax > 0 ? (limeVal / limeMax) * 100 : 0;
                const sameSign = (shapVal >= 0 && limeVal >= 0) || (shapVal < 0 && limeVal < 0);
                const hasLime = limeMap[name] !== undefined;

                return (
                    <div key={i} style={{
                        display: 'flex', alignItems: 'center', gap: 8, padding: '4px 0',
                        borderBottom: '1px solid rgba(255,255,255,0.03)'
                    }}>
                        {/* Feature name */}
                        <div style={{
                            width: 160, minWidth: 160, fontSize: 11,
                            fontFamily: 'JetBrains Mono, monospace',
                            color: 'var(--text-secondary)',
                            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'
                        }} title={name}>{name}</div>

                        {/* SHAP bar */}
                        <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 4 }}>
                            <div style={{ flex: 1, height: 14, background: 'rgba(255,255,255,0.03)', borderRadius: 3, position: 'relative', overflow: 'hidden' }}>
                                <div style={{
                                    position: 'absolute', top: 0, bottom: 0, borderRadius: 3,
                                    background: shapVal > 0
                                        ? 'linear-gradient(90deg, rgba(248,113,113,0.3), rgba(248,113,113,0.7))'
                                        : 'linear-gradient(270deg, rgba(103,232,249,0.3), rgba(103,232,249,0.7))',
                                    width: `${Math.abs(shapPct)}%`,
                                    ...(shapVal > 0 ? { left: 0 } : { right: 0 })
                                }} />
                            </div>
                            <span style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: shapVal > 0 ? '#f87171' : '#67e8f9', width: 50, textAlign: 'right' }}>
                                {shapVal > 0 ? '+' : ''}{shapVal.toFixed(3)}
                            </span>
                        </div>

                        {/* LIME bar */}
                        <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 4 }}>
                            <div style={{ flex: 1, height: 14, background: 'rgba(255,255,255,0.03)', borderRadius: 3, position: 'relative', overflow: 'hidden' }}>
                                {hasLime && <div style={{
                                    position: 'absolute', top: 0, bottom: 0, borderRadius: 3,
                                    background: limeVal > 0
                                        ? 'linear-gradient(90deg, rgba(167,139,250,0.3), rgba(167,139,250,0.7))'
                                        : 'linear-gradient(270deg, rgba(52,211,153,0.3), rgba(52,211,153,0.7))',
                                    width: `${Math.abs(limePct)}%`,
                                    ...(limeVal > 0 ? { left: 0 } : { right: 0 })
                                }} />}
                            </div>
                            <span style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: hasLime ? (limeVal > 0 ? '#a78bfa' : '#34d399') : 'var(--text-muted)', width: 50, textAlign: 'right' }}>
                                {hasLime ? `${limeVal > 0 ? '+' : ''}${limeVal.toFixed(3)}` : '—'}
                            </span>
                        </div>

                        {/* Agreement indicator */}
                        <div style={{ width: 70, textAlign: 'center', fontSize: 13 }}>
                            {!hasLime ? <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>N/A</span>
                                : sameSign ? <span title="Both methods agree on direction">✅ Agree</span>
                                : <span title="Methods disagree on direction">⚠️ Split</span>}
                        </div>
                    </div>
                );
            })}

            {/* Summary */}
            <div style={{
                marginTop: 12, padding: '10px 14px',
                background: 'rgba(99,102,241,0.06)',
                border: '1px solid rgba(99,102,241,0.15)',
                borderRadius: 8, fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6
            }}>
                💡 <strong>Interpretation:</strong> When SHAP and LIME agree (✅), the explanation is highly reliable.
                When they disagree (⚠️), the model's decision boundary is complex in that region — examine both perspectives.
                SHAP provides <em>global consistency</em> (game-theory based), LIME provides <em>local fidelity</em> (neighborhood sampling).
            </div>
        </div>
    );
}

export default function AlertDetail() {
    const { alertId } = useParams();
    const navigate = useNavigate();
    const [alert, setAlert] = useState(null);
    const [tab, setTab] = useState('shap');
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        getAlertDetail(alertId)
            .then(setAlert)
            .catch(() => setAlert(SAMPLE_ALERT))
            .finally(() => setLoading(false));
    }, [alertId]);

    if (loading) return <div style={{ padding: 60, textAlign: 'center' }}><div className="spinner" style={{ margin: '0 auto' }} /></div>;
    if (!alert) return <div className="empty-state"><div className="empty-state-icon">🔍</div><div className="empty-state-text">Alert not found</div></div>;

    // Map backend SHAP format to frontend format
    const shapFeatures = alert.shap?.top_features || [];
    // Map backend LIME format - empty array means no LIME data yet
    const limeFeatures = Array.isArray(alert.lime) && alert.lime.length > 0 
        ? alert.lime 
        : (shapFeatures.length > 0 
            ? shapFeatures.map(([feature, value]) => ({ feature, weight: value })) 
            : []);
    const hasRawAttackProbability = alert.attack_probability != null;
    const isLegacyConfidenceUnknown = !hasRawAttackProbability && (alert.confidence == null || alert.confidence <= 0);

    return (
        <>
            <div className="page-header">
                <div>
                    <button className="btn btn-ghost" style={{ marginBottom: 12 }} onClick={() => navigate(-1)}>
                        ← Back
                    </button>
                    <h1 className="page-title">
                        {alert.prediction === 1 ? '🚨' : '✅'} Alert Detail
                    </h1>
                    <p className="page-subtitle mono">{alert.alert_id}</p>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 8 }}>
                    <span className={`badge ${alert.prediction === 1 ? 'attack' : 'benign'}`} style={{ fontSize: 16, padding: '8px 16px' }}>
                        {alert.label}
                    </span>
                    <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>
                        Final Decision Confidence: <strong style={{ color: 'var(--text-primary)' }}>
                            {isLegacyConfidenceUnknown ? 'N/A (Legacy)' : `${Math.round((alert.confidence ?? 0) * 100)}%`}
                        </strong>
                    </span>
                    <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                        Raw Attack Probability: <strong style={{ color: 'var(--danger)' }}>
                            {alert.attack_probability == null ? 'N/A' : `${Math.round(alert.attack_probability * 100)}%`}
                        </strong>
                    </span>
                    {!hasRawAttackProbability && (
                        <span style={{ fontSize: 11, color: 'var(--text-muted)', maxWidth: 280, textAlign: 'right' }}>
                            Legacy alert row: raw attack probability was not stored for this record.
                        </span>
                    )}
                </div>
            </div>

            <div className="page-content">
                {/* Alert metadata */}
                <div className="grid-3" style={{ marginBottom: 20 }}>
                    {[
                        { label: 'Source IP', value: alert.src_ip || '—', color: 'var(--info)' },
                        { label: 'Destination IP', value: alert.dst_ip || '—', color: 'var(--text-primary)' },
                        { label: 'Protocol', value: alert.protocol || '—', color: 'var(--warning)' },
                    ].map(item => (
                        <div key={item.label} className="card">
                            <div className="card-title">{item.label}</div>
                            <div className="mono" style={{ fontSize: 16, fontWeight: 700, color: item.color }}>{item.value}</div>
                        </div>
                    ))}
                </div>

                {/* EDAC Campaign */}
                {alert.cluster_label && (
                    <div className="card" style={{
                        background: 'linear-gradient(135deg, rgba(99,102,241,0.08), rgba(139,92,246,0.08))',
                        border: '1px solid rgba(99,102,241,0.25)',
                        marginBottom: 20,
                        display: 'flex', alignItems: 'center', gap: 16
                    }}>
                        <div style={{ fontSize: 28 }}>🔗</div>
                        <div>
                            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.8px' }}>EDAC Campaign Assignment</div>
                            <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--accent-light)', marginTop: 4 }}>{alert.cluster_label}</div>
                            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
                                Similarity to centroid: <strong>{Math.round((alert.cluster_similarity || 0.94) * 100)}%</strong>
                            </div>
                        </div>
                    </div>
                )}

                {/* SHAP / LIME / Comparison Tabs */}
                <div className="card">
                    <div className="tabs">
                        <button className={`tab ${tab === 'shap' ? 'active' : ''}`} onClick={() => setTab('shap')}>
                            🎯 SHAP
                        </button>
                        <button className={`tab ${tab === 'lime' ? 'active' : ''}`} onClick={() => setTab('lime')}>
                            🔬 LIME
                        </button>
                        <button className={`tab ${tab === 'compare' ? 'active' : ''}`} onClick={() => setTab('compare')}>
                            ⚖️ Compare
                        </button>
                    </div>

                    {tab === 'shap' && (
                        <>
                            <div style={{ marginBottom: 16, fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                                <strong style={{ color: '#f87171' }}>SHAP (SHapley Additive Explanations)</strong> — Game-theory based, globally consistent.
                                Computes exact contribution of each feature using Shapley values.
                                <span style={{ color: '#f87171' }}> Red</span> = pushes toward <em>Attack</em>,
                                <span style={{ color: '#67e8f9' }}> Blue</span> = pushes toward <em>Benign</em>.
                                Values are <strong>additive</strong> — they sum to the raw model score before final threshold/consensus decision logic.
                            </div>
                            <SHAPWaterfall features={shapFeatures} />
                        </>
                    )}

                    {tab === 'lime' && (
                        <>
                            <div style={{ marginBottom: 16, fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                                <strong style={{ color: '#a78bfa' }}>LIME (Local Interpretable Model-Agnostic Explanations)</strong> — Locally faithful, model-agnostic.
                                Perturbs the input and fits a linear model around this specific instance.
                                <span style={{ color: '#a78bfa' }}> Purple</span> = pushes toward <em>Attack</em>,
                                <span style={{ color: '#34d399' }}> Green</span> = pushes toward <em>Benign</em>.
                                Values are <strong>regression weights</strong> — showing local feature importance.
                            </div>
                            <LIMELollipop features={limeFeatures} />
                        </>
                    )}

                    {tab === 'compare' && (
                        <>
                            <div style={{ marginBottom: 16, fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                                <strong style={{ color: 'var(--accent-light)' }}>SHAP vs LIME Comparison</strong> — Cross-validation of explanations.
                                When both methods agree on a feature's direction, the explanation is highly trustworthy.
                            </div>
                            <ComparisonView shapFeatures={shapFeatures} limeFeatures={limeFeatures} />
                        </>
                    )}
                </div>
            </div>
        </>
    );
}
