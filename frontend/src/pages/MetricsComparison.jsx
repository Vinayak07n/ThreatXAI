import { useEffect, useMemo, useState } from 'react';
import { getMetricsComparison } from '../api/client';

const METRIC_KEYS = [
    ['accuracy', 'Accuracy'],
    ['precision', 'Precision'],
    ['recall', 'Recall'],
    ['f1', 'F1 Score'],
    ['roc_auc', 'ROC-AUC'],
];

function normalizeByModel(metrics = []) {
    const out = {};
    metrics.forEach((m) => {
        out[m.model] = m;
    });
    return out;
}

export default function MetricsComparison() {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        getMetricsComparison()
            .then(setData)
            .catch(() => setData(null))
            .finally(() => setLoading(false));
    }, []);

    const currentMetrics = data?.current_dataset?.metrics || [];
    const cicidsMetrics = data?.cicids_dataset?.metrics || [];
    const hasCicids = cicidsMetrics.length > 0;

    const mergedRows = useMemo(() => {
        const currentMap = normalizeByModel(currentMetrics);
        const cicMap = normalizeByModel(cicidsMetrics);
        const models = Array.from(new Set([...Object.keys(currentMap), ...Object.keys(cicMap)]));
        return models.map((model) => ({
            model,
            current: currentMap[model],
            cicids: cicMap[model],
        }));
    }, [currentMetrics, cicidsMetrics]);

    if (loading) {
        return (
            <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh' }}>
                <div className="spinner" />
            </div>
        );
    }

    return (
        <>
            <div className="page-header">
                <div>
                    <h1 className="page-title">📈 Comparison Metrics</h1>
                    <p className="page-subtitle">CIC-IDS2017 vs ThreatXAI-SynthShield-v1 model performance</p>
                </div>
            </div>

            <div className="page-content">
                {!hasCicids && (
                    <div className="card" style={{ marginBottom: 16, border: '1px solid rgba(245,158,11,0.35)' }}>
                        <div style={{ fontSize: 13, color: '#fbbf24' }}>
                            CIC-IDS metrics file missing. Add <code>ml/models/metrics_cicids.json</code> to enable full comparison.
                        </div>
                    </div>
                )}

                <div className="card">
                    <div className="card-title">Dataset-Level Comparison</div>
                    <div style={{ overflowX: 'auto' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                            <thead>
                                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                                    <th style={{ textAlign: 'left', padding: '10px 8px' }}>Model</th>
                                    {METRIC_KEYS.map(([, label]) => (
                                        <th key={`c-${label}`} style={{ textAlign: 'right', padding: '10px 8px' }}>
                                            CIC-IDS {label}
                                        </th>
                                    ))}
                                    {METRIC_KEYS.map(([, label]) => (
                                        <th key={`t-${label}`} style={{ textAlign: 'right', padding: '10px 8px' }}>
                                            ThreatXAI {label}
                                        </th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody>
                                {mergedRows.map((row) => (
                                    <tr key={row.model} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                                        <td style={{ padding: '10px 8px', fontWeight: 700 }}>{row.model}</td>
                                        {METRIC_KEYS.map(([k]) => (
                                            <td key={`c-${row.model}-${k}`} style={{ padding: '10px 8px', textAlign: 'right', color: 'var(--text-secondary)' }}>
                                                {row.cicids?.[k] != null ? `${(row.cicids[k] * 100).toFixed(2)}%` : '—'}
                                            </td>
                                        ))}
                                        {METRIC_KEYS.map(([k]) => (
                                            <td key={`t-${row.model}-${k}`} style={{ padding: '10px 8px', textAlign: 'right', color: 'var(--text-primary)' }}>
                                                {row.current?.[k] != null ? `${(row.current[k] * 100).toFixed(2)}%` : '—'}
                                            </td>
                                        ))}
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </>
    );
}
