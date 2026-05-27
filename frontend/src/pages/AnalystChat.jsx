import { useEffect, useMemo, useState } from 'react';
import { askAnalyst, listChatSessions, getChatMessages, deleteChatSession, downloadChatReport } from '../api/client';

export default function AnalystChat() {
    const [sessions, setSessions] = useState([]);
    const [sessionId, setSessionId] = useState(null); // null => draft/unsaved chat
    const [messages, setMessages] = useState([]);
    const [question, setQuestion] = useState('');
    const [loading, setLoading] = useState(false);
    const [scopeAlertId, setScopeAlertId] = useState('');
    const [scopeClusterId, setScopeClusterId] = useState('');
    const [deleteCandidate, setDeleteCandidate] = useState(null);
    const [downloadingChat, setDownloadingChat] = useState(false);

    const isDraft = sessionId === null;

    const activeTitle = useMemo(() => {
        if (isDraft) return 'New Session (Draft)';
        return sessions.find(s => s.session_id === sessionId)?.title || 'SOC Analyst Session';
    }, [sessions, sessionId, isDraft]);

    const refreshSessions = async () => {
        try {
            const data = await listChatSessions(100);
            const rows = data || [];
            setSessions(rows);
            if (sessionId && !rows.some(s => s.session_id === sessionId)) {
                setSessionId(rows.length ? rows[0].session_id : null);
            }
        } catch {
            setSessions([]);
        }
    };

    const loadMessages = async (sid) => {
        if (!sid) {
            setMessages([]);
            return;
        }
        try {
            const data = await getChatMessages(sid);
            setMessages(data || []);
        } catch {
            setMessages([]);
        }
    };

    useEffect(() => {
        refreshSessions();
    }, []);

    useEffect(() => {
        loadMessages(sessionId);
    }, [sessionId]);

    const handleNewSession = () => {
        setSessionId(null);
        setMessages([]);
        setQuestion('');
    };

    const handleDeleteSession = (e, sid) => {
        e.stopPropagation();
        const target = sessions.find(s => s.session_id === sid);
        setDeleteCandidate({
            sessionId: sid,
            title: target?.title || sid,
        });
    };

    const confirmDeleteSession = async () => {
        if (!deleteCandidate?.sessionId) return;
        const sid = deleteCandidate.sessionId;
        try {
            await deleteChatSession(sid);
            const remaining = sessions.filter(s => s.session_id !== sid);
            setSessions(remaining);

            if (sessionId === sid) {
                if (remaining.length > 0) {
                    setSessionId(remaining[0].session_id);
                } else {
                    setSessionId(null);
                    setMessages([]);
                }
            }
        } catch {
            // ignore delete failures
        } finally {
            setDeleteCandidate(null);
        }
    };

    const handleAsk = async (e) => {
        e.preventDefault();
        const q = question.trim();
        if (!q || loading) return;

        setLoading(true);
        const optimistic = [...messages, { role: 'user', content: q, id: `u-${Date.now()}` }];
        setMessages(optimistic);
        setQuestion('');

        try {
            const res = await askAnalyst({
                sessionId,
                question: q,
                alertId: scopeAlertId.trim() || null,
                clusterId: scopeClusterId.trim() || null,
                modelType: 'hybrid',
            });

            if (res.session_id && res.session_id !== sessionId) {
                setSessionId(res.session_id);
            }
            await refreshSessions();
            await loadMessages(res.session_id || sessionId);
        } catch {
            setMessages([
                ...optimistic,
                {
                    role: 'assistant',
                    content: 'Unable to generate a response right now. Please verify backend/Groq configuration and try again.',
                    id: `a-${Date.now()}`,
                },
            ]);
        } finally {
            setLoading(false);
        }
    };

    const handleDownloadChat = async () => {
        if (!sessionId || downloadingChat) return;
        setDownloadingChat(true);
        try {
            await downloadChatReport(sessionId);
        } catch {
            // keep UI clean on download failures
        } finally {
            setDownloadingChat(false);
        }
    };

    return (
        <>
            <div className="page-header">
                <div>
                    <h1 className="page-title">🧠 Analyst Chat</h1>
                    <p className="page-subtitle">RAG context from alerts/campaigns + Groq LLM response</p>
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                    <button
                        className="btn btn-ghost"
                        onClick={handleDownloadChat}
                        disabled={!sessionId || downloadingChat}
                        title={sessionId ? 'Download current chat as PDF' : 'Start or open a session first'}
                    >
                        {downloadingChat ? 'Preparing...' : '⬇ Chat PDF'}
                    </button>
                    <button className="btn btn-primary" onClick={handleNewSession}>+ New Session</button>
                </div>
            </div>

            <div className="page-content" style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: 16 }}>
                <div className="card" style={{ maxHeight: '75vh', overflowY: 'auto' }}>
                    <div className="card-title">Sessions</div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                        {isDraft && (
                            <div
                                className="btn btn-primary"
                                style={{ justifyContent: 'flex-start', textAlign: 'left', padding: '8px 10px' }}
                            >
                                <span style={{ fontSize: 12 }}>New Session (Draft)</span>
                            </div>
                        )}

                        {sessions.length === 0 && !isDraft && (
                            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>No sessions yet.</div>
                        )}

                        {sessions.map(s => (
                            <div
                                key={s.session_id}
                                className={`btn ${sessionId === s.session_id ? 'btn-primary' : ''}`}
                                style={{
                                    display: 'flex',
                                    justifyContent: 'space-between',
                                    alignItems: 'center',
                                    textAlign: 'left',
                                    padding: '8px 10px',
                                    gap: 8,
                                }}
                                onClick={() => setSessionId(s.session_id)}
                            >
                                <span style={{ fontSize: 12, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                    {s.title || s.session_id}
                                </span>
                                <button
                                    onClick={(e) => handleDeleteSession(e, s.session_id)}
                                    style={{
                                        border: 'none',
                                        background: 'transparent',
                                        color: 'inherit',
                                        cursor: 'pointer',
                                        fontSize: 14,
                                        lineHeight: 1,
                                        opacity: 0.8,
                                    }}
                                    title="Delete session"
                                >
                                    ✕
                                </button>
                            </div>
                        ))}
                    </div>
                </div>

                <div className="card" style={{ display: 'flex', flexDirection: 'column', minHeight: '75vh' }}>
                    <div className="card-title">Conversation · {activeTitle}</div>
                    <div style={{ display: 'flex', gap: 10, marginBottom: 10 }}>
                        <input
                            value={scopeAlertId}
                            onChange={e => setScopeAlertId(e.target.value)}
                            placeholder="Optional Alert ID (single alert focus)"
                            style={{ flex: 1, background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8, color: 'var(--text-primary)', padding: '8px 10px', fontSize: 12 }}
                        />
                        <input
                            value={scopeClusterId}
                            onChange={e => setScopeClusterId(e.target.value)}
                            placeholder="Optional Campaign/Cluster ID (campaign focus)"
                            style={{ flex: 1, background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8, color: 'var(--text-primary)', padding: '8px 10px', fontSize: 12 }}
                        />
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: -4, marginBottom: 10 }}>
                        Leave both blank for overall SOC context. Use Alert ID for one alert investigation, or Campaign/Cluster ID for grouped campaign analysis.
                    </div>

                    <div style={{ flex: 1, overflowY: 'auto', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 10, padding: 12 }}>
                        {messages.length === 0 && (
                            <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
                                Ask questions like: "Summarize active campaigns and likely attack hypothesis."
                            </div>
                        )}
                        {messages.map((m, idx) => (
                            <div key={m.id || idx} style={{ marginBottom: 10, display: 'flex', justifyContent: m.role === 'user' ? 'flex-end' : 'flex-start' }}>
                                <div
                                    style={{
                                        maxWidth: '80%',
                                        background: m.role === 'user' ? 'var(--accent)' : 'var(--bg-card)',
                                        color: m.role === 'user' ? '#fff' : 'var(--text-primary)',
                                        border: '1px solid var(--border)',
                                        borderRadius: 10,
                                        padding: '10px 12px',
                                        fontSize: 13,
                                        lineHeight: 1.5,
                                        whiteSpace: 'pre-wrap',
                                    }}
                                >
                                    {m.content}
                                </div>
                            </div>
                        ))}
                    </div>

                    <form onSubmit={handleAsk} style={{ marginTop: 12, display: 'flex', gap: 8 }}>
                        <input
                            value={question}
                            onChange={e => setQuestion(e.target.value)}
                            placeholder="Ask the analyst assistant..."
                            style={{ flex: 1, background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8, color: 'var(--text-primary)', padding: '10px 12px', fontSize: 13 }}
                        />
                        <button className="btn btn-primary" disabled={loading || !question.trim()}>
                            {loading ? 'Thinking...' : 'Send'}
                        </button>
                    </form>
                </div>
            </div>

            {deleteCandidate && (
                <div
                    style={{
                        position: 'fixed',
                        inset: 0,
                        background: 'rgba(0, 0, 0, 0.55)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        zIndex: 9999,
                        padding: 16,
                    }}
                    onClick={() => setDeleteCandidate(null)}
                >
                    <div
                        className="card"
                        style={{ width: 'min(480px, 100%)', margin: 0 }}
                        onClick={(e) => e.stopPropagation()}
                    >
                        <div className="card-title" style={{ marginBottom: 8 }}>Delete Session</div>
                        <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                            Are you sure you want to delete this session permanently?
                        </div>
                        <div
                            style={{
                                marginTop: 8,
                                fontSize: 12,
                                color: 'var(--text-muted)',
                                whiteSpace: 'nowrap',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                            }}
                        >
                            Session: {deleteCandidate.title}
                        </div>
                        <div style={{ marginTop: 14, display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
                            <button className="btn" onClick={() => setDeleteCandidate(null)}>Cancel</button>
                            <button className="btn btn-primary" onClick={confirmDeleteSession}>Delete</button>
                        </div>
                    </div>
                </div>
            )}
        </>
    );
}
