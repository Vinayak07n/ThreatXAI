// App.jsx — Main router with sidebar layout
import { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, useLocation, useNavigate } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import Clusters from './pages/Clusters';
import AlertDetail from './pages/AlertDetail';
import ModelPerf from './pages/ModelPerf';
import MetricsComparison from './pages/MetricsComparison';
import Settings from './pages/Settings';
import AnalystChat from './pages/AnalystChat';
import { startCapture, stopCapture, getCaptureStatus } from './api/client';

const NAV = [
  { id: 'dashboard', label: 'Live Dashboard', icon: '📡', path: '/' },
  { id: 'clusters', label: 'Attack Campaigns', icon: '🔗', path: '/clusters', badge: 'NEW', badgeColor: 'green' },
  { id: 'performance', label: 'Model Performance', icon: '📊', path: '/performance' },
  { id: 'metrics-compare', label: 'Comparison Metrics', icon: '📈', path: '/metrics-comparison' },
  { id: 'analyst-chat', label: 'Analyst Chat', icon: '🧠', path: '/analyst-chat', badge: 'NEW', badgeColor: 'green' },
  { id: 'settings', label: 'Settings', icon: '⚙️', path: '/settings' },
];

function Sidebar({ capturing, setCapturing, alertCount }) {
  const navigate = useNavigate();
  const location = useLocation();

  const handleCaptureToggle = async () => {
    try {
      if (capturing) {
        await stopCapture();
        setCapturing(false);
      } else {
        await startCapture();
        setCapturing(true);
      }
    } catch (e) {
      // Demo mode — toggle anyway
      setCapturing(!capturing);
    }
  };

  return (
    <div className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-text">
          <div className="logo-icon">🛡️</div>
          <div>
            <div className="logo-title">ThreatXAI</div>
            <div className="logo-subtitle">XAI · IDS · SOC</div>
          </div>
        </div>
      </div>

      <div className="nav-section">Monitoring</div>
      {NAV.map(item => (
        <button
          key={item.id}
          className={`nav-link ${location.pathname === item.path ? 'active' : ''}`}
          onClick={() => navigate(item.path)}
        >
          <span>{item.icon}</span>
          <span>{item.label}</span>
          {item.id === 'dashboard' && alertCount > 0 && (
            <span className="nav-badge">{alertCount > 99 ? '99+' : alertCount}</span>
          )}
          {item.badge && item.id !== 'dashboard' && (
            <span className={`nav-badge ${item.badgeColor || ''}`}>{item.badge}</span>
          )}
        </button>
      ))}

      <div className="sidebar-footer">
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8, textAlign: 'center' }}>
          {capturing
            ? <><span className="live-dot" style={{ marginRight: 6 }}></span>Capturing live traffic</>
            : 'Capture stopped'
          }
        </div>
        <button
          className={`capture-btn ${capturing ? 'stop' : 'start'}`}
          onClick={handleCaptureToggle}
        >
          {capturing ? '⏹ Stop Capture' : '▶ Start Capture'}
        </button>
      </div>
    </div>
  );
}

function AppLayout() {
  const [capturing, setCapturing] = useState(false);
  const [alertCount, setAlertCount] = useState(0);
  const [pollingInterval, setPollingInterval] = useState(() => {
    const saved = localStorage.getItem('threatxai_polling_interval');
    return saved ? Number(saved) : 3;
  });

  // Persist polling interval to localStorage whenever it changes
  useEffect(() => {
    localStorage.setItem('threatxai_polling_interval', String(pollingInterval));
  }, [pollingInterval]);

  useEffect(() => {
    // Check capture status on load
    getCaptureStatus().then(s => {
      setCapturing(s.status === 'running');
      setAlertCount(s.alerts_generated || 0);
    }).catch(() => { });
  }, []);

  return (
    <div className="app-layout">
      <Sidebar capturing={capturing} setCapturing={setCapturing} alertCount={alertCount} />
      <div className="main-content">
        <Routes>
          <Route path="/" element={<Dashboard capturing={capturing} setAlertCount={setAlertCount} pollingInterval={pollingInterval} />} />
          <Route path="/clusters" element={<Clusters />} />
          <Route path="/alerts/:alertId" element={<AlertDetail />} />
          <Route path="/performance" element={<ModelPerf />} />
          <Route path="/metrics-comparison" element={<MetricsComparison />} />
          <Route path="/analyst-chat" element={<AnalystChat />} />
          <Route path="/settings" element={<Settings pollingInterval={pollingInterval} setPollingInterval={setPollingInterval} />} />
        </Routes>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AppLayout />
    </BrowserRouter>
  );
}
