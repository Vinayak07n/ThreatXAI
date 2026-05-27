"""routers/capture.py — POST /capture/start and /capture/stop"""

import json
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import and_
from backend.db.session import get_db
from backend.db.models import Alert
from backend.services import capture_service

router = APIRouter(prefix="/capture", tags=["Packet Capture"])

# Deduplication window (seconds) — skip storing if same src_ip+dst_ip+cluster_id
# was stored within this window
DEDUP_WINDOW_SECONDS = 60


def _store_alert(alert_data: dict):
    """Callback: writes captured+classified alert to database with deduplication."""
    from ..db.session import SessionLocal
    import logging
    log = logging.getLogger(__name__)
    db = SessionLocal()
    try:
        src_ip = alert_data.get("src_ip")
        dst_ip = alert_data.get("dst_ip")
        cluster_id = alert_data.get("cluster_id")

        # ── Deduplication: skip if same flow+cluster seen recently ──────────
        if src_ip and dst_ip and cluster_id:
            cutoff = datetime.utcnow() - timedelta(seconds=DEDUP_WINDOW_SECONDS)
            duplicate = db.query(Alert.id).filter(
                and_(
                    Alert.src_ip == src_ip,
                    Alert.dst_ip == dst_ip,
                    Alert.cluster_id == cluster_id,
                    Alert.timestamp >= cutoff,
                )
            ).first()
            if duplicate:
                log.debug(f"Dedup: skipping duplicate alert {src_ip}→{dst_ip} cluster={cluster_id}")
                return

        shap_data = {}
        for f in alert_data.get("shap_top_features", []):
            if isinstance(f, dict):
                shap_data[f["feature"]] = f["shap_value"]
            elif isinstance(f, (list, tuple)) and len(f) == 2:
                shap_data[f[0]] = f[1]

        alert = Alert(
            alert_id=alert_data.get("alert_id"),
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=alert_data.get("protocol"),
            prediction=alert_data.get("prediction", 0),
            label=alert_data.get("label", "Benign"),
            confidence=alert_data.get("confidence", 0.0),
            attack_probability=alert_data.get("attack_probability"),
            cluster_id=cluster_id,
            cluster_label=alert_data.get("cluster_label"),
            cluster_similarity=alert_data.get("cluster_similarity"),
            shap_json=json.dumps(shap_data),
            is_live_capture=True,
        )
        db.add(alert)
        db.commit()

        # ── Enforce alert cap ──────────────────────────────────────────────
        from backend.routers.alerts import _enforce_alert_cap
        _enforce_alert_cap(db)

    except Exception as e:
        log.error(f"Failed to store captured alert: {e}")
    finally:
        db.close()


@router.post("/start")
async def start_capture():
    """
    Start live packet capture + inference pipeline.
    
    Details:
    - Source: Live packets from all network interfaces using Scapy
    - Model: XGBoost (default for speed)
    - Features: Extracted from IP/TCP/UDP headers (68 features total)
    - Explanations: SHAP computed for all traffic (benign + attack)
    - Storage: Alerts stored in SQLite with full metadata
    - Requirements: Requires sudo/elevated privileges on macOS/Linux
    
    Falls back to demo/simulation mode automatically if permissions unavailable.
    """
    result = capture_service.start_capture(on_alert=_store_alert)
    return result


@router.post("/stop")
async def stop_capture():
    return capture_service.stop_capture()


@router.get("/status")
async def capture_status():
    return capture_service.get_capture_status()


@router.get("/info")
async def capture_info():
    """
    Detailed information about where packets come from and how they're processed.
    
    Alert Sources:
    1. Live Capture (/capture/start): Scapy sniffs packets from all network interfaces
    2. Manual Prediction (POST /predict): Submit feature vectors directly
    
    Live Capture Pipeline:
    - Packet Source: All network interfaces (requires sudo on macOS/Linux)
    - Flow Collection: Packets grouped into flows (TCP/UDP bidirectional)
    - Feature Extraction: CICFlowMeter-style features (68 total)
    - Model: XGBoost (fast, interpretable)
    - Explanations: SHAP values computed for all traffic
    - Output: Alert with metadata stored in SQLite
    """
    return {
        "packet_sources": {
            "live_capture": "All network interfaces via Scapy (requires sudo)",
            "manual_prediction": "POST /predict with 68-feature array",
        },
        "models_available": ["xgboost", "rf", "dnn", "hybrid"],
        "model_for_live_capture": "xgboost (default)",
        "explanations_for": "all traffic (benign + attack)",
        "alert_storage": "SQLite database at /backend/threatxai.db",
        "alert_fields": [
            "alert_id (UUID)",
            "timestamp",
            "src_ip",
            "dst_ip",
            "protocol",
            "prediction (0=benign, 1=attack)",
            "confidence (0-1)",
            "shap_json (explanations)",
            "cluster_id (for attacks)",
            "is_live_capture (true for captured alerts)",
        ]
    }
