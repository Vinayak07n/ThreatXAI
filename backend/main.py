"""main.py — ThreatXAI FastAPI Application Entry Point"""

import os
import sys
import json
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

# Add backend directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# Ensure .env is loaded for API keys/config regardless of launch command/cwd.
try:
    from dotenv import load_dotenv

    _BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    load_dotenv(os.path.join(_BASE_DIR, ".env"), override=False)
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"), override=False)
except Exception:
    pass


def _apply_sqlite_chat_migrations():
    """Best-effort migration for chat tables on existing SQLite DBs."""
    try:
        import sqlite3

        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "threatxai.db")
        if not os.path.exists(db_path):
            return

        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='chat_sessions'")
        has_sessions = cur.fetchone() is not None
        if has_sessions:
            cur.execute("PRAGMA table_info(chat_sessions)")
            cols = {r[1] for r in cur.fetchall()}
            if "title" not in cols:
                cur.execute("ALTER TABLE chat_sessions ADD COLUMN title VARCHAR(180)")
            if "model_name" not in cols:
                cur.execute("ALTER TABLE chat_sessions ADD COLUMN model_name VARCHAR(80)")
            if "updated_at" not in cols:
                cur.execute("ALTER TABLE chat_sessions ADD COLUMN updated_at DATETIME")

        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='chat_messages'")
        has_messages = cur.fetchone() is not None
        if has_messages:
            cur.execute("PRAGMA table_info(chat_messages)")
            cols = {r[1] for r in cur.fetchall()}
            if "context_json" not in cols:
                cur.execute("ALTER TABLE chat_messages ADD COLUMN context_json TEXT")

        conn.commit()
        conn.close()
    except Exception as e:
        log.warning(f"Chat schema migration skipped: {e}")


def _apply_sqlite_alert_migrations():
    """Best-effort migration for alert table additions on existing SQLite DBs."""
    try:
        import sqlite3

        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "threatxai.db")
        if not os.path.exists(db_path):
            return

        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'")
        has_alerts = cur.fetchone() is not None
        if has_alerts:
            cur.execute("PRAGMA table_info(alerts)")
            cols = {r[1] for r in cur.fetchall()}
            if "attack_probability" not in cols:
                cur.execute("ALTER TABLE alerts ADD COLUMN attack_probability FLOAT")

        conn.commit()
        conn.close()
    except Exception as e:
        log.warning(f"Alert schema migration skipped: {e}")


def _backfill_unassigned_attack_clusters(limit: int = 500):
    """
    Best-effort repair: assign campaign clusters to historical attack alerts
    that were stored without cluster_id.
    """
    try:
        from backend.db.session import SessionLocal
        from backend.db.models import Alert
        from backend.services.model_service import get_edac_engine
        import numpy as np

        edac = get_edac_engine()
        if edac is None:
            return

        db = SessionLocal()
        try:
            rows = (
                db.query(Alert)
                .filter(Alert.prediction == 1, Alert.cluster_id.is_(None), Alert.shap_json.isnot(None))
                .order_by(Alert.timestamp.asc())
                .limit(limit)
                .all()
            )
            repaired = 0
            for alert in rows:
                try:
                    shap_map = json.loads(alert.shap_json or "{}")
                    if not shap_map:
                        continue
                    vec = np.array([float(shap_map.get(f, 0.0)) for f in edac.feature_names], dtype=np.float32)
                    cluster_info = edac.assign_alert(vec, alert.alert_id)
                    alert.cluster_id = cluster_info.get("cluster_id")
                    alert.cluster_label = cluster_info.get("label")
                    alert.cluster_similarity = cluster_info.get("similarity_score")
                    repaired += 1
                except Exception:
                    continue
            if repaired > 0:
                db.commit()
                log.info(f"✓ Backfilled cluster assignment for {repaired} historical attack alerts")
        finally:
            db.close()
    except Exception as e:
        log.warning(f"Cluster backfill skipped: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: load models and create DB tables."""
    log.info("★ ThreatXAI API starting...")
    try:
        from backend.db.session import engine
        from backend.db import models
        models.Base.metadata.create_all(bind=engine)
        _apply_sqlite_chat_migrations()
        _apply_sqlite_alert_migrations()
        log.info("✓ Database tables created")
    except Exception as e:
        log.error(f"Database setup failed: {e}")
    
    # Apply persistent config
    try:
        from backend.services import capture_service
        capture_service._default_model = _app_config.get("default_model", "xgboost")
        
        from backend.services.model_service import get_edac_engine
        edac = get_edac_engine()
        if edac:
            edac.SIMILARITY_THRESHOLD = float(_app_config.get("edac_similarity_threshold", 0.80))
        log.info("✓ Persistent configuration applied")
        _backfill_unassigned_attack_clusters()
    except Exception as e:
        log.error(f"Failed to apply config: {e}")

    log.info("★ ThreatXAI API ready")
    yield
    log.info("ThreatXAI API shutting down")


app = FastAPI(
    title="ThreatXAI API",
    description=(
        "Explainable Intrusion Detection System with SHAP, LIME, and "
        "Explanation-Driven Alert Clustering (EDAC)."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
from backend.routers import predict, explain, alerts, capture, clusters, chat, reports

app.include_router(predict.router)
app.include_router(explain.router)
app.include_router(alerts.router)
app.include_router(capture.router)
app.include_router(clusters.router)
app.include_router(chat.router)
app.include_router(reports.router)


@app.get("/", tags=["Health"])
async def root():
    return {
        "name": "ThreatXAI API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
        "novel_feature": "Explanation-Driven Alert Clustering (EDAC)",
    }


@app.get("/health", tags=["Health"])
async def health():
    from backend.services.model_service import get_models
    models = get_models()
    return {
        "status": "healthy",
        "models_loaded": list(models.keys()),
        "model_count": len(models),
    }


@app.get("/metrics", tags=["Model Performance"])
async def model_metrics():
    from backend.services.model_service import get_metrics
    return {"metrics": get_metrics()}


@app.get("/metrics/comparison", tags=["Model Performance"])
async def model_metrics_comparison():
    from backend.services.model_service import get_metrics_comparison
    return get_metrics_comparison()


# ─── Runtime Configuration ─────────────────────────────────────────────────────

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

_app_config = {
    "default_model": "xgboost",
    "edac_similarity_threshold": 0.80,
    "min_campaign_size": 2,
    "max_alerts": 500,
}

if os.path.exists(CONFIG_FILE):
    try:
        with open(CONFIG_FILE, "r") as f:
            _app_config.update(json.load(f))
    except Exception as e:
        log.error(f"Failed to load config from JSON: {e}")

def _save_config():
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(_app_config, f, indent=4)
    except Exception as e:
        log.error(f"Failed to save config to JSON: {e}")


@app.get("/config", tags=["Configuration"])
async def get_config():
    return _app_config


@app.post("/config", tags=["Configuration"])
async def update_config(updates: dict):
    changed = {}
    if "default_model" in updates:
        valid_models = ["xgboost", "rf", "dnn", "hybrid"]
        model = updates["default_model"].lower()
        if model in valid_models:
            _app_config["default_model"] = model
            from backend.services import capture_service
            capture_service._default_model = model
            changed["default_model"] = model
    if "edac_similarity_threshold" in updates:
        thresh = float(updates["edac_similarity_threshold"])
        thresh = max(0.5, min(0.99, thresh))
        _app_config["edac_similarity_threshold"] = thresh
        try:
            from backend.services.model_service import get_edac_engine
            edac = get_edac_engine()
            if edac:
                edac.SIMILARITY_THRESHOLD = thresh
        except Exception:
            pass
        changed["edac_similarity_threshold"] = thresh
    if "max_alerts" in updates:
        cap = int(updates["max_alerts"])
        cap = max(50, min(10000, cap))
        _app_config["max_alerts"] = cap
        changed["max_alerts"] = cap
    if "min_campaign_size" in updates:
        m = int(updates["min_campaign_size"])
        m = max(1, min(20, m))
        _app_config["min_campaign_size"] = m
        changed["min_campaign_size"] = m
        
    _save_config()
    
    return {"status": "updated", "config": _app_config, "changed": changed}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
