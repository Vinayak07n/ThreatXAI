"""services/model_service.py — Loads and caches all trained models + EDAC engine"""

import os
import sys
import json
import numpy as np
import joblib
import logging

log = logging.getLogger(__name__)

ML_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "..", "ml")
MODELS_DIR = os.path.join(ML_DIR, "models")
PROCESSED_DIR = os.path.join(ML_DIR, "data", "processed")

# Global model cache
_models = {}
_feature_names = None
_scaler = None
_edac_engine = None


def get_models():
    global _models
    if not _models:
        load_all_models()
    return _models


def get_feature_names():
    global _feature_names
    if _feature_names is None:
        path = os.path.join(PROCESSED_DIR, "feature_names.npy")
        _feature_names = np.load(path, allow_pickle=True).tolist()
    return _feature_names


def get_scaler():
    global _scaler
    if _scaler is None:
        path = os.path.join(MODELS_DIR, "scaler.pkl")
        _scaler = joblib.load(path)
    return _scaler


def get_edac_engine():
    global _edac_engine
    if _edac_engine is None:
        sys.path.insert(0, ML_DIR)
        try:
            from edac import EDACEngine
            edac_path = os.path.join(MODELS_DIR, "edac_engine.pkl")
            if os.path.exists(edac_path):
                try:
                    _edac_engine = joblib.load(edac_path)
                    log.info("✓ EDAC engine loaded from pickle")
                except Exception as e:
                    log.warning(f"EDAC pickle load failed ({e}), creating new engine")
                    feature_names = get_feature_names()
                    _edac_engine = EDACEngine(feature_names)
            else:
                feature_names = get_feature_names()
                _edac_engine = EDACEngine(feature_names)
                log.warning("EDAC engine not seeded. Run `python ml/edac.py` first.")
        except Exception as e:
            log.error(f"EDAC loading failed: {e}")
            _edac_engine = None
    return _edac_engine


def get_metrics() -> list:
    path = os.path.join(MODELS_DIR, "metrics.json")
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return json.load(f)


def get_cicids_metrics() -> list:
    path = os.path.join(MODELS_DIR, "metrics_cicids.json")
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return json.load(f)


def get_metrics_comparison() -> dict:
    return {
        "current_dataset": {
            "name": "ThreatXAI-SynthShield-v1",
            "metrics": get_metrics(),
        },
        "cicids_dataset": {
            "name": "CIC-IDS2017",
            "metrics": get_cicids_metrics(),
        },
    }


def get_attack_names() -> list:
    path = os.path.join(MODELS_DIR, "attack_names.json")
    if not os.path.exists(path):
        return ["BENIGN", "Attack"]
    with open(path) as f:
        return json.load(f)


def load_all_models():
    global _models
    sys.path.insert(0, ML_DIR)
    log.info("Loading trained models...")

    xgb_path = os.path.join(MODELS_DIR, "xgboost_model.pkl")
    if os.path.exists(xgb_path):
        _models["xgboost"] = joblib.load(xgb_path)
        log.info("✓ XGBoost loaded")

    rf_path = os.path.join(MODELS_DIR, "rf_model.pkl")
    if os.path.exists(rf_path):
        _models["rf"] = joblib.load(rf_path)
        log.info("✓ Random Forest loaded")

    hybrid_path = os.path.join(MODELS_DIR, "hybrid_model.pkl")
    if os.path.exists(hybrid_path):
        _models["hybrid"] = joblib.load(hybrid_path)
        log.info("✓ Hybrid Ensemble loaded")

    try:
        import tensorflow as tf
        dnn_path = os.path.join(MODELS_DIR, "dnn_model.keras")
        if os.path.exists(dnn_path):
            _models["dnn"] = tf.keras.models.load_model(dnn_path)
            log.info("✓ DNN loaded")
    except Exception as e:
        log.warning(f"DNN not loaded: {e}")

    if not _models:
        log.error("No models found! Run `python ml/preprocess.py && python ml/train.py` first.")
