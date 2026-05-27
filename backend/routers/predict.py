"""routers/predict.py — POST /predict endpoint"""

import uuid
import json
import numpy as np
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.db.session import get_db
from backend.db.models import Alert
from backend.schemas import PredictRequest, PredictResponse
from backend.services.model_service import get_models, get_scaler, get_feature_names, get_edac_engine
from backend.services.explain_service import get_shap_explanation

router = APIRouter(prefix="/predict", tags=["Prediction"])

# Hardcoded per-model decision thresholds to reduce live false positives.
MODEL_ATTACK_THRESHOLDS = {
    "xgboost": 0.70,
    "rf": 0.72,
    "dnn": 0.75,
    "hybrid": 0.88,
}


def _get_attack_threshold(model_type: str) -> float:
    return float(MODEL_ATTACK_THRESHOLDS.get(model_type, 0.5))


@router.post("", response_model=PredictResponse)
async def predict(req: PredictRequest, db: Session = Depends(get_db)):
    models = get_models()
    if not models:
        raise HTTPException(503, "Models not loaded. Run training pipeline first.")

    model_type = req.model_type
    if model_type not in models:
        model_type = next(iter(models))

    model = models[model_type]
    scaler = get_scaler()
    feature_names = get_feature_names()

    features = np.array(req.features, dtype=np.float32)

    # Align dimensions
    n_expected = scaler.mean_.shape[0]
    if len(features) < n_expected:
        features = np.pad(features, (0, n_expected - len(features)))
    elif len(features) > n_expected:
        features = features[:n_expected]

    features_scaled = scaler.transform(features.reshape(1, -1))[0]

    # Predict
    if model_type == "dnn":
        proba = float(model.predict(features_scaled.reshape(1, -1), verbose=0).flatten()[0])
    else:
        proba = float(model.predict_proba(features_scaled.reshape(1, -1))[0][1])
    proba = max(0.0, min(1.0, proba))

    attack_threshold = _get_attack_threshold(model_type)
    prediction = int(proba >= attack_threshold)
    label = "Attack" if prediction == 1 else "Benign"
    alert_id = str(uuid.uuid4())

    # SHAP explanations for ALL traffic (both benign and attack)
    cluster_id = cluster_label = cluster_similarity = None
    shap_json = None
    shap_vector = np.array([], dtype=np.float32)

    try:
        shap_exp = get_shap_explanation(model, features_scaled, feature_names, model_type)
        shap_vector = np.array(shap_exp.get("shap_vector", []), dtype=np.float32)
        shap_json = json.dumps(shap_exp.get("shap_values", {}))

        # EDAC clustering only for attacks
        if prediction == 1:
            try:
                edac = get_edac_engine()
                if edac is not None:
                    cluster_info = edac.assign_alert(shap_vector, alert_id)
                    cluster_id = cluster_info.get("cluster_id")
                    cluster_label = cluster_info.get("label")
                    cluster_similarity = cluster_info.get("similarity_score")
            except Exception as e:
                import logging
                logging.warning(f"EDAC clustering failed: {e}")
    except Exception as e:
        import logging
        logging.error(f"SHAP Error: {e}")

    # Fallback clustering path so attack alerts are not left unassigned.
    if prediction == 1 and not cluster_id:
        try:
            edac = get_edac_engine()
            if edac is not None:
                if shap_vector.size == 0:
                    shap_vector = np.array(features_scaled, dtype=np.float32)
                cluster_info = edac.assign_alert(shap_vector, alert_id)
                cluster_id = cluster_info.get("cluster_id")
                cluster_label = cluster_info.get("label")
                cluster_similarity = cluster_info.get("similarity_score")
        except Exception as e:
            import logging
            logging.warning(f"EDAC fallback clustering failed: {e}")

    # Final confidence aligned to predicted label:
    # Attack => P(attack), Benign => P(benign)=1-P(attack)
    if prediction == 1:
        decision_confidence = max(0.0, min(1.0, round(proba, 4)))
    else:
        decision_confidence = max(0.0, min(1.0, round(1.0 - proba, 4)))

    # Store in DB
    alert = Alert(
        alert_id=alert_id,
        src_ip=req.src_ip,
        dst_ip=req.dst_ip,
        protocol=req.protocol,
        prediction=prediction,
        label=label,
        confidence=decision_confidence,
        attack_probability=round(proba, 4),
        cluster_id=cluster_id,
        cluster_label=cluster_label,
        cluster_similarity=cluster_similarity,
        shap_json=shap_json,
        features_json=json.dumps(req.features),
    )
    db.add(alert)
    db.commit()

    confidence = decision_confidence
    
    return PredictResponse(
        prediction=prediction,
        label=label,
        confidence=confidence,
        attack_probability=max(0.0, min(1.0, round(proba, 4))),
        model_used=model_type,
        alert_id=alert_id,
        cluster_id=cluster_id,
        cluster_label=cluster_label,
        cluster_similarity=cluster_similarity,
    )
