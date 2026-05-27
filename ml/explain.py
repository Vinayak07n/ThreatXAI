"""
explain.py — SHAP + LIME Explanation Engine
Provides global and local explanations for XGBoost, RF, and DNN models.
"""

import os
import json
import numpy as np
import joblib
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

PROCESSED_DIR = os.path.join(os.path.dirname(__file__), "data", "processed")
MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")


def get_feature_names():
    path = os.path.join(PROCESSED_DIR, "feature_names.npy")
    return np.load(path, allow_pickle=True).tolist()


# ─── SHAP Engine ──────────────────────────────────────────────────────────────

# Cached background dataset for DNN KernelExplainer
_dnn_background = None


def _get_dnn_background():
    """Load and cache a small background dataset from training data for SHAP KernelExplainer."""
    global _dnn_background
    if _dnn_background is None:
        bg_path = os.path.join(PROCESSED_DIR, "X_train.npy")
        if os.path.exists(bg_path):
            X_train = np.load(bg_path, allow_pickle=True)
            # Sample 100 random instances as background
            idx = np.random.choice(len(X_train), min(100, len(X_train)), replace=False)
            _dnn_background = X_train[idx].astype(np.float32)
            log.info(f"SHAP DNN background loaded: {_dnn_background.shape}")
        else:
            log.warning("X_train.npy not found — DNN SHAP explanations won't work")
    return _dnn_background


def compute_shap_values(model, X: np.ndarray, model_type: str = "xgboost") -> np.ndarray:
    """
    Returns SHAP values for X.
    model_type: 'xgboost' | 'rf' | 'dnn' | 'hybrid'
    """
    import shap

    if model_type in ("xgboost", "rf"):
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(X)
        # For binary classification RF returns list of 2 arrays
        if isinstance(shap_values, list):
            shap_values = shap_values[1]  # class=1 (attack)
    elif model_type in ("dnn", "hybrid"):
        # Use cached background dataset (not the input instance!)
        bg = _get_dnn_background()
        if bg is None:
            log.warning("No background data for DNN/Hybrid SHAP — returning zeros")
            return np.zeros_like(X)
        if model_type == "dnn":
            predict_fn = lambda x: model.predict(x, verbose=0).flatten()
        else:
            predict_fn = lambda x: model.predict_proba(x)[:, 1]
        explainer = shap.KernelExplainer(predict_fn, bg)
        shap_values = explainer.shap_values(X, nsamples=100)
    else:
        raise ValueError(f"Unknown model_type: {model_type}")

    return np.array(shap_values)


def shap_global_summary(model, X: np.ndarray, feature_names: list,
                         model_type: str = "xgboost", output_dir: str = None) -> dict:
    """
    Computes global SHAP feature importance.
    Returns dict: {feature_name: mean_abs_shap_value}
    """
    import shap
    import matplotlib.pyplot as plt

    shap_values = compute_shap_values(model, X[:500], model_type)  # subset for speed
    mean_abs = np.abs(shap_values).mean(axis=0)
    importance = dict(zip(feature_names, mean_abs.tolist()))
    importance_sorted = dict(sorted(importance.items(), key=lambda x: x[1], reverse=True))

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        # Bar chart of top 20
        top20 = list(importance_sorted.items())[:20]
        names, vals = zip(*top20)
        fig, ax = plt.subplots(figsize=(10, 7))
        colors = [f"#{int(255*(1-v/vals[0])):02x}{int(100+155*v/vals[0]):02x}ff" for v in vals]
        ax.barh(list(reversed(names)), list(reversed(vals)), color=list(reversed(colors)))
        ax.set_xlabel("Mean |SHAP Value|", fontsize=12)
        ax.set_title(f"Global SHAP Feature Importance ({model_type.upper()})", fontsize=14, fontweight="bold")
        plt.tight_layout()
        path = os.path.join(output_dir, f"shap_importance_{model_type}.png")
        plt.savefig(path, dpi=150)
        plt.close()
        log.info(f"SHAP importance plot saved → {path}")

    return importance_sorted


def shap_local_explanation(model, instance: np.ndarray, feature_names: list,
                            model_type: str = "xgboost") -> dict:
    """
    Returns local SHAP explanation for a single instance.
    Returns: {feature: shap_value} sorted by absolute impact.
    """
    shap_values = compute_shap_values(model, instance.reshape(1, -1), model_type)
    shap_vec = shap_values.flatten()
    explanation = {
        "shap_values": dict(zip(feature_names, shap_vec.tolist())),
        "top_features": sorted(
            zip(feature_names, shap_vec.tolist()),
            key=lambda x: abs(x[1]), reverse=True
        )[:15],
        "shap_vector": shap_vec.tolist(),  # raw vector for EDAC clustering
    }
    return explanation


# ─── LIME Engine ──────────────────────────────────────────────────────────────

def lime_local_explanation(model, instance: np.ndarray,
                            X_train: np.ndarray, feature_names: list,
                            model_type: str = "xgboost", num_features: int = 15) -> dict:
    """
    Returns LIME local explanation for a single instance.
    """
    from lime.lime_tabular import LimeTabularExplainer

    if model_type in ("xgboost", "rf"):
        predict_fn = model.predict_proba
    else:  # DNN
        predict_fn = lambda x: np.column_stack([
            1 - model.predict(x, verbose=0).flatten(),
            model.predict(x, verbose=0).flatten()
        ])

    explainer = LimeTabularExplainer(
        X_train,
        feature_names=feature_names,
        class_names=["Benign", "Attack"],
        mode="classification",
        random_state=42,
    )

    exp = explainer.explain_instance(
        instance, predict_fn,
        num_features=num_features,
        num_samples=500,
    )

    lime_vals = exp.as_list()  # [(feature_desc, weight), ...]

    return {
        "lime_features": [{"feature": f, "weight": round(w, 6)} for f, w in lime_vals],
        "prediction_proba": exp.predict_proba.tolist(),
        "top_features": lime_vals[:10],
    }


# ─── Batch explanation for training (used by EDAC) ────────────────────────────

def compute_shap_vectors_batch(model, X: np.ndarray, model_type: str = "xgboost") -> np.ndarray:
    """Compute SHAP vectors for a batch of instances. Returns shape (N, n_features)."""
    return compute_shap_values(model, X, model_type)


if __name__ == "__main__":
    # Quick smoke test
    X_train = np.load(os.path.join(PROCESSED_DIR, "X_train.npy"))
    X_test = np.load(os.path.join(PROCESSED_DIR, "X_test.npy"))
    feature_names = get_feature_names()
    model = joblib.load(os.path.join(MODELS_DIR, "xgboost_model.pkl"))

    log.info("Running global SHAP summary...")
    importance = shap_global_summary(model, X_test, feature_names, "xgboost", MODELS_DIR)
    log.info(f"Top 5 features: {list(importance.items())[:5]}")

    log.info("Running local SHAP for instance 0...")
    local = shap_local_explanation(model, X_test[0], feature_names, "xgboost")
    log.info(f"Top SHAP feature: {local['top_features'][0]}")

    log.info("Running LIME for instance 0...")
    lime = lime_local_explanation(model, X_test[0], X_train, feature_names, "xgboost")
    log.info(f"LIME top: {lime['lime_features'][:3]}")
