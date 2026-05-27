"""
evaluate.py — Model Evaluation and Metrics Generation
Evaluates all trained models and saves metrics + confusion matrix plots.
"""

import os
import json
import numpy as np
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    roc_curve,
)
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

PROCESSED_DIR = os.path.join(os.path.dirname(__file__), "data", "processed")
MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")


def load_test_data():
    X_test = np.load(os.path.join(PROCESSED_DIR, "X_test.npy"))
    y_test = np.load(os.path.join(PROCESSED_DIR, "y_test_binary.npy"))
    return X_test, y_test


def compute_metrics(name: str, y_true, y_pred, y_proba):
    metrics = {
        "model": name,
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_true, y_pred, zero_division=0), 4),
        "roc_auc": round(roc_auc_score(y_true, y_proba), 4),
    }
    log.info("\n%s Metrics:\n%s", name, json.dumps(metrics, indent=2))
    return metrics


def plot_confusion_matrix(name: str, y_true, y_pred, output_dir: str):
    cm = confusion_matrix(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=["Benign", "Attack"],
        yticklabels=["Benign", "Attack"],
        ax=ax,
    )
    ax.set_title(f"{name} — Confusion Matrix", fontsize=14, fontweight="bold")
    ax.set_ylabel("True Label")
    ax.set_xlabel("Predicted Label")
    plt.tight_layout()
    path = os.path.join(output_dir, f"confusion_matrix_{name.lower().replace(' ', '_')}.png")
    plt.savefig(path, dpi=150)
    plt.close()
    log.info(f"Confusion matrix saved → {path}")
    return path


def plot_roc_curves(all_results: list, output_dir: str):
    fig, ax = plt.subplots(figsize=(8, 6))
    colors = ["#2563EB", "#16A34A", "#DC2626", "#7C3AED"]

    for i, res in enumerate(all_results):
        fpr, tpr, _ = roc_curve(res["y_true"], res["y_proba"])
        ax.plot(
            fpr,
            tpr,
            color=colors[i % len(colors)],
            label=f"{res['model']} (AUC={res['metrics']['roc_auc']:.3f})",
            linewidth=2,
        )

    ax.plot([0, 1], [0, 1], "k--", linewidth=1, label="Random Classifier")
    ax.set_xlabel("False Positive Rate", fontsize=12)
    ax.set_ylabel("True Positive Rate", fontsize=12)
    ax.set_title("ROC Curves — All Models", fontsize=14, fontweight="bold")
    ax.legend(fontsize=11)
    ax.grid(alpha=0.3)
    plt.tight_layout()
    path = os.path.join(output_dir, "roc_curves.png")
    plt.savefig(path, dpi=150)
    plt.close()
    log.info(f"ROC curves saved → {path}")
    return path


def evaluate_all():
    X_test, y_test = load_test_data()
    os.makedirs(MODELS_DIR, exist_ok=True)
    all_results = []
    all_metrics = []

    xgb = joblib.load(os.path.join(MODELS_DIR, "xgboost_model.pkl"))
    y_pred_xgb = xgb.predict(X_test)
    y_proba_xgb = xgb.predict_proba(X_test)[:, 1]
    metrics_xgb = compute_metrics("XGBoost", y_test, y_pred_xgb, y_proba_xgb)
    plot_confusion_matrix("XGBoost", y_test, y_pred_xgb, MODELS_DIR)
    all_results.append({"model": "XGBoost", "y_true": y_test, "y_proba": y_proba_xgb, "metrics": metrics_xgb})
    all_metrics.append(metrics_xgb)

    rf = joblib.load(os.path.join(MODELS_DIR, "rf_model.pkl"))
    y_pred_rf = rf.predict(X_test)
    y_proba_rf = rf.predict_proba(X_test)[:, 1]
    metrics_rf = compute_metrics("Random Forest", y_test, y_pred_rf, y_proba_rf)
    plot_confusion_matrix("Random Forest", y_test, y_pred_rf, MODELS_DIR)
    all_results.append({"model": "Random Forest", "y_true": y_test, "y_proba": y_proba_rf, "metrics": metrics_rf})
    all_metrics.append(metrics_rf)

    try:
        import tensorflow as tf

        dnn = tf.keras.models.load_model(os.path.join(MODELS_DIR, "dnn_model.keras"))
        y_proba_dnn = dnn.predict(X_test, verbose=0).flatten()
        y_pred_dnn = (y_proba_dnn >= 0.5).astype(int)
        metrics_dnn = compute_metrics("DNN", y_test, y_pred_dnn, y_proba_dnn)
        plot_confusion_matrix("DNN", y_test, y_pred_dnn, MODELS_DIR)
        all_results.append({"model": "DNN", "y_true": y_test, "y_proba": y_proba_dnn, "metrics": metrics_dnn})
        all_metrics.append(metrics_dnn)
    except Exception as e:
        log.warning(f"DNN evaluation skipped: {e}")

    hybrid_path = os.path.join(MODELS_DIR, "hybrid_model.pkl")
    if os.path.exists(hybrid_path):
        hybrid = joblib.load(hybrid_path)
        y_proba_hybrid = hybrid.predict_proba(X_test)[:, 1]
        y_pred_hybrid = (y_proba_hybrid >= 0.5).astype(int)
        metrics_hybrid = compute_metrics("Hybrid Ensemble", y_test, y_pred_hybrid, y_proba_hybrid)
        plot_confusion_matrix("Hybrid Ensemble", y_test, y_pred_hybrid, MODELS_DIR)
        all_results.append(
            {"model": "Hybrid Ensemble", "y_true": y_test, "y_proba": y_proba_hybrid, "metrics": metrics_hybrid}
        )
        all_metrics.append(metrics_hybrid)

    plot_roc_curves(all_results, MODELS_DIR)

    metrics_path = os.path.join(MODELS_DIR, "metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(all_metrics, f, indent=2)
    log.info(f"All metrics saved → {metrics_path}")

    return all_metrics


if __name__ == "__main__":
    evaluate_all()
