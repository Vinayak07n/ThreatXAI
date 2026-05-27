"""
hybrid_model.py — ThreatXAI Hybrid ensemble of XGBoost + RF + DNN.
"""

import numpy as np


class ThreatXAIHybridEnsemble:
    """
    Weighted adaptive ensemble with consensus-aware adjustment.

    Base formula:
      p_base = sum_i (w_i * p_i)

    Confidence-adaptive weighting:
      c_i = 1 - H(p_i)/log(2), where H is binary entropy
      w_i' = normalize(w_i * (0.5 + 0.5*c_i))

    Consensus amplification:
      momentum = max(p_i) - min(p_i)
      p_final = clip(p_base + gamma * momentum * (mean(p_i) - 0.5), 0, 1)
    """

    def __init__(self, xgb_model, rf_model, dnn_model, base_weights=None, gamma=0.15):
        self.xgb_model = xgb_model
        self.rf_model = rf_model
        self.dnn_model = dnn_model
        self.base_weights = np.array(base_weights or [0.4, 0.35, 0.25], dtype=np.float64)
        self.gamma = float(gamma)

    @staticmethod
    def _entropy_confidence(p):
        p = np.clip(p, 1e-8, 1 - 1e-8)
        h = -(p * np.log(p) + (1 - p) * np.log(1 - p))
        return 1.0 - (h / np.log(2.0))

    def _base_model_probabilities(self, X):
        p_xgb = self.xgb_model.predict_proba(X)[:, 1]
        p_rf = self.rf_model.predict_proba(X)[:, 1]
        p_dnn = self.dnn_model.predict(X, verbose=0).reshape(-1)
        return np.column_stack([p_xgb, p_rf, p_dnn])

    def predict_proba(self, X):
        probs = self._base_model_probabilities(X)
        conf = self._entropy_confidence(probs)

        # Per-sample adaptive weights based on confidence from each constituent model
        w = self.base_weights.reshape(1, -1) * (0.5 + 0.5 * conf)
        w = w / np.maximum(w.sum(axis=1, keepdims=True), 1e-12)

        p_base = (w * probs).sum(axis=1)
        momentum = probs.max(axis=1) - probs.min(axis=1)
        direction = probs.mean(axis=1) - 0.5
        p_final = np.clip(p_base + self.gamma * momentum * direction, 0.0, 1.0)

        return np.column_stack([1.0 - p_final, p_final])

    def predict(self, X):
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)

    def get_metadata(self):
        return {
            "name": "ThreatXAI Hybrid Ensemble",
            "base_weights": self.base_weights.tolist(),
            "gamma": self.gamma,
            "formula": "adaptive weighted probability + consensus amplification",
        }
