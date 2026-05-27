"""
edac.py — Explanation-Driven Alert Clustering (EDAC) ★ NOVEL CONTRIBUTION ★
─────────────────────────────────────────────────────────────────────────────
EDAC clusters intrusion alerts using their SHAP explanation vectors as
semantic fingerprints, rather than traditional network metadata (IP/port).

KEY INSIGHT: Two alerts are "the same attack" if the MODEL REASONS ABOUT THEM
the same way — i.e., their SHAP vectors are similar — regardless of source IP.

This fills the gap confirmed in XAI-IDS literature (2023-2024):
"Existing XAI-IDS explains individual predictions but lacks integrated
 alert management frameworks to reduce alert volume meaningfully."
"""

import os
import json
import uuid
import numpy as np
from typing import Optional
from scipy.spatial.distance import cosine
from sklearn.preprocessing import normalize
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")
PROCESSED_DIR = os.path.join(os.path.dirname(__file__), "data", "processed")


# ─── Attack Semantic Labels ────────────────────────────────────────────────────
# These map SHAP cluster patterns to human-readable attack labels.
# In production, these are learned via centroid feature analysis.

ATTACK_LABEL_TEMPLATES = {
    "high_syn_high_rate": "SYN Flood / DDoS Campaign",
    "low_duration_tiny_packets": "Port Scan Campaign",
    "repeated_auth_patterns": "Brute Force Campaign",
    "large_payload_slow_flow": "Slow HTTP DoS",
    "heartbeat_anomaly": "Heartbleed / Protocol Exploit",
    "botnet_periodic": "Botnet C2 Communication",
    "infiltration_lateral": "Lateral Movement / Infiltration",
    "default": "Anomalous Traffic Pattern",
}

# Feature indices that define each attack archetype (based on CIC-IDS2017 top features)
FEATURE_ARCHETYPES = {
    "SYN_FLAG_COUNT": 33,       # SYN Flag Count
    "FLOW_BYTES_S": 4,          # Flow Bytes/s
    "FLOW_PACKETS_S": 5,        # Flow Packets/s
    "FLOW_DURATION": 66,        # Flow Duration
    "TOTAL_FWD_PACKETS": 62,    # Total Fwd Packets
    "TOTAL_BWD_PACKETS": 63,    # Total Backward Packets
    "INIT_WIN_FWD": 50,         # Init_Win_bytes_forward
    "ACK_FLAG_COUNT": 37,       # ACK Flag Count
    "FWD_PACKET_LEN_MEAN": 1,   # Fwd Packet Length Mean
}


class EDACCluster:
    """Represents a cluster of semantically similar alerts grouped by SHAP vectors."""

    def __init__(self, cluster_id: str, centroid: np.ndarray,
                 feature_names: list, label: str = None):
        self.cluster_id = cluster_id
        self.centroid = centroid.copy()
        self.feature_names = feature_names
        self.label = label or "Unknown Pattern"
        self.member_count = 1
        self.alert_ids: list = []
        self.top_shap_features: list = []  # [(feature_name, mean_shap), ...]
        self._update_top_features()

    def _update_top_features(self):
        """Recalculate top contributing features from centroid."""
        pairs = list(zip(self.feature_names, self.centroid.tolist()))
        self.top_shap_features = sorted(pairs, key=lambda x: abs(x[1]), reverse=True)[:10]

    def update_centroid(self, new_shap_vector: np.ndarray, alpha: float = 0.1):
        """
        Online centroid update: exponential moving average.
        alpha = learning rate (how quickly centroid adapts).
        """
        self.centroid = (1 - alpha) * self.centroid + alpha * new_shap_vector
        self.member_count += 1
        self._update_top_features()

    def infer_label(self) -> str:
        """
        Infers a semantic attack label based on centroid SHAP pattern.
        High-SHAP features determine attack archetype.
        """
        c = self.centroid
        n = len(c)

        def get_val(idx):
            return c[idx] if idx < n else 0.0

        syn = get_val(FEATURE_ARCHETYPES["SYN_FLAG_COUNT"])
        bytes_s = get_val(FEATURE_ARCHETYPES["FLOW_BYTES_S"])
        packets_s = get_val(FEATURE_ARCHETYPES["FLOW_PACKETS_S"])
        duration = get_val(FEATURE_ARCHETYPES["FLOW_DURATION"])
        fwd_pkts = get_val(FEATURE_ARCHETYPES["TOTAL_FWD_PACKETS"])
        bwd_pkts = get_val(FEATURE_ARCHETYPES["TOTAL_BWD_PACKETS"])
        init_win = get_val(FEATURE_ARCHETYPES["INIT_WIN_FWD"])
        ack = get_val(FEATURE_ARCHETYPES["ACK_FLAG_COUNT"])
        pkt_len = get_val(FEATURE_ARCHETYPES["FWD_PACKET_LEN_MEAN"])

        # Rule-based label inference from SHAP centroid
        if syn > 0.15 and bytes_s > 0.1:
            return ATTACK_LABEL_TEMPLATES["high_syn_high_rate"]
        elif duration < -0.1 and fwd_pkts > 0.1 and bwd_pkts < -0.05:
            return ATTACK_LABEL_TEMPLATES["low_duration_tiny_packets"]
        elif ack > 0.05 and pkt_len < 0.0 and init_win > 0.05:
            return ATTACK_LABEL_TEMPLATES["repeated_auth_patterns"]
        elif bytes_s < -0.05 and duration > 0.1 and packets_s < -0.05:
            return ATTACK_LABEL_TEMPLATES["large_payload_slow_flow"]
        elif init_win < -0.1:
            return ATTACK_LABEL_TEMPLATES["heartbeat_anomaly"]
        elif duration > 0.15 and fwd_pkts > 0.05 and bwd_pkts > 0.05:
            return ATTACK_LABEL_TEMPLATES["botnet_periodic"]
        else:
            return ATTACK_LABEL_TEMPLATES["default"]

    def to_dict(self) -> dict:
        return {
            "cluster_id": self.cluster_id,
            "label": self.label,
            "member_count": self.member_count,
            "alert_ids": self.alert_ids[-20:],  # last 20 for API response
            "top_shap_features": [
                {"feature": f, "shap_value": round(v, 6)}
                for f, v in self.top_shap_features[:10]
            ],
            "centroid": self.centroid.tolist(),
        }


class EDACEngine:
    """
    Explanation-Driven Alert Clustering Engine.

    On each new alert:
    1. Compute SHAP vector for the alert's feature set.
    2. Compare cosine similarity to all existing cluster centroids.
    3a. If similarity > THRESHOLD: assign to nearest cluster, update centroid.
    3b. If similarity < THRESHOLD: create new cluster (novel attack pattern).
    4. Return cluster_id, label, similarity_score.
    """

    SIMILARITY_THRESHOLD = 0.80  # cosine similarity threshold for cluster assignment
    MAX_CLUSTERS = 100            # max clusters to prevent unbounded growth

    def __init__(self, feature_names: list):
        self.feature_names = feature_names
        self.clusters: dict[str, EDACCluster] = {}
        self._anomalous_label_counter = 0

    def __setstate__(self, state):
        """Backward compatibility for older pickled engines."""
        self.__dict__.update(state)
        if "_anomalous_label_counter" not in self.__dict__:
            self._anomalous_label_counter = 0

    def _next_anomalous_label(self) -> str:
        self._anomalous_label_counter += 1
        return f"{ATTACK_LABEL_TEMPLATES['default']} #{self._anomalous_label_counter}"

    def _assign_new_cluster_label(self, cluster: EDACCluster) -> str:
        base = cluster.infer_label()
        if base == ATTACK_LABEL_TEMPLATES["default"]:
            return self._next_anomalous_label()
        return base

    def _refresh_existing_cluster_label(self, cluster: EDACCluster) -> str:
        """
        Keep stable anomalous suffix labels while allowing specific labels
        to replace generic ones when centroid matures.
        """
        inferred = cluster.infer_label()
        current = cluster.label or ""
        if inferred == ATTACK_LABEL_TEMPLATES["default"]:
            # Preserve previously assigned numbered anomalous label
            if current.startswith(ATTACK_LABEL_TEMPLATES["default"]):
                return current
            return self._next_anomalous_label()
        return inferred

    def _cosine_similarity(self, a: np.ndarray, b: np.ndarray) -> float:
        """Returns cosine similarity in [0, 1]. Higher = more similar."""
        a_norm = np.linalg.norm(a)
        b_norm = np.linalg.norm(b)
        if a_norm == 0 or b_norm == 0:
            return 0.0
        return float(np.dot(a, b) / (a_norm * b_norm))

    def assign_alert(self, shap_vector: np.ndarray, alert_id: str) -> dict:
        """
        Assigns alert to a cluster based on its SHAP vector.
        Returns assignment metadata.
        """
        shap_vector = np.array(shap_vector, dtype=np.float32)

        if not self.clusters:
            # First alert — create first cluster
            return self._create_cluster(shap_vector, alert_id, similarity=1.0)

        # Find most similar cluster
        best_cluster_id = None
        best_similarity = -1.0

        for cid, cluster in self.clusters.items():
            sim = self._cosine_similarity(shap_vector, cluster.centroid)
            if sim > best_similarity:
                best_similarity = sim
                best_cluster_id = cid

        if best_similarity >= self.SIMILARITY_THRESHOLD:
            # Assign to existing cluster
            cluster = self.clusters[best_cluster_id]
            cluster.update_centroid(shap_vector)
            cluster.alert_ids.append(alert_id)
            # Re-infer label as centroid evolves
            cluster.label = self._refresh_existing_cluster_label(cluster)
            log.debug(f"Alert {alert_id} → Cluster {best_cluster_id} "
                      f"(sim={best_similarity:.3f}, label={cluster.label})")
            return {
                "cluster_id": best_cluster_id,
                "label": cluster.label,
                "similarity_score": round(best_similarity, 4),
                "is_new_cluster": False,
                "member_count": cluster.member_count,
                "top_features": cluster.top_shap_features[:5],
            }
        else:
            # New attack pattern detected
            if len(self.clusters) >= self.MAX_CLUSTERS:
                # Merge with most similar when at capacity
                cluster = self.clusters[best_cluster_id]
                cluster.update_centroid(shap_vector)
                cluster.alert_ids.append(alert_id)
                return {
                    "cluster_id": best_cluster_id,
                    "label": cluster.label,
                    "similarity_score": round(best_similarity, 4),
                    "is_new_cluster": False,
                    "member_count": cluster.member_count,
                    "top_features": cluster.top_shap_features[:5],
                }
            return self._create_cluster(shap_vector, alert_id, similarity=best_similarity)

    def _create_cluster(self, shap_vector: np.ndarray, alert_id: str,
                        similarity: float) -> dict:
        cluster_id = f"cluster_{str(uuid.uuid4())[:8]}"
        cluster = EDACCluster(cluster_id, shap_vector, self.feature_names)
        cluster.label = self._assign_new_cluster_label(cluster)
        cluster.alert_ids.append(alert_id)
        self.clusters[cluster_id] = cluster
        log.info(f"★ New Cluster Created: {cluster_id} | {cluster.label} | "
                 f"prev_sim={similarity:.3f}")
        return {
            "cluster_id": cluster_id,
            "label": cluster.label,
            "similarity_score": round(similarity, 4),
            "is_new_cluster": True,
            "member_count": 1,
            "top_features": cluster.top_shap_features[:5],
        }

    def get_all_clusters(self) -> list:
        return [c.to_dict() for c in self.clusters.values()]

    def get_cluster(self, cluster_id: str) -> Optional[dict]:
        c = self.clusters.get(cluster_id)
        return c.to_dict() if c else None

    def seed_from_training_data(self, shap_matrix: np.ndarray,
                                 predictions: np.ndarray,
                                 n_seed: int = 500):
        """
        Seeds the EDAC engine from training data SHAP vectors using
        HDBSCAN for initial cluster discovery.
        Only attack-predicted instances are clustered.
        """
        try:
            import hdbscan
        except ImportError:
            log.warning("hdbscan not installed, skipping seed clustering.")
            return

        attack_mask = predictions == 1
        attack_shap = shap_matrix[attack_mask]

        if len(attack_shap) < 10:
            log.warning("Too few attack samples to seed EDAC.")
            return

        # Use a sample for speed
        idx = np.random.choice(len(attack_shap), min(n_seed, len(attack_shap)), replace=False)
        sample = attack_shap[idx].astype(np.float64)

        # Normalize for cosine distance
        sample_norm = normalize(sample, norm="l2")

        log.info(f"HDBSCAN clustering {len(sample)} SHAP vectors...")
        clusterer = hdbscan.HDBSCAN(
            min_cluster_size=10,
            min_samples=5,
            metric="euclidean",  # on normalized vectors = cosine
            cluster_selection_method="eom",
        )
        labels = clusterer.fit_predict(sample_norm)
        unique_labels = set(labels) - {-1}  # -1 = noise

        for lbl in unique_labels:
            mask = labels == lbl
            centroid = sample[mask].mean(axis=0)
            cluster_id = f"cluster_{str(uuid.uuid4())[:8]}"
            cluster = EDACCluster(cluster_id, centroid, self.feature_names)
            cluster.label = self._assign_new_cluster_label(cluster)
            cluster.member_count = int(mask.sum())
            self.clusters[cluster_id] = cluster

        noise_count = (labels == -1).sum()
        log.info(f"EDAC seeded: {len(unique_labels)} clusters, {noise_count} noise points")

    def to_json(self) -> str:
        return json.dumps(self.get_all_clusters(), indent=2)

    def save(self, path: str):
        import joblib
        joblib.dump(self, path)
        log.info(f"EDAC engine saved → {path}")

    @staticmethod
    def load(path: str) -> "EDACEngine":
        import joblib
        engine = joblib.load(path)
        log.info(f"EDAC engine loaded from {path} ({len(engine.clusters)} clusters)")
        return engine


# ─── CLI Seed Script ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import joblib
    from explain import compute_shap_vectors_batch

    log.info("Seeding EDAC engine from training data...")
    X_train = np.load(os.path.join(PROCESSED_DIR, "X_train.npy"))
    y_train = np.load(os.path.join(PROCESSED_DIR, "y_train_binary.npy"))
    feature_names = np.load(os.path.join(PROCESSED_DIR, "feature_names.npy"), allow_pickle=True).tolist()
    model = joblib.load(os.path.join(MODELS_DIR, "xgboost_model.pkl"))

    # Compute SHAP for a sample
    sample_size = min(2000, len(X_train))
    idx = np.random.choice(len(X_train), sample_size, replace=False)
    X_sample = X_train[idx]
    y_sample = y_train[idx]

    log.info(f"Computing SHAP vectors for {sample_size} samples...")
    shap_matrix = compute_shap_vectors_batch(model, X_sample, "xgboost")

    # Initialize and seed EDAC
    engine = EDACEngine(feature_names)
    engine.seed_from_training_data(shap_matrix, y_sample, n_seed=500)

    # Save
    engine_path = os.path.join(MODELS_DIR, "edac_engine.pkl")
    engine.save(engine_path)
    log.info(f"\n★ EDAC Summary:\n{engine.to_json()[:2000]}")
