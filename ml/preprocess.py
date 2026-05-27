"""
preprocess.py — ThreatXAI preprocessing pipeline
Builds/loads dataset, cleans, normalizes, and persists train/test splits.
"""

import os
import sys
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib
import logging

from synthetic_dataset import generate_synthetic_threatxai_dataset

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
RAW_DIR = os.path.join(DATA_DIR, "raw")
PROCESSED_DIR = os.path.join(DATA_DIR, "processed")
MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")

DROP_COLS = [
    "Flow ID", "Source IP", "Source Port", "Destination IP",
    "Destination Port", "Protocol", "Timestamp"
]
LABEL_COL = "Label"


def prepare_dataset(csv_path: str = None):
    """
    Returns path to training CSV.
    Default behavior generates ThreatXAI's in-house synthetic dataset for novelty.
    """
    os.makedirs(RAW_DIR, exist_ok=True)

    if csv_path:
        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"Provided dataset path not found: {csv_path}")
        return csv_path

    synth_path = os.path.join(RAW_DIR, "threatxai_synthshield_v1.csv")
    synth_meta = os.path.join(RAW_DIR, "threatxai_synthshield_v1.meta.json")

    if os.path.exists(synth_path):
        log.info(f"Using existing synthetic dataset at {synth_path}")
        return synth_path

    log.info("Generating ThreatXAI in-house synthetic benign/attack dataset...")
    metadata = generate_synthetic_threatxai_dataset(
        output_csv_path=synth_path,
        output_meta_path=synth_meta,
        n_samples=90000,
        benign_ratio=0.58,
        seed=42,
    )
    log.info(
        "Synthetic dataset generated: rows=%s benign=%s attack=%s features=%s",
        metadata["rows"],
        metadata["benign_rows"],
        metadata["attack_rows"],
        metadata["feature_count"],
    )
    return synth_path


def load_and_clean(csv_path: str) -> pd.DataFrame:
    log.info(f"Loading {csv_path}...")
    df = pd.read_csv(csv_path, low_memory=False)

    df.columns = df.columns.str.strip()

    drop = [c for c in DROP_COLS if c in df.columns]
    df = df.drop(columns=drop)

    df = df.replace([np.inf, -np.inf], np.nan)
    before = len(df)
    df = df.dropna()
    log.info(f"Dropped {before - len(df)} rows with NaN/Inf")

    before = len(df)
    df = df.drop_duplicates()
    log.info(f"Dropped {before - len(df)} duplicate rows")

    if LABEL_COL not in df.columns:
        raise ValueError(f"Label column '{LABEL_COL}' not found. Columns: {df.columns.tolist()}")

    return df


def encode_labels(df: pd.DataFrame):
    """Returns binary labels + multiclass labels + attack type names."""
    df = df.copy()
    df["Label"] = df["Label"].astype(str).str.strip()

    le = LabelEncoder()
    df["label_multiclass"] = le.fit_transform(df["Label"])

    df["label_binary"] = (df["Label"].str.upper() != "BENIGN").astype(int)

    attack_names = list(le.classes_)
    log.info(f"Classes: {attack_names}")
    log.info(f"Binary label distribution:\n{df['label_binary'].value_counts()}")

    return df, le, attack_names


def preprocess(csv_path: str = None):
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    os.makedirs(MODELS_DIR, exist_ok=True)

    source_csv = prepare_dataset(csv_path)
    df = load_and_clean(source_csv)
    df, le, attack_names = encode_labels(df)

    feature_cols = [c for c in df.columns if c not in ["Label", "label_binary", "label_multiclass"]]
    X = df[feature_cols].values.astype(np.float32)
    y_binary = df["label_binary"].values
    y_multi = df["label_multiclass"].values

    X_train, X_test, y_train_b, y_test_b, y_train_m, y_test_m = train_test_split(
        X, y_binary, y_multi, test_size=0.2, random_state=42, stratify=y_binary
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    np.save(os.path.join(PROCESSED_DIR, "X_train.npy"), X_train_scaled)
    np.save(os.path.join(PROCESSED_DIR, "X_test.npy"), X_test_scaled)
    np.save(os.path.join(PROCESSED_DIR, "y_train_binary.npy"), y_train_b)
    np.save(os.path.join(PROCESSED_DIR, "y_test_binary.npy"), y_test_b)
    np.save(os.path.join(PROCESSED_DIR, "y_train_multi.npy"), y_train_m)
    np.save(os.path.join(PROCESSED_DIR, "y_test_multi.npy"), y_test_m)
    np.save(os.path.join(PROCESSED_DIR, "feature_names.npy"), np.array(feature_cols))

    joblib.dump(scaler, os.path.join(MODELS_DIR, "scaler.pkl"))
    joblib.dump(le, os.path.join(MODELS_DIR, "label_encoder.pkl"))

    import json
    with open(os.path.join(MODELS_DIR, "attack_names.json"), "w") as f:
        json.dump(attack_names, f, indent=2)

    log.info(f"Preprocessing complete. Train: {len(X_train_scaled)}, Test: {len(X_test_scaled)}")
    log.info(f"Feature count: {X_train_scaled.shape[1]}")
    return X_train_scaled, X_test_scaled, y_train_b, y_test_b, feature_cols


if __name__ == "__main__":
    csv_arg = sys.argv[1] if len(sys.argv) > 1 else None
    preprocess(csv_arg)
