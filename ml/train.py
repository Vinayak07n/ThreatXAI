"""
train.py — Model Training Pipeline
Trains XGBoost, Random Forest, DNN, and ThreatXAI Hybrid Ensemble.
"""

import os
import json
import numpy as np
import joblib
import logging
from sklearn.metrics import f1_score

from hybrid_model import ThreatXAIHybridEnsemble

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

PROCESSED_DIR = os.path.join(os.path.dirname(__file__), "data", "processed")
MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")


def load_data():
    X_train = np.load(os.path.join(PROCESSED_DIR, "X_train.npy"))
    X_test = np.load(os.path.join(PROCESSED_DIR, "X_test.npy"))
    y_train = np.load(os.path.join(PROCESSED_DIR, "y_train_binary.npy"))
    y_test = np.load(os.path.join(PROCESSED_DIR, "y_test_binary.npy"))
    return X_train, X_test, y_train, y_test


def train_xgboost(X_train, y_train):
    from xgboost import XGBClassifier

    log.info("Training XGBoost...")
    model = XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
        tree_method="hist",
    )
    model.fit(X_train, y_train, eval_set=[(X_train, y_train)], verbose=50)
    path = os.path.join(MODELS_DIR, "xgboost_model.pkl")
    joblib.dump(model, path)
    log.info(f"XGBoost saved → {path}")
    return model


def train_random_forest(X_train, y_train):
    from sklearn.ensemble import RandomForestClassifier

    log.info("Training Random Forest...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=5,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    path = os.path.join(MODELS_DIR, "rf_model.pkl")
    joblib.dump(model, path)
    log.info(f"Random Forest saved → {path}")
    return model


def train_dnn(X_train, y_train, X_test, y_test):
    import tensorflow as tf
    from tensorflow import keras

    log.info("Training DNN...")

    tf.random.set_seed(42)
    n_features = X_train.shape[1]

    model = keras.Sequential(
        [
            keras.layers.Input(shape=(n_features,)),
            keras.layers.Dense(256, activation="relu"),
            keras.layers.BatchNormalization(),
            keras.layers.Dropout(0.3),
            keras.layers.Dense(128, activation="relu"),
            keras.layers.BatchNormalization(),
            keras.layers.Dropout(0.3),
            keras.layers.Dense(64, activation="relu"),
            keras.layers.Dropout(0.2),
            keras.layers.Dense(32, activation="relu"),
            keras.layers.Dense(1, activation="sigmoid"),
        ]
    )

    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=1e-3),
        loss="binary_crossentropy",
        metrics=["accuracy", keras.metrics.AUC(name="auc")],
    )

    callbacks = [
        keras.callbacks.EarlyStopping(monitor="val_auc", patience=10, restore_best_weights=True, mode="max"),
        keras.callbacks.ReduceLROnPlateau(monitor="val_loss", factor=0.5, patience=5),
    ]

    model.fit(
        X_train,
        y_train,
        validation_data=(X_test, y_test),
        epochs=50,
        batch_size=512,
        callbacks=callbacks,
        verbose=1,
    )

    path = os.path.join(MODELS_DIR, "dnn_model.keras")
    model.save(path)
    log.info(f"DNN saved → {path}")
    return model


def train_hybrid(xgb, rf, dnn, X_val, y_val):
    log.info("Training ThreatXAI Hybrid Ensemble...")

    p_xgb = xgb.predict_proba(X_val)[:, 1]
    p_rf = rf.predict_proba(X_val)[:, 1]
    p_dnn = dnn.predict(X_val, verbose=0).reshape(-1)

    f1s = np.array(
        [
            f1_score(y_val, (p_xgb >= 0.5).astype(int), zero_division=0),
            f1_score(y_val, (p_rf >= 0.5).astype(int), zero_division=0),
            f1_score(y_val, (p_dnn >= 0.5).astype(int), zero_division=0),
        ],
        dtype=np.float64,
    )
    temperature = max(float(np.std(f1s)), 1e-6)
    weights = np.exp(f1s / temperature)
    weights = (weights / weights.sum()).tolist()

    hybrid = ThreatXAIHybridEnsemble(
        xgb_model=xgb,
        rf_model=rf,
        dnn_model=dnn,
        base_weights=weights,
        gamma=0.15,
    )

    path = os.path.join(MODELS_DIR, "hybrid_model.pkl")
    joblib.dump(hybrid, path)
    log.info(f"Hybrid saved → {path}")

    meta_path = os.path.join(MODELS_DIR, "hybrid_meta.json")
    with open(meta_path, "w") as f:
        json.dump(hybrid.get_metadata(), f, indent=2)
    log.info(f"Hybrid metadata saved → {meta_path}")

    return hybrid


def train_all():
    os.makedirs(MODELS_DIR, exist_ok=True)
    X_train, X_test, y_train, y_test = load_data()

    xgb = train_xgboost(X_train, y_train)
    rf = train_random_forest(X_train, y_train)
    dnn = train_dnn(X_train, y_train, X_test, y_test)
    hybrid = train_hybrid(xgb, rf, dnn, X_test, y_test)

    log.info("All models trained successfully.")
    return xgb, rf, dnn, hybrid


if __name__ == "__main__":
    train_all()
