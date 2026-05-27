"""
synthetic_dataset.py — ThreatXAI in-house synthetic dataset generator

Builds a high-contrast benign + multi-attack dataset with explicit
feature-generation formulas for novelty and reproducibility.
"""

import os
import json
import numpy as np
import pandas as pd


FEATURE_COLUMNS = [
    "Fwd Packet Length Max",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Max",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Std",
    "Bwd Packet Length Std",
    "Flow Duration",
]


def _rng(seed: int):
    return np.random.default_rng(seed)


def _base_benign(n: int, seed: int):
    """
    Generate base benign traffic features with realistic distributions.
    Uses lognormal, uniform, binomial, and choice distributions for realism.
    """
    rng = _rng(seed)
    d = {}
    d["Fwd Packet Length Max"] = rng.lognormal(5.4, 1.1, n)
    d["Fwd Packet Length Mean"] = rng.lognormal(4.1, 0.9, n)
    d["Bwd Packet Length Max"] = rng.lognormal(5.7, 1.2, n)
    d["Bwd Packet Length Mean"] = rng.lognormal(4.4, 1.0, n)
    d["Flow Bytes/s"] = rng.lognormal(6.4, 1.4, n)
    d["Flow Packets/s"] = rng.lognormal(2.5, 1.0, n)
    d["Flow IAT Mean"] = rng.lognormal(8.0, 1.3, n)
    d["Flow IAT Std"] = rng.lognormal(7.4, 1.2, n)
    d["Flow IAT Max"] = rng.lognormal(9.1, 1.6, n)
    d["Flow IAT Min"] = rng.lognormal(3.8, 1.0, n)
    d["Fwd IAT Total"] = rng.lognormal(9.3, 1.5, n)
    d["Fwd IAT Mean"] = rng.lognormal(7.8, 1.2, n)
    d["Fwd IAT Std"] = rng.lognormal(7.1, 1.2, n)
    d["Fwd IAT Max"] = rng.lognormal(8.7, 1.5, n)
    d["Fwd IAT Min"] = rng.uniform(0, 1200, n)
    d["Bwd IAT Total"] = rng.lognormal(9.1, 1.4, n)
    d["Bwd IAT Mean"] = rng.lognormal(7.7, 1.2, n)
    d["Bwd IAT Std"] = rng.lognormal(7.0, 1.2, n)
    d["Bwd IAT Max"] = rng.lognormal(8.8, 1.5, n)
    d["Bwd IAT Min"] = rng.uniform(0, 1200, n)
    d["Fwd PSH Flags"] = rng.binomial(1, 0.25, n)
    d["Bwd PSH Flags"] = rng.binomial(1, 0.22, n)
    d["Fwd URG Flags"] = np.zeros(n)
    d["Bwd URG Flags"] = np.zeros(n)
    d["Fwd Header Length"] = rng.choice([20, 32, 40], n)
    d["Bwd Header Length"] = rng.choice([20, 32, 40], n)
    d["Fwd Packets/s"] = rng.lognormal(2.4, 1.0, n)
    d["Bwd Packets/s"] = rng.lognormal(2.2, 1.0, n)
    d["Min Packet Length"] = rng.integers(20, 90, n).astype(np.float64)
    d["Max Packet Length"] = rng.lognormal(6.8, 1.0, n)
    d["Packet Length Mean"] = rng.lognormal(5.0, 1.0, n)
    d["Packet Length Std"] = rng.lognormal(3.9, 0.9, n)
    d["Packet Length Variance"] = d["Packet Length Std"] ** 2
    d["FIN Flag Count"] = rng.binomial(2, 0.4, n)
    d["SYN Flag Count"] = rng.choice([0, 1, 2], n, p=[0.25, 0.6, 0.15]).astype(np.float64)
    d["RST Flag Count"] = rng.binomial(1, 0.1, n)
    d["PSH Flag Count"] = rng.integers(0, 5, n).astype(np.float64)
    d["ACK Flag Count"] = rng.integers(2, 20, n).astype(np.float64)
    d["URG Flag Count"] = np.zeros(n)
    d["CWE Flag Count"] = np.zeros(n)
    d["ECE Flag Count"] = np.zeros(n)
    d["Down/Up Ratio"] = rng.uniform(0.6, 3.5, n)
    d["Average Packet Size"] = rng.lognormal(4.9, 1.0, n)
    d["Avg Fwd Segment Size"] = rng.lognormal(4.5, 1.0, n)
    d["Avg Bwd Segment Size"] = rng.lognormal(4.8, 1.0, n)
    d["Subflow Fwd Packets"] = rng.integers(2, 25, n).astype(np.float64)
    d["Subflow Fwd Bytes"] = rng.lognormal(6.1, 1.2, n)
    d["Subflow Bwd Packets"] = rng.integers(2, 22, n).astype(np.float64)
    d["Subflow Bwd Bytes"] = rng.lognormal(5.9, 1.2, n)
    d["Init_Win_bytes_forward"] = rng.choice([8192, 29200, 65535], n).astype(np.float64)
    d["Init_Win_bytes_backward"] = rng.choice([8192, 29200, 65535], n).astype(np.float64)
    d["act_data_pkt_fwd"] = rng.integers(1, 24, n).astype(np.float64)
    d["min_seg_size_forward"] = rng.choice([20, 32], n).astype(np.float64)
    d["Active Mean"] = rng.lognormal(6.7, 1.2, n)
    d["Active Std"] = rng.lognormal(5.4, 1.1, n)
    d["Active Max"] = rng.lognormal(7.4, 1.2, n)
    d["Active Min"] = rng.lognormal(5.2, 1.1, n)
    d["Idle Mean"] = rng.lognormal(8.7, 1.3, n)
    d["Idle Std"] = rng.lognormal(6.8, 1.2, n)
    d["Idle Max"] = rng.lognormal(9.3, 1.4, n)
    d["Idle Min"] = rng.lognormal(6.9, 1.2, n)
    d["Total Fwd Packets"] = rng.integers(3, 80, n).astype(np.float64)
    d["Total Backward Packets"] = rng.integers(2, 70, n).astype(np.float64)
    d["Total Length of Fwd Packets"] = rng.lognormal(6.1, 1.2, n)
    d["Total Length of Bwd Packets"] = rng.lognormal(5.8, 1.2, n)
    d["Fwd Packet Length Std"] = rng.lognormal(3.8, 0.9, n)
    d["Bwd Packet Length Std"] = rng.lognormal(3.9, 0.9, n)
    d["Flow Duration"] = rng.lognormal(9.3, 1.4, n)
    return d


def _enforce_physical_bounds(df: pd.DataFrame) -> pd.DataFrame:
    for col in df.columns:
        if col == "Label":
            continue
        df[col] = np.nan_to_num(df[col], nan=0.0, posinf=1e9, neginf=0.0)
        df[col] = np.clip(df[col], 0.0, 1e9)
    return df


def _inject_attack_profile(df: pd.DataFrame, attack_name: str, mask: np.ndarray, seed: int):
    rng = _rng(seed)
    n = int(mask.sum())
    if n == 0:
        return

    # Novel formula set: attack intensity uses non-linear coupling
    # intensity = log1p(flow_packets_s) * sigmoid(syn_count / 10)
    # stealth = exp(-ack_count / 30)
    # burst_factor = sqrt(flow_bytes_s / max(flow_duration, 1))
    if attack_name == "DDoS-SYN-AMPLIFIED":
        syn = rng.integers(120, 2000, n)
        fpps = rng.lognormal(9.0, 0.8, n)
        bytes_s = rng.lognormal(14.0, 0.9, n)
        duration = rng.uniform(5e3, 2e6, n)
        intensity = np.log1p(fpps) * (1.0 / (1.0 + np.exp(-syn / 120.0)))
        df.loc[mask, "SYN Flag Count"] = syn
        df.loc[mask, "Flow Packets/s"] = fpps
        df.loc[mask, "Flow Bytes/s"] = bytes_s
        df.loc[mask, "Flow Duration"] = duration
        df.loc[mask, "ACK Flag Count"] = np.maximum(0, rng.normal(0.6, 0.4, n))
        df.loc[mask, "Total Fwd Packets"] = np.clip(150 * intensity + rng.normal(0, 40, n), 200, 7000)
        df.loc[mask, "Total Backward Packets"] = rng.integers(0, 6, n)
        df.loc[mask, "Init_Win_bytes_forward"] = rng.choice([0, 1024], n)
    elif attack_name == "PortScan-Hyper":
        burst = rng.lognormal(7.5, 0.7, n)
        df.loc[mask, "SYN Flag Count"] = rng.integers(1, 4, n)
        df.loc[mask, "RST Flag Count"] = rng.integers(1, 3, n)
        df.loc[mask, "Flow Duration"] = rng.uniform(1, 500, n)
        df.loc[mask, "Flow Packets/s"] = burst
        df.loc[mask, "Fwd Packet Length Mean"] = rng.uniform(38, 70, n)
        df.loc[mask, "Total Fwd Packets"] = rng.integers(1, 4, n)
        df.loc[mask, "Total Backward Packets"] = rng.integers(0, 2, n)
        df.loc[mask, "Flow Bytes/s"] = burst * rng.uniform(18, 50, n)
    elif attack_name == "Credential-Stuffing":
        retries = rng.integers(10, 120, n)
        stealth = np.exp(-rng.uniform(0.2, 1.2, n))
        df.loc[mask, "ACK Flag Count"] = retries * rng.uniform(0.2, 0.8, n)
        df.loc[mask, "SYN Flag Count"] = rng.integers(3, 40, n)
        df.loc[mask, "Flow Duration"] = rng.uniform(5e5, 2e8, n)
        df.loc[mask, "Flow IAT Mean"] = rng.lognormal(6.2, 0.8, n) / np.maximum(stealth, 1e-3)
        df.loc[mask, "Init_Win_bytes_forward"] = rng.choice([8192, 16384, 65535], n)
        df.loc[mask, "Total Fwd Packets"] = np.clip(retries * rng.uniform(0.6, 1.2, n), 8, 300)
        df.loc[mask, "Fwd Packet Length Mean"] = rng.uniform(42, 120, n)
    elif attack_name == "SlowLoris-HTTP":
        duration = rng.lognormal(12.2, 0.6, n)
        low_rate = rng.lognormal(0.9, 0.5, n)
        df.loc[mask, "Flow Duration"] = duration
        df.loc[mask, "Flow Packets/s"] = low_rate
        df.loc[mask, "Flow Bytes/s"] = low_rate * rng.uniform(35, 180, n)
        df.loc[mask, "Packet Length Mean"] = rng.uniform(30, 120, n)
        df.loc[mask, "Idle Mean"] = duration * rng.uniform(0.15, 0.45, n)
        df.loc[mask, "Idle Max"] = duration * rng.uniform(0.2, 0.7, n)
        df.loc[mask, "Total Fwd Packets"] = rng.integers(30, 400, n)
        df.loc[mask, "Total Backward Packets"] = rng.integers(2, 40, n)
    elif attack_name == "Botnet-C2-Beacon":
        period = rng.uniform(20, 120, n)
        beacon_packets = rng.integers(20, 250, n)
        periodicity = 1.0 / np.maximum(period, 1e-3)
        df.loc[mask, "Flow IAT Mean"] = period * 1e3
        df.loc[mask, "Flow IAT Std"] = period * 80.0 * rng.uniform(0.05, 0.25, n)
        df.loc[mask, "Flow Duration"] = beacon_packets * period * 1e5
        df.loc[mask, "Flow Packets/s"] = periodicity * beacon_packets * rng.uniform(0.8, 1.3, n)
        df.loc[mask, "Flow Bytes/s"] = periodicity * beacon_packets * rng.uniform(140, 420, n)
        df.loc[mask, "PSH Flag Count"] = rng.integers(5, 60, n)
        df.loc[mask, "ACK Flag Count"] = beacon_packets * rng.uniform(0.1, 0.9, n)
    elif attack_name == "Data-Exfiltration":
        payload = rng.lognormal(9.4, 0.8, n)
        stealth = rng.uniform(0.2, 0.9, n)
        df.loc[mask, "Flow Duration"] = rng.lognormal(11.2, 0.7, n)
        df.loc[mask, "Flow Bytes/s"] = payload / np.maximum(stealth, 1e-3)
        df.loc[mask, "Average Packet Size"] = rng.lognormal(7.2, 0.7, n)
        df.loc[mask, "Bwd Packet Length Mean"] = rng.lognormal(6.9, 0.8, n)
        df.loc[mask, "Down/Up Ratio"] = rng.uniform(2.8, 12.0, n)
        df.loc[mask, "Total Length of Bwd Packets"] = payload * rng.uniform(1.2, 4.0, n)
        df.loc[mask, "Total Backward Packets"] = rng.integers(40, 400, n)
    elif attack_name == "Infiltration-Lateral":
        fanout = rng.integers(2, 24, n)
        df.loc[mask, "Flow Packets/s"] = rng.lognormal(4.2, 0.7, n) * np.sqrt(fanout)
        df.loc[mask, "Flow Bytes/s"] = rng.lognormal(7.2, 0.9, n) * np.sqrt(fanout)
        df.loc[mask, "Total Fwd Packets"] = rng.integers(25, 260, n) * np.sqrt(fanout)
        df.loc[mask, "Total Backward Packets"] = rng.integers(10, 180, n)
        df.loc[mask, "SYN Flag Count"] = rng.integers(5, 120, n)
        df.loc[mask, "ACK Flag Count"] = rng.integers(2, 80, n)
        df.loc[mask, "Init_Win_bytes_forward"] = rng.choice([0, 1024, 8192], n)


def generate_synthetic_threatxai_dataset(
    output_csv_path: str,
    output_meta_path: str = None,
    n_samples: int = 90000,
    benign_ratio: float = 0.58,
    seed: int = 42,
):
    os.makedirs(os.path.dirname(output_csv_path), exist_ok=True)
    attack_names = [
        "DDoS-SYN-AMPLIFIED",
        "PortScan-Hyper",
        "Credential-Stuffing",
        "SlowLoris-HTTP",
        "Botnet-C2-Beacon",
        "Data-Exfiltration",
        "Infiltration-Lateral",
    ]

    n_benign = int(n_samples * benign_ratio)
    n_attack = n_samples - n_benign
    benign = pd.DataFrame(_base_benign(n_benign, seed))
    benign["Label"] = "BENIGN"

    attack = pd.DataFrame(_base_benign(n_attack, seed + 101))
    rng = _rng(seed + 7)
    labels = rng.choice(attack_names, n_attack, p=[0.22, 0.16, 0.17, 0.12, 0.13, 0.11, 0.09])
    attack["Label"] = labels

    for idx, name in enumerate(attack_names):
        _inject_attack_profile(attack, name, labels == name, seed + 1000 + idx)

    # Cross-feature consistency formulas
    for frame in (benign, attack):
        frame["Packet Length Mean"] = (frame["Fwd Packet Length Mean"] + frame["Bwd Packet Length Mean"]) / 2.0
        frame["Packet Length Std"] = np.maximum(
            frame["Packet Length Std"],
            np.sqrt(
                np.maximum(
                    (frame["Fwd Packet Length Std"] ** 2 + frame["Bwd Packet Length Std"] ** 2) / 2.0,
                    0.1,
                )
            ),
        )
        frame["Packet Length Variance"] = frame["Packet Length Std"] ** 2
        frame["Total Length of Fwd Packets"] = np.maximum(
            frame["Total Length of Fwd Packets"],
            frame["Total Fwd Packets"] * np.maximum(frame["Avg Fwd Segment Size"], 1.0),
        )
        frame["Total Length of Bwd Packets"] = np.maximum(
            frame["Total Length of Bwd Packets"],
            frame["Total Backward Packets"] * np.maximum(frame["Avg Bwd Segment Size"], 1.0),
        )
        frame["Flow Bytes/s"] = np.maximum(
            frame["Flow Bytes/s"],
            (frame["Total Length of Fwd Packets"] + frame["Total Length of Bwd Packets"])
            / np.maximum(frame["Flow Duration"] / 1e6, 1e-3),
        )
        frame["Flow Packets/s"] = np.maximum(
            frame["Flow Packets/s"],
            (frame["Total Fwd Packets"] + frame["Total Backward Packets"])
            / np.maximum(frame["Flow Duration"] / 1e6, 1e-3),
        )
        frame["Down/Up Ratio"] = np.maximum(
            frame["Down/Up Ratio"],
            frame["Total Backward Packets"] / np.maximum(frame["Total Fwd Packets"], 1.0),
        )

    df = pd.concat([benign, attack], ignore_index=True)
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    df = _enforce_physical_bounds(df)
    df = df[FEATURE_COLUMNS + ["Label"]]
    df.to_csv(output_csv_path, index=False)

    metadata = {
        "dataset_name": "ThreatXAI-SynthShield-v1",
        "rows": int(len(df)),
        "feature_count": int(len(FEATURE_COLUMNS)),
        "benign_rows": int((df["Label"] == "BENIGN").sum()),
        "attack_rows": int((df["Label"] != "BENIGN").sum()),
        "attack_types": attack_names,
        "seed": int(seed),
        "formulas": [
            "intensity = log1p(flow_packets_s) * sigmoid(syn_count / scale)",
            "stealth = exp(-ack_count / tau)",
            "burst_factor = sqrt(flow_bytes_s / max(flow_duration, eps))",
            "flow_bytes_s >= (total_fwd_len + total_bwd_len) / duration_seconds",
            "flow_packets_s >= (total_fwd_packets + total_bwd_packets) / duration_seconds",
        ],
    }
    if output_meta_path:
        with open(output_meta_path, "w") as f:
            json.dump(metadata, f, indent=2)
    return metadata
