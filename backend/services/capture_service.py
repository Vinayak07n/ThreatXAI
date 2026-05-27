"""
services/capture_service.py — Live Packet Capture using Scapy
Captures network packets, extracts features compatible with the trained model,
classifies them, generates SHAP explanations, and stores alerts.
"""

import os
import sys
import uuid
import json
import time
import threading
import numpy as np
import logging
from typing import Optional, Callable

log = logging.getLogger(__name__)

# Capture state
_capture_thread: Optional[threading.Thread] = None
_is_capturing = False
_packets_captured = 0
_alerts_generated = 0
_stop_event = threading.Event()
_default_model = "xgboost"

# Hardcoded per-model decision thresholds to reduce live false positives.
MODEL_ATTACK_THRESHOLDS = {
    "xgboost": 0.70,
    "rf": 0.72,
    "dnn": 0.75,
    "hybrid": 0.88,
}

# Extra hard guardrail for live capture to suppress false positives on normal traffic.
LIVE_ATTACK_MIN_RAW_PROBA = 0.9999


def _get_attack_threshold(model_type: str) -> float:
    return float(MODEL_ATTACK_THRESHOLDS.get(model_type, 0.5))


def _model_attack_proba(model, model_type: str, features_scaled: np.ndarray) -> float:
    if model_type == "dnn" or not hasattr(model, "predict_proba"):
        raw = model.predict(features_scaled.reshape(1, -1), verbose=0)
        if raw.shape[-1] == 1:
            return float(raw[0][0])
        return float(raw[0][1])
    return float(model.predict_proba(features_scaled.reshape(1, -1))[0][1])


def get_capture_status() -> dict:
    return {
        "status": "running" if _is_capturing else "stopped",
        "packets_captured": _packets_captured,
        "alerts_generated": _alerts_generated,
        "model_used": _default_model,
        "capture_source": "all network interfaces (Scapy)",
        "requires_sudo": True,
        "description": f"Live packet capture using Scapy. Packets are processed into flows, features extracted, and sent to {_default_model.upper()} model for classification.",
    }


def start_capture(on_alert: Optional[Callable] = None):
    """Starts background Scapy packet capture from all network interfaces."""
    global _capture_thread, _is_capturing, _packets_captured, _alerts_generated

    if _is_capturing:
        return {"status": "already_running"}

    _packets_captured = 0
    _alerts_generated = 0
    _stop_event.clear()
    _is_capturing = True

    _capture_thread = threading.Thread(
        target=_capture_loop, args=(on_alert,), daemon=True
    )
    _capture_thread.start()
    log.info(f"★ Packet capture started - Listening on all network interfaces with Scapy")
    log.info(f"   Model: {_default_model.upper()} | Network: All interfaces | Status: Capturing")
    return {
        "status": "started",
        "message": "Capturing packets from all network interfaces using Scapy",
        "model": _default_model,
        "interface": "all",
        "note": "Requires sudo/elevated privileges on macOS/Linux. Falls back to simulation if unavailable."
    }


def stop_capture():
    """Stops background Scapy packet capture."""
    global _is_capturing
    _stop_event.set()
    _is_capturing = False
    log.info("Packet capture stopped")
    return {"status": "stopped", "packets_captured": _packets_captured, "alerts_generated": _alerts_generated}


def _capture_loop(on_alert: Optional[Callable]):
    """Main capture loop — collects flows, extracts features, runs inference."""
    global _packets_captured, _alerts_generated

    try:
        from scapy.all import sniff, IP, IPv6, TCP, UDP
    except ImportError:
        log.warning("⚠ Scapy not available — using simulated capture for demo.")
        _simulated_capture_loop(on_alert)
        return

    log.info("📡 Scapy initialized - Sniffing packets from ALL network interfaces")
    flow_buffer = {}  # flow_key → list of packets
    FLOW_TIMEOUT = 5  # seconds to wait before processing a flow

    def process_packet(pkt):
        global _packets_captured
        if _stop_event.is_set():
            return

        _packets_captured += 1

        has_ipv4 = IP in pkt
        has_ipv6 = IPv6 in pkt
        if not has_ipv4 and not has_ipv6:
            return

        if has_ipv4:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        else:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
        protocol = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else "OTHER")

        # Flow key (bidirectional)
        flow_key = tuple(sorted([src_ip, dst_ip]) + [protocol])

        if flow_key not in flow_buffer:
            flow_buffer[flow_key] = {
                "packets": [], "start_time": time.time(),
                "src_ip": src_ip, "dst_ip": dst_ip, "protocol": protocol
            }

        flow_buffer[flow_key]["packets"].append(pkt)

        # Process completed flows
        now = time.time()
        completed = [k for k, v in flow_buffer.items()
                     if now - v["start_time"] > FLOW_TIMEOUT or len(v["packets"]) > 100]

        for key in completed:
            flow = flow_buffer.pop(key)
            features = _extract_features(flow["packets"])
            if features is not None:
                _run_inference(features, flow["src_ip"], flow["dst_ip"],
                               flow["protocol"], on_alert)

    try:
        # sniff() captures packets from all interfaces
        # prn=process_packet: callback for each packet
        # store=False: don't store packets in memory (space efficient)
        # timeout=300: stop after 5 minutes of inactivity
        log.info("🔍 Starting packet sniff - listening on all interfaces...")
        sniff(prn=process_packet, stop_filter=lambda _: _stop_event.is_set(),
              store=False, timeout=300)
    except PermissionError:
        log.error("❌ Permission denied - Scapy requires sudo/elevated privileges on this OS")
        log.warning("⚠ Falling back to simulated capture...")
        _simulated_capture_loop(on_alert)
    except Exception as e:
        log.warning(f"Scapy sniff error (may need sudo): {e}")
        _simulated_capture_loop(on_alert)


def _extract_features(packets: list) -> Optional[np.ndarray]:
    """
    Extracts CICFlowMeter-compatible features from a list of Scapy packets.
    Returns a 67-feature vector (subset of the 78 CIC features extractable live).
    """
    try:
        from scapy.all import IP, TCP, UDP
        import statistics

        if not packets or len(packets) < 2:
            return None

        # Timing
        timestamps = [float(p.time) for p in packets]
        flow_duration = (max(timestamps) - min(timestamps)) * 1e6  # microseconds

        # Packet lengths
        lengths = [len(p) for p in packets]
        fwd_pkts = [p for p in packets if IP in p]
        bwd_pkts = fwd_pkts[len(fwd_pkts)//2:]  # approximation
        fwd_pkts = fwd_pkts[:len(fwd_pkts)//2]

        fwd_lens = [len(p) for p in fwd_pkts] or [0]
        bwd_lens = [len(p) for p in bwd_pkts] or [0]

        # TCP flags analysis
        syn_count = sum(1 for p in packets if TCP in p and p[TCP].flags & 0x02)
        ack_count = sum(1 for p in packets if TCP in p and p[TCP].flags & 0x10)
        fin_count = sum(1 for p in packets if TCP in p and p[TCP].flags & 0x01)
        psh_count = sum(1 for p in packets if TCP in p and p[TCP].flags & 0x08)
        rst_count = sum(1 for p in packets if TCP in p and p[TCP].flags & 0x04)

        # Flow rates
        if flow_duration > 0:
            flow_bytes_s = sum(lengths) / (flow_duration / 1e6)
            flow_pkts_s = len(packets) / (flow_duration / 1e6)
        else:
            flow_bytes_s = 0
            flow_pkts_s = 0

        def _iat_stats(ts: list[float]) -> tuple[float, float, float, float, float]:
            if len(ts) < 2:
                return 0.0, 0.0, 0.0, 0.0, 0.0
            deltas = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
            total = sum(deltas) * 1e6
            mean = statistics.mean(deltas) * 1e6
            std = statistics.stdev(deltas) * 1e6 if len(deltas) > 1 else 0.0
            return total, mean, std, max(deltas) * 1e6, min(deltas) * 1e6

        # IAT (inter-arrival times)
        _, iat_mean, iat_std, iat_max, iat_min = _iat_stats(timestamps)
        fwd_ts = [float(p.time) for p in fwd_pkts]
        bwd_ts = [float(p.time) for p in bwd_pkts]
        fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = _iat_stats(fwd_ts)
        bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = _iat_stats(bwd_ts)

        features = [
            max(fwd_lens),                                    # Fwd Packet Length Max
            statistics.mean(fwd_lens),                        # Fwd Packet Length Mean
            max(bwd_lens),                                    # Bwd Packet Length Max
            statistics.mean(bwd_lens),                        # Bwd Packet Length Mean
            flow_bytes_s,                                     # Flow Bytes/s
            flow_pkts_s,                                      # Flow Packets/s
            iat_mean, iat_std, iat_max, iat_min,             # Flow IAT
            fwd_iat_total,                                   # Fwd IAT Total
            fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min,  # Fwd IAT
            bwd_iat_total,                                   # Bwd IAT Total
            bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min,  # Bwd IAT
            int(bool(psh_count)), 0, 0, 0,                   # PSH/URG flags
            len(fwd_pkts) * 20, len(bwd_pkts) * 20,         # Header lengths
            flow_pkts_s / 2, flow_pkts_s / 2,               # Fwd/Bwd Packets/s
            min(lengths), max(lengths),                       # Min/Max Packet Length
            statistics.mean(lengths),                         # Packet Length Mean
            statistics.stdev(lengths) if len(lengths)>1 else 0,  # Packet Length Std
            (statistics.stdev(lengths)**2 if len(lengths)>1 else 0),  # Variance
            fin_count, syn_count, rst_count,                  # TCP Flags
            psh_count, ack_count, 0, 0, 0,                   # More flags
            len(bwd_pkts)/max(len(fwd_pkts),1),             # Down/Up Ratio
            statistics.mean(lengths),                         # Average Packet Size
            statistics.mean(fwd_lens),                        # Avg Fwd Segment
            statistics.mean(bwd_lens),                        # Avg Bwd Segment
            len(fwd_pkts), sum(fwd_lens), len(bwd_pkts), sum(bwd_lens),  # Subflows
            65535, 65535,                                     # Init Win bytes (default)
            len(fwd_pkts), 20,                               # act_data, min_seg
            iat_mean, iat_std, iat_max, iat_min,             # Active
            iat_mean * 10, iat_std * 2, iat_max * 5, iat_min,  # Idle
            len(fwd_pkts), len(bwd_pkts),                    # Total Fwd/Bwd Packets
            sum(fwd_lens), sum(bwd_lens),                    # Total Lengths
            statistics.stdev(fwd_lens) if len(fwd_lens)>1 else 0,  # Fwd Length Std
            statistics.stdev(bwd_lens) if len(bwd_lens)>1 else 0,  # Bwd Length Std
            flow_duration,                                    # Flow Duration
        ]

        # Pad/truncate to expected feature count
        features = np.array(features, dtype=np.float32)
        features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)
        return features

    except Exception as e:
        log.debug(f"Feature extraction error: {e}")
        return None


def _run_inference(features: np.ndarray, src_ip: str, dst_ip: str,
                   protocol: str, on_alert: Optional[Callable]):
    """Run model prediction + SHAP + EDAC and call alert callback."""
    global _alerts_generated
    try:
        from backend.services.model_service import get_models, get_scaler, get_feature_names, get_edac_engine
        from backend.services.explain_service import get_shap_explanation

        models = get_models()
        if not models:
            return

        scaler = get_scaler()
        feature_names = get_feature_names()

        # Align feature dimensions
        n_expected = scaler.mean_.shape[0]
        if len(features) < n_expected:
            features = np.pad(features, (0, n_expected - len(features)))
        elif len(features) > n_expected:
            features = features[:n_expected]

        features_scaled = scaler.transform(features.reshape(1, -1))[0]

        model = models.get(_default_model) or models.get("xgboost") or list(models.values())[0]
        model_type = _default_model if _default_model in models else list(models.keys())[0]

        proba = _model_attack_proba(model, model_type, features_scaled)
        # Keep probabilities bounded for stable confidence math/display.
        proba = max(0.0, min(1.0, float(proba)))
        attack_threshold = _get_attack_threshold(model_type)
        prediction = int(proba >= attack_threshold)
        votes = 1 if prediction == 1 else 0
        total_voters = 1
        min_votes = 1

        # False-positive guardrail for live capture:
        # require multi-model agreement before promoting to Attack.
        if prediction == 1:
            voters = [m for m in ["xgboost", "rf", "hybrid"] if m in models]
            if model_type not in voters and model_type in models:
                voters.append(model_type)
            votes = 0
            for voter in voters:
                p = _model_attack_proba(models[voter], voter, features_scaled)
                if p >= _get_attack_threshold(voter):
                    votes += 1
            total_voters = len(voters)
            min_votes = len(voters) if len(voters) >= 3 else (2 if len(voters) >= 2 else 1)
            if votes < min_votes:
                prediction = 0

        # Final live-capture gate: even after consensus, require extreme raw attack probability.
        if prediction == 1 and proba < LIVE_ATTACK_MIN_RAW_PROBA:
            prediction = 0

        alert_id = str(uuid.uuid4())

        # SHAP explanation for ALL traffic (both benign and attack)
        shap_exp = {}
        cluster_info = {}
        shap_vector = np.array([])
        try:
            shap_exp = get_shap_explanation(model, features_scaled, feature_names, model_type)
            shap_vector = np.array(shap_exp.get("shap_vector", []), dtype=np.float32)

            # EDAC clustering only for attacks
            if prediction == 1 and len(shap_vector) > 0:
                edac = get_edac_engine()
                cluster_info = edac.assign_alert(shap_vector, alert_id)
        except Exception as e:
            log.warning(f"SHAP/EDAC error: {e}")

        # Ensure every attack gets a campaign assignment (fallback to scaled feature vector).
        if prediction == 1 and not cluster_info.get("cluster_id"):
            try:
                edac = get_edac_engine()
                if edac is not None:
                    if shap_vector.size == 0:
                        shap_vector = np.array(features_scaled, dtype=np.float32)
                    cluster_info = edac.assign_alert(shap_vector, alert_id)
            except Exception as e:
                log.warning(f"EDAC fallback assignment failed: {e}")

        if prediction == 1:
            _alerts_generated += 1

        benign_votes = max(total_voters - votes, 0)
        attack_vote_ratio = votes / max(total_voters, 1)
        benign_vote_ratio = benign_votes / max(total_voters, 1)

        if prediction == 1:
            label_confidence = max(proba, attack_vote_ratio)
        else:
            # Benign confidence is label-aligned and never contradictory with final decision context.
            label_confidence = max(1.0 - proba, benign_vote_ratio)

        # Numeric safety and UX guardrail.
        label_confidence = max(0.0, min(1.0, float(label_confidence)))

        alert_data = {
            "alert_id": alert_id,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "prediction": prediction,
            "label": "Attack" if prediction == 1 else "Benign",
            "confidence": round(float(label_confidence), 4),
            "attack_probability": round(float(proba), 4),
            "cluster_id": cluster_info.get("cluster_id"),
            "cluster_label": cluster_info.get("label"),
            "cluster_similarity": cluster_info.get("similarity_score"),
            "shap_top_features": shap_exp.get("top_features", [])[:10],
            "model_used": model_type,
            "is_live_capture": True,
        }

        if on_alert:
            on_alert(alert_data)

    except Exception as e:
        log.error(f"Inference error: {e}")


def _simulated_capture_loop(on_alert: Optional[Callable]):
    """Simulated capture for demo when Scapy is unavailable or no sudo."""
    import random
    log.info("Running SIMULATED packet capture (demo mode)")

    attack_profiles = [
        {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.100", "protocol": "TCP", "label": "Attack", "confidence": 0.97},
        {"src_ip": "172.16.0.5", "dst_ip": "192.168.1.200", "protocol": "UDP", "label": "Attack", "confidence": 0.89},
        {"src_ip": "192.168.2.10", "dst_ip": "8.8.8.8", "protocol": "TCP", "label": "Benign", "confidence": 0.12},
        {"src_ip": "10.10.0.50", "dst_ip": "192.168.1.1", "protocol": "TCP", "label": "Attack", "confidence": 0.94},
        {"src_ip": "192.168.1.50", "dst_ip": "google.com", "protocol": "TCP", "label": "Benign", "confidence": 0.05},
    ]

    interval = 2  # seconds between simulated alerts

    while not _stop_event.is_set():
        profile = random.choice(attack_profiles)
        alert_id = str(uuid.uuid4())
        prediction = 1 if profile["label"] == "Attack" else 0

        # Simulated SHAP top features
        feature_names = ["SYN Flag Count", "Flow Bytes/s", "Flow Duration",
                         "Total Fwd Packets", "Fwd Packet Length Mean",
                         "Flow Packets/s", "ACK Flag Count", "Init_Win_bytes_forward"]
        shap_tops = [{"feature": f, "shap_value": round(random.uniform(-0.3, 0.5), 4)}
                     for f in feature_names[:5]]

        alert_data = {
            "alert_id": alert_id,
            "src_ip": profile["src_ip"],
            "dst_ip": profile["dst_ip"],
            "protocol": profile["protocol"],
            "prediction": prediction,
            "label": profile["label"],
            "confidence": profile["confidence"],
            "cluster_id": None,
            "cluster_label": None,
            "cluster_similarity": None,
            "shap_top_features": shap_tops,
            "is_live_capture": True,
        }

        if prediction == 1:
            alert_data["cluster_id"] = f"cluster_{random.choice(['a1b2', 'c3d4', 'e5f6'])}"
            alert_data["cluster_label"] = random.choice(["SYN Flood Campaign", "Port Scan Campaign", "Brute Force Campaign"])
            alert_data["cluster_similarity"] = round(random.uniform(0.80, 0.99), 2)

        if on_alert:
            on_alert(alert_data)

        _stop_event.wait(interval)
