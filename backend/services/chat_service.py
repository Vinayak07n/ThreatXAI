"""chat_service.py — Retrieval + Groq LLM response generation for analyst chat."""

import os
import json
import httpx
import re
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from backend.db.models import Alert


GROQ_API_BASE = os.getenv("GROQ_API_BASE", "https://api.groq.com/openai/v1")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_FALLBACK_MODELS = [
    m.strip()
    for m in os.getenv("GROQ_FALLBACK_MODELS", "llama-3.1-8b-instant").split(",")
    if m.strip()
]


def _safe_shap_top(shap_json: Optional[str], top_n: int = 8):
    if not shap_json:
        return []
    try:
        data = json.loads(shap_json)
        return sorted(data.items(), key=lambda x: abs(x[1]), reverse=True)[:top_n]
    except Exception:
        return []


def _parse_time_window(question: str):
    q = (question or "").lower()
    now = datetime.utcnow()

    m = re.search(r"last\s+(\d+)\s*(minute|minutes|min|hour|hours|hr|day|days)", q)
    if m:
        n = int(m.group(1))
        unit = m.group(2)
        if unit.startswith(("minute", "min")):
            delta = timedelta(minutes=n)
        elif unit.startswith(("hour", "hr")):
            delta = timedelta(hours=n)
        else:
            delta = timedelta(days=n)
        return now - delta, f"last {n} {unit}"

    if "last hour" in q:
        return now - timedelta(hours=1), "last 1 hour"
    if "last 24 hours" in q:
        return now - timedelta(hours=24), "last 24 hours"
    if "today" in q:
        start = datetime(now.year, now.month, now.day)
        return start, "today"
    return None, None


def _parse_intent(question: str) -> Dict[str, Any]:
    q = (question or "").lower()
    since_dt, time_label = _parse_time_window(question)

    focus_campaigns = any(k in q for k in ["campaign", "campaigns", "top active attack", "top attack"])
    focus_containment = any(k in q for k in ["containment", "next 15 minutes", "immediate actions", "soc take"])
    focus_attacks = any(k in q for k in ["attack", "ioc", "cve", "threat", "malicious", "incident"]) or focus_campaigns

    cluster_match = re.search(r"\bcluster_[a-zA-Z0-9]{8}\b", question or "")
    return {
        "since_dt": since_dt,
        "time_label": time_label,
        "focus_campaigns": focus_campaigns,
        "focus_containment": focus_containment,
        "focus_attacks": focus_attacks,
        "cluster_from_text": cluster_match.group(0) if cluster_match else None,
    }


def retrieve_context(
    db: Session, question: str, alert_id: Optional[str] = None, cluster_id: Optional[str] = None
) -> Dict[str, Any]:
    intent = _parse_intent(question)
    effective_cluster_id = cluster_id or intent["cluster_from_text"]
    q = db.query(Alert)

    stale_attack_fallback = False
    latest_event_ts = db.query(Alert.timestamp).order_by(Alert.timestamp.desc()).limit(1).scalar()
    no_data_in_window = False

    if alert_id:
        item = q.filter(Alert.alert_id == alert_id).first()
        alerts = [item] if item else []
    elif effective_cluster_id:
        alerts = (
            q.filter(Alert.cluster_id == effective_cluster_id)
            .order_by(Alert.timestamp.desc())
            .limit(20)
            .all()
        )
    else:
        if intent["since_dt"] is not None:
            q = q.filter(Alert.timestamp >= intent["since_dt"])
        if intent["focus_campaigns"]:
            q = q.filter(Alert.prediction == 1)
        alerts = q.order_by(Alert.timestamp.desc()).limit(50).all()

        # If a strict time window yields no data, keep that fact explicit.
        # For broad non-time queries only, fallback to latest alerts.
        if not alerts and intent["since_dt"] is None:
            alerts = db.query(Alert).order_by(Alert.timestamp.desc()).limit(25).all()
        elif not alerts and intent["focus_attacks"]:
            no_data_in_window = bool(intent["time_label"])
            # If query is attack-focused but window is empty, fallback to recent attacks.
            alerts = (
                db.query(Alert)
                .filter(Alert.prediction == 1)
                .order_by(Alert.timestamp.desc())
                .limit(25)
                .all()
            )
            stale_attack_fallback = len(alerts) > 0

    attacks = [a for a in alerts if a and a.prediction == 1]
    benign = [a for a in alerts if a and a.prediction == 0]
    clusters = {}
    for a in attacks:
        key = a.cluster_label or "Unclustered"
        clusters[key] = clusters.get(key, 0) + 1

    top_alerts = []
    for a in alerts[:8]:
        if not a:
            continue
        top_alerts.append(
            {
                "alert_id": a.alert_id,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "src_ip": a.src_ip,
                "dst_ip": a.dst_ip,
                "protocol": a.protocol,
                "label": a.label,
                "confidence": a.confidence,
                "cluster_label": a.cluster_label,
                "top_shap_features": _safe_shap_top(a.shap_json),
            }
        )

    # Lightweight rule-based threat-intel retrieval from campaign labels/question
    question_l = (question or "").lower()
    iocs = []
    cves = []
    mitigations = []
    cluster_text = " ".join([k.lower() for k in clusters.keys()])
    merged_text = f"{question_l} {cluster_text}"

    if "ddos" in merged_text or "syn" in merged_text:
        iocs.extend(["high SYN flag spikes", "extreme flow_packets/s", "near-zero ACK ratio"])
        cves.extend(["CVE-2018-5391", "CVE-2020-25705"])
        mitigations.extend(["Enable SYN cookies", "Rate-limit edge ingress", "Apply BCP38 filtering"])
    if "scan" in merged_text or "portscan" in merged_text:
        iocs.extend(["high RST counts", "very short flow duration", "single-packet fan-out"])
        cves.extend(["CVE-2021-41773"])
        mitigations.extend(["Block scan source ranges", "Increase scan detection thresholds", "Harden exposed services"])
    if "credential" in merged_text or "brute" in merged_text:
        iocs.extend(["repeated auth bursts", "high ACK retries", "small request payload loops"])
        cves.extend(["CVE-2023-20198", "CVE-2024-3400"])
        mitigations.extend(["Enable MFA", "Account lockout policy", "Geo/risk-based login controls"])
    if "infiltration" in merged_text or "lateral" in merged_text:
        iocs.extend(["multi-host east-west bursts", "abnormal subflow fanout", "window-size anomalies"])
        cves.extend(["CVE-2021-44228", "CVE-2020-1472"])
        mitigations.extend(["Segment east-west traffic", "Rotate privileged credentials", "Apply EDR containment"])

    # Generic security guidance anchors for broad questions when attack evidence is thin.
    generic_iocs = [
        "multiple failed authentication bursts",
        "unexpected privileged account creation",
        "unusual outbound data transfer spikes",
        "rare process spawning from office/browser apps",
        "suspicious PowerShell or command-line encodings",
    ]
    generic_cves = ["CVE-2021-44228", "CVE-2020-1472", "CVE-2023-20198", "CVE-2024-3400"]
    if not iocs:
        iocs.extend(generic_iocs[:4])
    if not cves:
        cves.extend(generic_cves[:3])

    top_campaigns = sorted(clusters.items(), key=lambda x: x[1], reverse=True)[:8]

    return {
        "scope": "alert" if alert_id else ("cluster" if effective_cluster_id else "global"),
        "question": question,
        "selected_alert_id": alert_id,
        "selected_cluster_id": effective_cluster_id,
        "retrieval_meta": {
            "time_filter_applied": intent["time_label"] is not None,
            "time_filter_label": intent["time_label"],
            "focus_campaigns": intent["focus_campaigns"],
            "focus_containment": intent["focus_containment"],
            "no_data_in_window": no_data_in_window or bool(intent["time_label"] and len(alerts) == 0),
            "stale_attack_fallback": stale_attack_fallback,
            "latest_event_timestamp": latest_event_ts.isoformat() if latest_event_ts else None,
        },
        "stats": {
            "total_considered": len(alerts),
            "attacks": len(attacks),
            "benign": len(benign),
            "attack_rate": round(len(attacks) / len(alerts), 4) if alerts else 0.0,
            "campaign_breakdown": clusters,
            "top_campaigns": top_campaigns,
        },
        "alerts": top_alerts,
        "threat_intel": {
            "iocs": sorted(set(iocs))[:8],
            "cves": sorted(set(cves))[:6],
            "recommended_actions": sorted(set(mitigations))[:8],
        },
    }


def build_system_prompt(context: Dict[str, Any]) -> str:
    return (
        "You are a SOC co-pilot. Respond with precise, evidence-based incident guidance. "
        "Use provided context first and clearly separate facts from inferences. "
        "If context is sparse or stale, provide clearly-labeled general SOC best-practice guidance. "
        "Use plain text only (no markdown, no asterisks, no headings with #). "
        "Format with clear section labels like 'Summary:', 'Hypothesis:', 'Confidence:', 'Next Steps:'. "
        "If a time window is requested but has no records, state this clearly with the exact window and latest data time. "
        "If no active attack exists, provide readiness actions (validation checks, monitoring and hardening) instead of vague no-op text. "
        "When user asks for SIEM rules, return concrete detection logic examples using available IoCs/CVEs and mark any generic assumptions explicitly. "
        "Include: 1) incident summary, 2) likely hypothesis, 3) confidence, 4) actionable next steps."
        f"\n\nContext JSON:\n{json.dumps(context, ensure_ascii=False)}"
    )


def fallback_answer(context: Dict[str, Any]) -> str:
    stats = context.get("stats", {})
    intel = context.get("threat_intel", {})
    return (
        "Groq API key is not configured. Here is a deterministic analyst summary:\n"
        f"- Alerts analyzed: {stats.get('total_considered', 0)} (attacks: {stats.get('attacks', 0)}, benign: {stats.get('benign', 0)})\n"
        f"- Campaign signals: {stats.get('campaign_breakdown', {})}\n"
        f"- IoCs: {intel.get('iocs', [])}\n"
        f"- CVEs to investigate: {intel.get('cves', [])}\n"
        f"- Recommended actions: {intel.get('recommended_actions', [])}"
    )


async def generate_analyst_answer(
    question: str, context: Dict[str, Any], chat_history: List[Dict[str, str]]
) -> Dict[str, Any]:
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return {"answer": fallback_answer(context), "model": "fallback"}

    messages = [{"role": "system", "content": build_system_prompt(context)}]
    for m in chat_history[-8:]:
        role = m.get("role", "user")
        if role in {"user", "assistant"}:
            messages.append({"role": role, "content": m.get("content", "")[:4000]})
    messages.append({"role": "user", "content": question})

    model_candidates = [GROQ_MODEL] + [m for m in GROQ_FALLBACK_MODELS if m != GROQ_MODEL]
    last_error = None
    async with httpx.AsyncClient(timeout=45) as client:
        for candidate in model_candidates:
            try:
                resp = await client.post(
                    f"{GROQ_API_BASE}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": candidate,
                        "messages": messages,
                        "temperature": 0.2,
                        "max_tokens": 800,
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                answer = data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
                if answer:
                    return {"answer": _sanitize_answer(answer), "model": candidate}
            except Exception as e:
                last_error = str(e)
                continue

    return {
        "answer": (
            "Unable to reach Groq model endpoints right now. "
            "Using fallback analyst summary.\n\n" + fallback_answer(context)
        ),
        "model": f"fallback ({last_error or 'no-model-response'})",
    }


def _sanitize_answer(text: str) -> str:
    """Normalize model output to clean plain text for SOC chat UI."""
    if not text:
        return text

    # Remove markdown emphasis and headings
    cleaned = text.replace("***", "").replace("**", "").replace("*", "")
    cleaned = re.sub(r"^\s{0,3}#{1,6}\s*", "", cleaned, flags=re.MULTILINE)
    cleaned = cleaned.replace("`", "")

    # Normalize bullet markers and spacing
    cleaned = re.sub(r"^\s*[-•]\s*", "- ", cleaned, flags=re.MULTILINE)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
    return cleaned
