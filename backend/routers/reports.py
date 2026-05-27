"""routers/reports.py — PDF exports for alerts and analyst chat sessions."""

from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session
from backend.db.session import get_db
from backend.db.models import Alert, ChatSession, ChatMessage
from backend.services.pdf_service import build_text_pdf

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/alerts/pdf")
async def export_alerts_pdf(
    prediction: int | None = Query(default=None, description="0 benign, 1 attack, None all"),
    cluster_id: str | None = Query(default=None),
    limit: int = Query(default=500, ge=1, le=5000),
    db: Session = Depends(get_db),
):
    q = db.query(Alert).order_by(Alert.timestamp.desc())
    if prediction is not None:
        q = q.filter(Alert.prediction == prediction)
    if cluster_id:
        q = q.filter(Alert.cluster_id == cluster_id)
    rows = q.limit(limit).all()

    lines = [
        f"Filters: prediction={prediction if prediction is not None else 'all'}, cluster_id={cluster_id or 'all'}, limit={limit}",
        "",
        "Columns: time | alert_id | src_ip -> dst_ip | protocol | label | final_confidence | raw_attack_probability | campaign",
        "-" * 120,
    ]

    for a in rows:
        ts = a.timestamp.isoformat() if a.timestamp else "N/A"
        campaign = a.cluster_label or "-"
        raw_attack = f"{(a.attack_probability * 100):.2f}%" if a.attack_probability is not None else "N/A"
        final_conf = f"{(a.confidence * 100):.2f}%" if a.confidence is not None else "N/A"
        lines.append(
            f"{ts} | {a.alert_id} | {a.src_ip or '-'} -> {a.dst_ip or '-'} | {a.protocol or '-'} | "
            f"{a.label or '-'} | {final_conf} | {raw_attack} | {campaign}"
        )

    pdf = build_text_pdf("ThreatXAI Alerts Report", lines)
    filename = f"threatxai_alerts_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/chat/{session_id}/pdf")
async def export_chat_pdf(session_id: str, db: Session = Depends(get_db)):
    session = db.query(ChatSession).filter(ChatSession.session_id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail=f"Chat session {session_id} not found")

    msgs = (
        db.query(ChatMessage)
        .filter(ChatMessage.session_id == session_id)
        .order_by(ChatMessage.created_at.asc())
        .all()
    )

    lines = [
        f"Session ID: {session.session_id}",
        f"Title: {session.title or 'SOC Analyst Session'}",
        f"Model: {session.model_name or 'N/A'}",
        "",
        "-" * 120,
    ]

    for m in msgs:
        ts = m.created_at.isoformat() if m.created_at else "N/A"
        role = (m.role or "unknown").upper()
        lines.append(f"[{ts}] {role}:")
        lines.append((m.content or "").strip() or "(empty)")
        lines.append("")

    pdf = build_text_pdf("ThreatXAI Analyst Chat Report", lines)
    filename = f"threatxai_chat_{session_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
