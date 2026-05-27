"""routers/chat.py — Persistent analyst chat sessions + Groq-backed Q&A."""

import json
import uuid
import re
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import ChatSession, ChatMessage
from backend.schemas import AnalystChatRequest, AnalystChatResponse
from backend.services.chat_service import retrieve_context, generate_analyst_answer, GROQ_MODEL

router = APIRouter(prefix="/analyst", tags=["Analyst Chat"])


def _title_from_question(question: str) -> str:
    text = re.sub(r"\s+", " ", (question or "").strip())
    text = re.sub(r"[^\w\s:/.-]", "", text)
    words = [w for w in text.split(" ") if w]
    if not words:
        return "SOC Analyst Session"
    return " ".join(words[:7])[:80]


def _create_session(db: Session, title: str = None) -> ChatSession:
    sid = str(uuid.uuid4())
    row = ChatSession(session_id=sid, title=title or "SOC Analyst Session", model_name=GROQ_MODEL)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@router.get("/sessions")
async def list_sessions(limit: int = 50, db: Session = Depends(get_db)):
    rows = db.query(ChatSession).order_by(ChatSession.updated_at.desc()).limit(min(limit, 200)).all()
    return [
        {
            "session_id": s.session_id,
            "title": s.title,
            "model_name": s.model_name,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "updated_at": s.updated_at.isoformat() if s.updated_at else None,
        }
        for s in rows
    ]


@router.post("/sessions")
async def create_session(payload: dict = None, db: Session = Depends(get_db)):
    title = (payload or {}).get("title")
    s = _create_session(db, title=title)
    return {
        "session_id": s.session_id,
        "title": s.title,
        "model_name": s.model_name,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }


@router.get("/sessions/{session_id}/messages")
async def get_messages(session_id: str, db: Session = Depends(get_db)):
    s = db.query(ChatSession).filter(ChatSession.session_id == session_id).first()
    if not s:
        raise HTTPException(404, "Session not found")
    rows = db.query(ChatMessage).filter(ChatMessage.session_id == session_id).order_by(ChatMessage.created_at.asc()).all()
    return [
        {
            "id": m.id,
            "role": m.role,
            "content": m.content,
            "context": json.loads(m.context_json) if m.context_json else None,
            "created_at": m.created_at.isoformat() if m.created_at else None,
        }
        for m in rows
    ]


@router.delete("/sessions/{session_id}")
async def delete_session(session_id: str, db: Session = Depends(get_db)):
    s = db.query(ChatSession).filter(ChatSession.session_id == session_id).first()
    if not s:
        raise HTTPException(404, "Session not found")

    db.query(ChatMessage).filter(ChatMessage.session_id == session_id).delete(synchronize_session=False)
    db.delete(s)
    db.commit()
    return {"status": "deleted", "session_id": session_id}


@router.post("/chat", response_model=AnalystChatResponse)
async def chat(req: AnalystChatRequest, db: Session = Depends(get_db)):
    question = (req.question or "").strip()
    if not question:
        raise HTTPException(400, "Question is required")
    if len(question) > 8000:
        raise HTTPException(400, "Question too long")

    session = None
    if req.session_id:
        session = db.query(ChatSession).filter(ChatSession.session_id == req.session_id).first()
    if not session:
        session = _create_session(db, title=_title_from_question(question))

    history_rows = (
        db.query(ChatMessage)
        .filter(ChatMessage.session_id == session.session_id)
        .order_by(ChatMessage.created_at.asc())
        .all()
    )
    history = [{"role": r.role, "content": r.content} for r in history_rows if r.role in {"user", "assistant"}]

    # Backfill session title from first meaningful user query for older/default sessions.
    if not history and (not session.title or session.title == "SOC Analyst Session"):
        session.title = _title_from_question(question)
        db.add(session)
        db.commit()

    effective_alert_id = req.alert_id
    if not effective_alert_id:
        m = re.search(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", question)
        if m:
            effective_alert_id = m.group(0)

    effective_cluster_id = req.cluster_id
    if not effective_cluster_id:
        m = re.search(r"\bcluster_[a-zA-Z0-9]{8}\b", question)
        if m:
            effective_cluster_id = m.group(0)

    context = retrieve_context(
        db,
        question=question,
        alert_id=effective_alert_id,
        cluster_id=effective_cluster_id,
    )
    answer_payload = await generate_analyst_answer(question=question, context=context, chat_history=history)
    answer = answer_payload.get("answer", "").strip() or "No answer generated."

    user_msg = ChatMessage(session_id=session.session_id, role="user", content=question)
    assistant_msg = ChatMessage(
        session_id=session.session_id,
        role="assistant",
        content=answer,
        context_json=json.dumps(
            {
                "context": context,
                "model": answer_payload.get("model", GROQ_MODEL),
                "model_type": req.model_type,
                "effective_alert_id": effective_alert_id,
                "effective_cluster_id": effective_cluster_id,
            }
        ),
    )
    db.add(user_msg)
    db.add(assistant_msg)
    db.commit()

    return AnalystChatResponse(session_id=session.session_id, answer=answer, context_used=context)
