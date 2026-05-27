"""db/models.py — SQLAlchemy ORM models for ThreatXAI"""

from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean
from sqlalchemy.sql import func
from .session import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(36), unique=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    src_ip = Column(String(45), nullable=True)
    dst_ip = Column(String(45), nullable=True)
    protocol = Column(String(20), nullable=True)
    prediction = Column(Integer)  # 0=Benign, 1=Attack
    label = Column(String(20))
    confidence = Column(Float)  # final decision confidence (label-aligned)
    attack_probability = Column(Float, nullable=True)  # raw P(attack) before final decision logic
    cluster_id = Column(String(36), nullable=True, index=True)
    cluster_label = Column(String(100), nullable=True)
    cluster_similarity = Column(Float, nullable=True)
    shap_json = Column(Text, nullable=True)  # JSON: {feature: shap_value}
    lime_json = Column(Text, nullable=True)  # JSON: [{feature, weight}]
    features_json = Column(Text, nullable=True)  # Raw features for replay
    is_live_capture = Column(Boolean, default=False)


class ClusterRecord(Base):
    __tablename__ = "clusters"

    id = Column(Integer, primary_key=True)
    cluster_id = Column(String(36), unique=True, index=True)
    label = Column(String(100))
    member_count = Column(Integer, default=0)
    centroid_json = Column(Text)  # SHAP centroid vector
    top_features_json = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class ChatSession(Base):
    __tablename__ = "chat_sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(36), unique=True, index=True)
    title = Column(String(180), nullable=True)
    model_name = Column(String(80), default="llama-3.3-70b-versatile")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(36), index=True)
    role = Column(String(20))  # user | assistant | system
    content = Column(Text)
    context_json = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
