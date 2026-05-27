"""schemas.py — Pydantic request/response models for ThreatXAI API"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class PredictRequest(BaseModel):
    features: List[float] = Field(..., description="68 CICFlowMeter feature values")
    src_ip: Optional[str] = Field(default=None, description="Source IP address")
    dst_ip: Optional[str] = Field(default=None, description="Destination IP address")
    protocol: Optional[str] = Field(default=None, description="Protocol (TCP, UDP, ICMP, etc)")
    model_type: str = Field(default="xgboost", description="xgboost | rf | dnn | hybrid")


class SHAPFeature(BaseModel):
    feature: str
    shap_value: float


class LIMEFeature(BaseModel):
    feature: str
    weight: float


class PredictResponse(BaseModel):
    prediction: int           # 0=Benign, 1=Attack
    label: str                # "Benign" or "Attack"
    confidence: float         # final decision confidence (label-aligned)
    attack_probability: Optional[float] = None  # raw model P(attack)
    model_used: str
    alert_id: Optional[str] = None
    cluster_id: Optional[str] = None
    cluster_label: Optional[str] = None
    cluster_similarity: Optional[float] = None


class ExplainRequest(BaseModel):
    features: List[float]
    alert_id: Optional[str] = None
    model_type: str = "xgboost"


class AnalystChatRequest(BaseModel):
    session_id: Optional[str] = None
    question: str
    alert_id: Optional[str] = None
    cluster_id: Optional[str] = None
    model_type: str = "xgboost"


class AnalystChatResponse(BaseModel):
    session_id: str
    answer: str
    context_used: Dict[str, Any]


class SHAPResponse(BaseModel):
    alert_id: Optional[str]
    shap_values: Dict[str, float]
    top_features: List[SHAPFeature]
    base_value: float = 0.5
    prediction: int
    confidence: float


class LIMEResponse(BaseModel):
    alert_id: Optional[str]
    lime_features: List[LIMEFeature]
    prediction_proba: List[float]


class AlertOut(BaseModel):
    id: int
    alert_id: str
    timestamp: datetime
    src_ip: Optional[str]
    dst_ip: Optional[str]
    protocol: Optional[str]
    prediction: int
    label: str
    confidence: float
    attack_probability: Optional[float]
    cluster_id: Optional[str]
    cluster_label: Optional[str]
    shap_top_features: Optional[List[SHAPFeature]]

    class Config:
        from_attributes = True


class ClusterOut(BaseModel):
    cluster_id: str
    label: str
    member_count: int
    alert_ids: List[str]
    top_shap_features: List[SHAPFeature]


class CaptureStatus(BaseModel):
    status: str   # "running" | "stopped"
    packets_captured: int
    alerts_generated: int


class MetricsOut(BaseModel):
    model: str
    accuracy: float
    precision: float
    recall: float
    f1: float
    roc_auc: float
