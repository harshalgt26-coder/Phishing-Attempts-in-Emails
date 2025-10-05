from __future__ import annotations

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class AttachmentMeta(BaseModel):
    filename: str
    mime_type: Optional[str] = None
    size_bytes: Optional[int] = None


class EmailInput(BaseModel):
    subject: str = Field("", description="Email subject line")
    body_text: Optional[str] = Field(None, description="Plain-text body")
    body_html: Optional[str] = Field(None, description="HTML body if available")
    sender_email: str = Field(..., description="Sender email address, optionally with display name")
    sender_display_name: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    attachments: List[AttachmentMeta] = Field(default_factory=list)


class DetectionSignal(BaseModel):
    id: str
    title: str
    description: str
    severity: str = Field("low", description="low|medium|high")
    score_delta: int = Field(0, description="How much this signal influences the score")


class DetectionResult(BaseModel):
    verdict: str = Field(..., description="phishing|suspicious|safe")
    score: int = Field(..., ge=0, le=100)
    confidence: str = Field(..., description="low|medium|high")
    signals: List[DetectionSignal]
    recommendations: List[str]
    llm_summary: Optional[str] = None


class SampleEmail(BaseModel):
    id: str
    subject: str
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    sender_email: str
    sender_display_name: Optional[str] = None
    attachments: List[AttachmentMeta] = Field(default_factory=list)
    headers: Optional[Dict[str, str]] = None
