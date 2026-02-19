"""
AI Real-Time Scam Link Detector - Pydantic Schemas
"""
from pydantic import BaseModel, HttpUrl, field_validator
from typing import Optional, List
from datetime import datetime
import re


class URLCheckRequest(BaseModel):
    """Request model for URL scanning."""
    url: str
    device_id: Optional[str] = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        # Add scheme if missing
        if not re.match(r"^https?://", v, re.IGNORECASE):
            v = "http://" + v
        # Basic URL pattern validation
        url_pattern = re.compile(
            r"^https?://"
            r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|"
            r"localhost|"
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
            r"(?::\d+)?"
            r"(?:/?|[/?]\S+)$",
            re.IGNORECASE,
        )
        if not url_pattern.match(v):
            raise ValueError("Invalid URL format")
        return v


class ThreatReport(BaseModel):
    """Full threat analysis response."""
    url: str
    risk_score: float
    status: str  # "Safe" | "Suspicious" | "Phishing"
    confidence: float
    ml_prediction: str
    ml_confidence: float
    domain_age_days: Optional[int] = None
    ssl_valid: Optional[bool] = None
    ssl_issuer: Optional[str] = None
    ssl_expiry: Optional[str] = None
    impersonation_risk: bool = False
    impersonation_target: Optional[str] = None
    suspicious_keywords: List[str] = []
    url_features: Optional[dict] = None
    google_safe_browsing: Optional[str] = None
    recommendations: List[str] = []
    scanned_at: str


class ScanHistoryItem(BaseModel):
    """Single scan history item."""
    id: int
    url: str
    risk_score: float
    status: str
    scanned_at: datetime


class ScanHistoryResponse(BaseModel):
    """List of scan history items."""
    total: int
    records: List[ScanHistoryItem]


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    ml_model_loaded: bool
