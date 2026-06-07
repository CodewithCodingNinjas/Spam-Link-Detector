"""
AI Real-Time Scam Link Detector - Main FastAPI Application
"""
import json
import logging
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Depends, HTTPException, Security
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from config import settings
from database import init_db, get_session, ScanRecord
from schemas import (
    URLCheckRequest,
    ThreatReport,
    ScanHistoryResponse,
    ScanHistoryItem,
    HealthResponse,
)
from modules.risk_engine import RiskScoringEngine

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

# API Key security
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: str = Security(api_key_header)):
    """Validate API key from request header."""
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API Key")
    if api_key != settings.API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return api_key


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan - startup and shutdown events."""
    # Startup
    logger.info("Starting AI Scam Link Detector API...")
    await init_db()
    logger.info("Database initialized")

    # Pre-load ML model
    from ml.predictor import get_predictor
    predictor = get_predictor()
    logger.info(f"ML Model loaded: {predictor.is_loaded()}")

    yield

    # Shutdown
    logger.info("Shutting down API...")


# Create FastAPI app
app = FastAPI(
    title="AI Real-Time Scam Link Detector",
    description="AI-powered URL Threat Intelligence System for detecting phishing and scam links",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Add rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Risk engine singleton
risk_engine = RiskScoringEngine()


# ========== ENDPOINTS ==========


@app.get("/", tags=["Root"])
async def root():
    """Root endpoint."""
    return {
        "name": "AI Real-Time Scam Link Detector API",
        "version": "1.0.0",
        "docs": "/docs",
    }


@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Health check endpoint."""
    from ml.predictor import get_predictor
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        ml_model_loaded=get_predictor().is_loaded(),
    )


@app.post("/check-link", response_model=ThreatReport, tags=["Scanning"])
@limiter.limit(settings.RATE_LIMIT)
async def check_link(
    request: Request,
    body: URLCheckRequest,
    session: AsyncSession = Depends(get_session),
    api_key: str = Depends(verify_api_key),
):
    """
    Scan a URL for phishing/scam threats.
    
    Returns a comprehensive threat report with:
    - Risk score (0-100)
    - Status (Safe / Suspicious / Phishing)
    - ML prediction with confidence
    - Domain age analysis
    - SSL validation
    - Brand impersonation check
    - Suspicious keyword detection
    - Recommendations
    """
    logger.info(f"Scanning URL: {body.url}")

    try:
        # Run full analysis
        report = await risk_engine.analyze(body.url)

        # Save to database
        scan_record = ScanRecord(
            url=body.url,
            risk_score=report["risk_score"],
            status=report["status"],
            ml_prediction=report["ml_prediction"],
            ml_confidence=report["ml_confidence"],
            domain_age_days=report.get("domain_age_days"),
            ssl_valid=report.get("ssl_valid"),
            impersonation_risk=report.get("impersonation_risk", False),
            suspicious_keywords=json.dumps(report.get("suspicious_keywords", [])),
            ip_address=request.client.host if request.client else None,
            device_id=body.device_id,
            response_json=json.dumps(report, default=str),
        )
        session.add(scan_record)
        await session.commit()

        return ThreatReport(
            url=report["url"],
            risk_score=report["risk_score"],
            status=report["status"],
            risk_level=report.get("risk_level", report["status"]),
            confidence=report["confidence"],
            ml_prediction=report["ml_prediction"],
            ml_confidence=report["ml_confidence"],
            domain_age_days=report.get("domain_age_days"),
            ssl_valid=report.get("ssl_valid"),
            ssl_issuer=report.get("ssl_issuer"),
            ssl_expiry=report.get("ssl_expiry"),
            impersonation_risk=report.get("impersonation_risk", False),
            impersonation_target=report.get("impersonation_target"),
            suspicious_keywords=report.get("suspicious_keywords", []),
            url_features=report.get("url_features"),
            google_safe_browsing=report.get("google_safe_browsing"),
            redirect_count=report.get("redirect_count", 0),
            final_url=report.get("final_url"),
            threat_summary=report.get("threat_summary"),
            recommendations=report.get("recommendations", []),
            scanned_at=report["scanned_at"],
        )

    except Exception as e:
        logger.error(f"Error scanning URL {body.url}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}",
        )


@app.get("/scan-history", response_model=ScanHistoryResponse, tags=["History"])
@limiter.limit(settings.RATE_LIMIT)
async def get_scan_history(
    request: Request,
    limit: int = 50,
    offset: int = 0,
    device_id: str = None,
    session: AsyncSession = Depends(get_session),
    api_key: str = Depends(verify_api_key),
):
    """
    Get scan history, optionally filtered by device ID.
    """
    try:
        query = select(ScanRecord).order_by(desc(ScanRecord.scanned_at))

        if device_id:
            query = query.where(ScanRecord.device_id == device_id)

        query = query.offset(offset).limit(limit)
        result = await session.execute(query)
        records = result.scalars().all()

        # Get total count
        from sqlalchemy import func
        count_query = select(func.count(ScanRecord.id))
        if device_id:
            count_query = count_query.where(ScanRecord.device_id == device_id)
        count_result = await session.execute(count_query)
        total = count_result.scalar()

        history_items = [
            ScanHistoryItem(
                id=r.id,
                url=r.url,
                risk_score=r.risk_score,
                status=r.status,
                scanned_at=r.scanned_at,
            )
            for r in records
        ]

        return ScanHistoryResponse(total=total, records=history_items)

    except Exception as e:
        logger.error(f"Error fetching scan history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scan/{scan_id}", tags=["History"])
@limiter.limit(settings.RATE_LIMIT)
async def get_scan_detail(
    request: Request,
    scan_id: int,
    session: AsyncSession = Depends(get_session),
    api_key: str = Depends(verify_api_key),
):
    """Get detailed scan result by ID."""
    try:
        result = await session.execute(
            select(ScanRecord).where(ScanRecord.id == scan_id)
        )
        record = result.scalar_one_or_none()

        if not record:
            raise HTTPException(status_code=404, detail="Scan record not found")

        if record.response_json:
            return json.loads(record.response_json)

        return {
            "id": record.id,
            "url": record.url,
            "risk_score": record.risk_score,
            "status": record.status,
            "ml_prediction": record.ml_prediction,
            "domain_age_days": record.domain_age_days,
            "ssl_valid": record.ssl_valid,
            "impersonation_risk": record.impersonation_risk,
            "suspicious_keywords": json.loads(record.suspicious_keywords or "[]"),
            "scanned_at": record.scanned_at.isoformat(),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching scan detail: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ========== ERROR HANDLERS ==========


@app.exception_handler(422)
async def validation_exception_handler(request: Request, exc):
    return JSONResponse(
        status_code=422,
        content={
            "error": "Validation Error",
            "detail": "Invalid URL format. Please provide a valid URL.",
        },
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
    )
