"""
AI Real-Time Scam Link Detector - Database Models
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from config import settings

Base = declarative_base()

# Async engine
engine = create_async_engine(settings.DATABASE_URL, echo=settings.DEBUG)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class ScanRecord(Base):
    """Stores scan history in the database."""
    __tablename__ = "scan_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(Text, nullable=False, index=True)
    risk_score = Column(Float, nullable=False)
    status = Column(String(20), nullable=False)  # Safe / Suspicious / Phishing
    ml_prediction = Column(String(20), nullable=True)
    ml_confidence = Column(Float, nullable=True)
    domain_age_days = Column(Integer, nullable=True)
    ssl_valid = Column(Boolean, nullable=True)
    impersonation_risk = Column(Boolean, default=False)
    suspicious_keywords = Column(Text, nullable=True)  # JSON string
    ip_address = Column(String(45), nullable=True)
    device_id = Column(String(100), nullable=True)
    scanned_at = Column(DateTime, default=datetime.utcnow)
    response_json = Column(Text, nullable=True)  # Full response JSON


async def init_db():
    """Create database tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_session() -> AsyncSession:
    """Dependency for getting async session."""
    async with async_session() as session:
        yield session
