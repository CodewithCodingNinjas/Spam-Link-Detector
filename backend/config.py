"""
AI Real-Time Scam Link Detector - Configuration
"""
import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    # Server
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"

    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", "sqlite+aiosqlite:///./scamdetector.db"
    )

    # API Security
    API_KEY: str = os.getenv("API_KEY", "dev-api-key-change-me")
    RATE_LIMIT: str = os.getenv("RATE_LIMIT", "30/minute")

    # Google Safe Browsing
    GOOGLE_SAFE_BROWSING_API_KEY: str = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")

    # ML Model paths
    ML_MODEL_PATH: str = os.getenv("ML_MODEL_PATH", "ml/model/phishing_model.joblib")
    ML_VECTORIZER_PATH: str = os.getenv(
        "ML_VECTORIZER_PATH", "ml/model/feature_vectorizer.joblib"
    )

    # CORS
    CORS_ORIGINS: list = os.getenv("CORS_ORIGINS", "*").split(",")

    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # Brand list for impersonation detection
    KNOWN_BRANDS: list = [
        "google.com", "facebook.com", "amazon.com", "apple.com",
        "microsoft.com", "paypal.com", "netflix.com", "instagram.com",
        "twitter.com", "linkedin.com", "whatsapp.com", "telegram.org",
        "paytm.com", "phonepe.com", "gpay.com", "sbi.co.in",
        "icicibank.com", "hdfcbank.com", "axisbank.com", "flipkart.com",
        "myntra.com", "snapdeal.com", "zomato.com", "swiggy.com",
        "ola.com", "uber.com", "razorpay.com", "stripe.com",
        "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
        "dropbox.com", "github.com", "stackoverflow.com", "reddit.com",
        "yahoo.com", "outlook.com", "hotmail.com", "gmail.com",
    ]

    # Suspicious keywords
    SUSPICIOUS_KEYWORDS: list = [
        "verify", "login", "update", "secure", "account", "banking",
        "confirm", "password", "suspend", "unusual", "activity",
        "click", "urgent", "immediately", "expire", "limited",
        "offer", "free", "prize", "winner", "congratulations",
        "claim", "reward", "gift", "bonus", "discount",
        "wallet", "transfer", "payment", "invoice", "receipt",
        "signin", "signup", "authenticate", "credential", "token",
        "otp", "verification", "validate", "unlock", "restore",
    ]


settings = Settings()
