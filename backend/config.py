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
        # Global tech
        "google.com", "facebook.com", "amazon.com", "apple.com",
        "microsoft.com", "paypal.com", "netflix.com", "instagram.com",
        "twitter.com", "x.com", "linkedin.com", "whatsapp.com",
        "telegram.org", "discord.com", "tiktok.com", "youtube.com",
        "twitch.tv", "spotify.com", "adobe.com", "zoom.us",
        # Indian fintech / banking
        "paytm.com", "phonepe.com", "gpay.com", "sbi.co.in",
        "icicibank.com", "hdfcbank.com", "axisbank.com", "kotak.com",
        "yesbank.in", "pnbnet.in", "bankofbaroda.in", "canarabank.in",
        "upi.npci.org.in", "bhimupi.org.in",
        # Indian e-commerce
        "flipkart.com", "myntra.com", "snapdeal.com", "meesho.com",
        "nykaa.com", "bigbasket.com", "blinkit.com",
        # Indian utility
        "zomato.com", "swiggy.com", "ola.com", "uber.com",
        "irctc.co.in", "makemytrip.com", "goibibo.com", "ixigo.com",
        # Global fintech
        "razorpay.com", "stripe.com", "wise.com", "cashapp.com",
        "venmo.com", "skrill.com", "coinbase.com", "binance.com",
        # US banking
        "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
        "usbank.com", "capitalone.com", "tdbank.com",
        # Dev / productivity
        "dropbox.com", "github.com", "gitlab.com", "stackoverflow.com",
        "reddit.com", "notion.so", "atlassian.com", "slack.com",
        # Email
        "yahoo.com", "outlook.com", "hotmail.com", "gmail.com",
        "protonmail.com", "icloud.com",
        # Delivery / logistics
        "fedex.com", "dhl.com", "ups.com", "dtdc.com", "bluedart.com",
        # Government (India)
        "incometax.gov.in", "uidai.gov.in", "mca.gov.in",
        "india.gov.in", "digilocker.gov.in",
    ]

    # Suspicious TLDs
    SUSPICIOUS_TLDS: list = [
        ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
        ".buzz", ".club", ".work", ".info", ".click", ".link",
        ".icu", ".cam", ".rest", ".monster",
        ".ru", ".cn", ".pw", ".cc", ".su",
        ".cyou", ".cfd", ".sbs", ".hair", ".autos",
        ".realty", ".lat", ".vip",
    ]

    # Suspicious keywords
    SUSPICIOUS_KEYWORDS: list = [
        # Auth / account
        "verify", "login", "signin", "signup", "update", "secure",
        "account", "banking", "confirm", "password", "suspend",
        "unusual", "activity", "authenticate", "credential", "token",
        "otp", "verification", "validate", "unlock", "restore",
        "2fa", "mfa", "reset", "recover",
        # Urgency
        "click", "urgent", "immediately", "expire", "limited",
        "action-required", "act-now", "last-chance", "24hours",
        "blocked", "suspended", "restricted", "disabled",
        # Reward / prize
        "offer", "free", "prize", "winner", "congratulations",
        "claim", "reward", "gift", "bonus", "discount",
        "cashback", "rebate", "lottery", "jackpot", "lucky",
        # Financial
        "wallet", "transfer", "payment", "invoice", "receipt",
        "refund", "kyc", "aadhar", "pan-update", "billing",
        "subscription", "autopay", "emi",
        # Delivery scam
        "parcel", "shipment", "package", "tracking", "delivery",
        "customs", "courier",
        # Tech support
        "support", "helpdesk", "customer-care", "toll-free",
        "technician", "virus", "malware",
    ]


settings = Settings()
