"""
Final Risk Scoring Engine
Combines all analysis modules into a single weighted risk score.
"""
import asyncio
from datetime import datetime
from typing import Dict, Any, List
from urllib.parse import urlparse
import logging

from modules.url_features import url_feature_extractor
from modules.domain_intel import DomainIntelligence
from modules.ssl_checker import SSLChecker
from modules.brand_impersonation import BrandImpersonationDetector
from modules.safe_browsing import GoogleSafeBrowsing
from ml.predictor import get_predictor

logger = logging.getLogger(__name__)


class RiskScoringEngine:
    """
    Combines ML predictions with rule-based threat intelligence
    to produce a final risk score (0-100).
    """

    # Weight configuration for different risk factors
    WEIGHTS = {
        "ml_prediction": 0.35,       # ML model weight
        "domain_age": 0.15,          # Domain age check weight
        "ssl_check": 0.10,           # SSL validation weight
        "brand_impersonation": 0.15, # Impersonation detection weight
        "url_features": 0.10,        # URL structural features weight
        "safe_browsing": 0.15,       # Google Safe Browsing weight
    }

    def __init__(self):
        self.domain_intel = DomainIntelligence()
        self.ssl_checker = SSLChecker()
        self.brand_detector = BrandImpersonationDetector()
        self.safe_browsing = GoogleSafeBrowsing()
        self.predictor = get_predictor()

    async def analyze(self, url: str) -> Dict[str, Any]:
        """
        Perform complete threat analysis on a URL.
        
        Returns a comprehensive threat report.
        """
        logger.info(f"Starting analysis for: {url}")

        # Extract domain
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split("/")[0]
        domain = domain.split(":")[0]

        # Step 1: Extract URL features
        url_features = url_feature_extractor.extract(url)
        numeric_features = url_feature_extractor.extract_numeric_features(url)

        # Step 2: ML Prediction
        ml_result = self.predictor.predict(numeric_features)

        # Step 3: Run all async checks in parallel
        domain_task = self.domain_intel.analyze(
            DomainIntelligence.get_domain_from_url(url)
        )
        ssl_task = self.ssl_checker.check(domain)
        brand_task = self.brand_detector.analyze(url)
        safe_browsing_task = self.safe_browsing.check(url)

        domain_result, ssl_result, brand_result, sb_result = await asyncio.gather(
            domain_task, ssl_task, brand_task, safe_browsing_task,
            return_exceptions=True,
        )

        # Handle exceptions in parallel tasks
        if isinstance(domain_result, Exception):
            logger.error(f"Domain intel error: {domain_result}")
            domain_result = {"risk_contribution": 10.0, "domain_age_days": None, "error": str(domain_result)}
        if isinstance(ssl_result, Exception):
            logger.error(f"SSL check error: {ssl_result}")
            ssl_result = {"risk_contribution": 10.0, "ssl_valid": None, "error": str(ssl_result)}
        if isinstance(brand_result, Exception):
            logger.error(f"Brand detection error: {brand_result}")
            brand_result = {"risk_contribution": 0.0, "impersonation_risk": False, "error": str(brand_result)}
        if isinstance(sb_result, Exception):
            logger.error(f"Safe browsing error: {sb_result}")
            sb_result = {"risk_contribution": 0.0, "safe_browsing_status": "error"}

        # Step 4: Calculate component scores (0-100 each)
        ml_score = ml_result["probability"] * 100
        domain_score = min(domain_result.get("risk_contribution", 0) * 3.33, 100)
        ssl_score = min(ssl_result.get("risk_contribution", 0) * 4, 100)
        brand_score = min(brand_result.get("risk_contribution", 0) * 4, 100)
        url_feature_score = self._calculate_url_feature_score(url_features)
        sb_score = min(sb_result.get("risk_contribution", 0) * 2.86, 100)

        # Step 5: Weighted final score
        final_score = (
            ml_score * self.WEIGHTS["ml_prediction"]
            + domain_score * self.WEIGHTS["domain_age"]
            + ssl_score * self.WEIGHTS["ssl_check"]
            + brand_score * self.WEIGHTS["brand_impersonation"]
            + url_feature_score * self.WEIGHTS["url_features"]
            + sb_score * self.WEIGHTS["safe_browsing"]
        )

        # Clamp to 0-100
        final_score = round(min(max(final_score, 0), 100), 1)

        # Determine status
        if final_score >= 70:
            status = "Phishing"
        elif final_score >= 40:
            status = "Suspicious"
        else:
            status = "Safe"

        # Calculate overall confidence
        confidence = round(ml_result.get("confidence", 50.0), 1)

        # Generate recommendations
        recommendations = self._generate_recommendations(
            final_score, status, ml_result, domain_result,
            ssl_result, brand_result, url_features,
        )

        # Build response
        report = {
            "url": url,
            "risk_score": final_score,
            "status": status,
            "confidence": confidence,
            "ml_prediction": ml_result["prediction"],
            "ml_confidence": round(ml_result["confidence"], 1),
            "domain_age_days": domain_result.get("domain_age_days"),
            "ssl_valid": ssl_result.get("ssl_valid"),
            "ssl_issuer": ssl_result.get("ssl_issuer"),
            "ssl_expiry": ssl_result.get("ssl_expiry"),
            "impersonation_risk": brand_result.get("impersonation_risk", False),
            "impersonation_target": brand_result.get("impersonation_target"),
            "suspicious_keywords": url_features.get("found_keywords", []),
            "url_features": {
                "url_length": url_features["url_length"],
                "has_https": bool(url_features["has_https"]),
                "has_ip_address": bool(url_features["has_ip_address"]),
                "num_subdomains": url_features["num_subdomains"],
                "is_suspicious_tld": bool(url_features["is_suspicious_tld"]),
                "is_shortened": bool(url_features["is_shortened"]),
                "suspicious_keyword_count": url_features["suspicious_keyword_count"],
            },
            "google_safe_browsing": sb_result.get("safe_browsing_status"),
            "recommendations": recommendations,
            "scanned_at": datetime.utcnow().isoformat(),
            # Component scores for transparency
            "_component_scores": {
                "ml_score": round(ml_score, 1),
                "domain_score": round(domain_score, 1),
                "ssl_score": round(ssl_score, 1),
                "brand_score": round(brand_score, 1),
                "url_feature_score": round(url_feature_score, 1),
                "safe_browsing_score": round(sb_score, 1),
            },
        }

        logger.info(f"Analysis complete: {url} -> {status} (score: {final_score})")
        return report

    def _calculate_url_feature_score(self, features: Dict[str, Any]) -> float:
        """Calculate risk score from URL structural features (0-100)."""
        score = 0.0

        # Long URL
        if features["url_length"] > 75:
            score += 15
        if features["url_length"] > 100:
            score += 10

        # No HTTPS
        if not features["has_https"]:
            score += 15

        # IP address in URL
        if features["has_ip_address"]:
            score += 20

        # @ symbol
        if features["has_at_symbol"]:
            score += 15

        # Suspicious keywords
        score += min(features["suspicious_keyword_count"] * 5, 20)

        # Suspicious TLD
        if features["is_suspicious_tld"]:
            score += 15

        # Many subdomains
        if features["num_subdomains"] > 2:
            score += 10

        # Shortened URL
        if features["is_shortened"]:
            score += 10

        # Double slash redirect
        if features["has_double_slash_redirect"]:
            score += 10

        return min(score, 100)

    def _generate_recommendations(
        self, score, status, ml_result, domain_result,
        ssl_result, brand_result, url_features,
    ) -> List[str]:
        """Generate human-readable security recommendations."""
        recs = []

        if status == "Phishing":
            recs.append("⚠️ DO NOT click this link! It has been identified as likely phishing.")
            recs.append("🔒 Never enter personal information on this website.")

        if status == "Suspicious":
            recs.append("⚠️ Exercise caution with this link. It shows some suspicious indicators.")

        if brand_result.get("impersonation_risk"):
            target = brand_result.get("impersonation_target", "a known brand")
            recs.append(f"🎭 This URL may be impersonating {target}. Verify by visiting the official website directly.")

        if domain_result.get("is_new_domain"):
            days = domain_result.get("domain_age_days", "unknown")
            recs.append(f"🆕 This domain was registered only {days} days ago. New domains are often used in scams.")

        if ssl_result.get("ssl_valid") is False:
            recs.append("🔓 This website does not have a valid SSL certificate. Your data may not be encrypted.")

        if not url_features.get("has_https"):
            recs.append("🔓 This URL uses HTTP instead of HTTPS. Connection is not secure.")

        if url_features.get("has_ip_address"):
            recs.append("🌐 This URL uses an IP address instead of a domain name, which is unusual for legitimate sites.")

        if url_features.get("is_shortened"):
            recs.append("🔗 This is a shortened URL. The actual destination is hidden.")

        if url_features.get("suspicious_keyword_count", 0) > 2:
            recs.append("🔑 This URL contains multiple suspicious keywords commonly used in phishing attacks.")

        if status == "Safe":
            recs.append("✅ This URL appears to be safe based on our analysis.")
            recs.append("ℹ️ Always verify the sender's identity before clicking links from unknown sources.")

        return recs


# Singleton
risk_engine = RiskScoringEngine()
