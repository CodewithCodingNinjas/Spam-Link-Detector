"""
Google Safe Browsing API Module (Optional)
Cross-checks URLs against Google's threat database.
"""
import httpx
from typing import Dict, Any
import logging

from config import settings

logger = logging.getLogger(__name__)

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


class GoogleSafeBrowsing:
    """Checks URLs against Google Safe Browsing API."""

    def __init__(self):
        self.api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY
        self.enabled = bool(self.api_key)

    async def check(self, url: str) -> Dict[str, Any]:
        """
        Check URL against Google Safe Browsing.
        Returns threat type if found.
        """
        result = {
            "safe_browsing_status": "unknown",
            "threat_type": None,
            "risk_contribution": 0.0,
            "enabled": self.enabled,
        }

        if not self.enabled:
            result["safe_browsing_status"] = "api_not_configured"
            return result

        try:
            payload = {
                "client": {
                    "clientId": "scam-link-detector",
                    "clientVersion": "1.0.0",
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION",
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }

            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    f"{SAFE_BROWSING_URL}?key={self.api_key}",
                    json=payload,
                )

                if response.status_code == 200:
                    data = response.json()
                    if "matches" in data and data["matches"]:
                        match = data["matches"][0]
                        result["safe_browsing_status"] = "threat_found"
                        result["threat_type"] = match.get("threatType", "UNKNOWN")
                        result["risk_contribution"] = 35.0
                    else:
                        result["safe_browsing_status"] = "safe"
                        result["risk_contribution"] = 0.0
                else:
                    logger.warning(
                        f"Safe Browsing API returned {response.status_code}"
                    )
                    result["safe_browsing_status"] = "api_error"

        except Exception as e:
            logger.error(f"Safe Browsing API error: {e}")
            result["safe_browsing_status"] = "api_error"

        return result


# Singleton
safe_browsing = GoogleSafeBrowsing()
