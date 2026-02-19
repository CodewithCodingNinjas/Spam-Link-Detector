"""
Domain Intelligence Module
Checks domain age, registration info using WHOIS.
"""
import whois
from datetime import datetime
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class DomainIntelligence:
    """Performs WHOIS lookups and domain age analysis."""

    @staticmethod
    async def analyze(domain: str) -> Dict[str, Any]:
        """
        Analyze domain registration info.
        Returns domain age, registrar, creation date, etc.
        """
        result = {
            "domain": domain,
            "domain_age_days": None,
            "creation_date": None,
            "expiration_date": None,
            "registrar": None,
            "is_new_domain": None,
            "risk_contribution": 0.0,
            "error": None,
        }

        try:
            w = whois.whois(domain)

            # Get creation date
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                age_delta = datetime.utcnow() - creation_date
                result["domain_age_days"] = age_delta.days
                result["creation_date"] = creation_date.isoformat()
                result["is_new_domain"] = age_delta.days < 90

                # Risk contribution based on domain age
                if age_delta.days < 30:
                    result["risk_contribution"] = 30.0
                elif age_delta.days < 90:
                    result["risk_contribution"] = 20.0
                elif age_delta.days < 180:
                    result["risk_contribution"] = 10.0
                elif age_delta.days < 365:
                    result["risk_contribution"] = 5.0
                else:
                    result["risk_contribution"] = 0.0

            # Get expiration date
            expiration_date = w.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if expiration_date:
                result["expiration_date"] = expiration_date.isoformat()

            # Get registrar
            result["registrar"] = w.registrar

        except Exception as e:
            logger.warning(f"WHOIS lookup failed for {domain}: {e}")
            result["error"] = str(e)
            # If WHOIS fails, it might be a suspicious domain
            result["risk_contribution"] = 15.0

        return result

    @staticmethod
    def get_domain_from_url(url: str) -> str:
        """Extract the registrable domain from a URL."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split("/")[0]
        # Remove port if present
        domain = domain.split(":")[0]
        # Remove www prefix
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
