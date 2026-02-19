"""
Brand Impersonation Detection Module
Detects if a URL is trying to impersonate a known brand using fuzzy matching.
"""
from rapidfuzz import fuzz, process
from urllib.parse import urlparse
from typing import Dict, Any, Optional, Tuple
import re
import logging

from config import settings

logger = logging.getLogger(__name__)


class BrandImpersonationDetector:
    """Detects brand impersonation in URLs using fuzzy matching."""

    def __init__(self):
        self.known_brands = settings.KNOWN_BRANDS
        self.brand_names = [b.split(".")[0] for b in self.known_brands]
        self.similarity_threshold = 75  # Percent similarity to trigger

    async def analyze(self, url: str) -> Dict[str, Any]:
        """
        Check if the URL domain is trying to impersonate a known brand.
        
        Examples:
            paytm-offer-verify-login.com → impersonating paytm.com
            g00gle-login.com → impersonating google.com
        """
        result = {
            "impersonation_risk": False,
            "impersonation_target": None,
            "similarity_score": 0.0,
            "risk_contribution": 0.0,
            "details": None,
        }

        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path.split("/")[0]
            domain = domain.split(":")[0].lower()

            # Remove www prefix
            if domain.startswith("www."):
                domain = domain[4:]

            # Check if it's exactly a known brand (safe)
            if domain in [b.lower() for b in self.known_brands]:
                return result

            # Extract the main part of the domain (without TLD)
            domain_parts = domain.split(".")
            if len(domain_parts) < 2:
                return result

            # Get the domain name without TLD
            domain_name = ".".join(domain_parts[:-1]) if len(domain_parts) > 1 else domain_parts[0]

            # Check each segment of the domain
            # Split by hyphens and dots to check individual parts
            segments = re.split(r"[-._]", domain_name)

            best_match = None
            best_score = 0.0

            for segment in segments:
                if len(segment) < 3:
                    continue

                # Check against known brand names
                match = process.extractOne(
                    segment,
                    self.brand_names,
                    scorer=fuzz.ratio,
                    score_cutoff=self.similarity_threshold,
                )

                if match and match[1] > best_score:
                    best_match = match
                    best_score = match[1]

            # Also check the full domain name against brands
            full_match = process.extractOne(
                domain_name.replace("-", "").replace("_", ""),
                self.brand_names,
                scorer=fuzz.partial_ratio,
                score_cutoff=self.similarity_threshold,
            )

            if full_match and full_match[1] > best_score:
                best_match = full_match
                best_score = full_match[1]

            # Check for common letter substitutions (homoglyph attacks)
            cleaned_domain = self._normalize_homoglyphs(domain_name)
            homo_match = process.extractOne(
                cleaned_domain.replace("-", "").replace("_", ""),
                self.brand_names,
                scorer=fuzz.ratio,
                score_cutoff=self.similarity_threshold,
            )

            if homo_match and homo_match[1] > best_score:
                best_match = homo_match
                best_score = homo_match[1]

            if best_match and best_score >= self.similarity_threshold:
                brand_index = self.brand_names.index(best_match[0])
                target_brand = self.known_brands[brand_index]

                # Only flag if it's NOT the actual brand domain
                if domain != target_brand.lower():
                    result["impersonation_risk"] = True
                    result["impersonation_target"] = target_brand
                    result["similarity_score"] = round(best_score, 2)
                    result["details"] = (
                        f"Domain '{domain}' appears to impersonate '{target_brand}' "
                        f"(similarity: {best_score:.1f}%)"
                    )

                    # Risk contribution based on similarity
                    if best_score >= 90:
                        result["risk_contribution"] = 25.0
                    elif best_score >= 80:
                        result["risk_contribution"] = 20.0
                    else:
                        result["risk_contribution"] = 15.0

        except Exception as e:
            logger.error(f"Brand impersonation check error: {e}")

        return result

    @staticmethod
    def _normalize_homoglyphs(text: str) -> str:
        """Replace common homoglyph characters with their ASCII equivalents."""
        replacements = {
            "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
            "7": "t", "8": "b", "@": "a", "$": "s", "!": "i",
            "|": "l", "ph": "f", "ш": "w", "а": "a", "е": "e",
            "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
        }
        result = text.lower()
        for old, new in replacements.items():
            result = result.replace(old, new)
        return result


# Singleton
brand_detector = BrandImpersonationDetector()
