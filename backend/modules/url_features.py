"""
URL Feature Extraction Module
Extracts structural features from URLs for ML model and rule-based analysis.
"""
import re
from urllib.parse import urlparse
from typing import Dict, Any
from config import settings


class URLFeatureExtractor:
    """Extracts numerical and categorical features from a URL."""

    def __init__(self):
        self.suspicious_keywords = settings.SUSPICIOUS_KEYWORDS

    def extract(self, url: str) -> Dict[str, Any]:
        """Extract all features from a URL string."""
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split("/")[0]
        path = parsed.path or ""
        full_url = url.lower()

        features = {
            # Length-based features
            "url_length": len(url),
            "domain_length": len(domain),
            "path_length": len(path),

            # Count-based features
            "num_dots": url.count("."),
            "num_hyphens": url.count("-"),
            "num_underscores": url.count("_"),
            "num_slashes": url.count("/"),
            "num_question_marks": url.count("?"),
            "num_equals": url.count("="),
            "num_ampersands": url.count("&"),
            "num_at_symbols": url.count("@"),
            "num_special_chars": len(re.findall(r"[^a-zA-Z0-9./:?=&_-]", url)),
            "num_digits_in_domain": len(re.findall(r"\d", domain)),
            "num_subdomains": max(0, domain.count(".") - 1),

            # Boolean features
            "has_https": 1 if parsed.scheme == "https" else 0,
            "has_ip_address": 1 if self._has_ip(domain) else 0,
            "has_at_symbol": 1 if "@" in url else 0,
            "has_double_slash_redirect": 1 if "//" in url[8:] else 0,
            "has_port": 1 if parsed.port and parsed.port not in [80, 443] else 0,
            "has_hex_encoding": 1 if "%" in url else 0,

            # Keyword-based features
            "suspicious_keyword_count": self._count_suspicious_keywords(full_url),
            "has_suspicious_keywords": 1 if self._count_suspicious_keywords(full_url) > 0 else 0,
            "found_keywords": self._get_suspicious_keywords(full_url),

            # Entropy & ratios
            "digit_ratio": self._digit_ratio(url),
            "special_char_ratio": self._special_char_ratio(url),

            # TLD analysis
            "tld": self._get_tld(domain),
            "is_suspicious_tld": 1 if self._get_tld(domain) in [
                ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
                ".buzz", ".club", ".work", ".info", ".click", ".link",
                ".icu", ".cam", ".rest", ".monster",
            ] else 0,

            # URL contains common phishing patterns
            "has_login_form_pattern": 1 if re.search(
                r"(login|signin|verify|auth|secure|account|update|confirm)", full_url
            ) else 0,

            # Shortener detection
            "is_shortened": 1 if self._is_shortened_url(domain) else 0,
        }

        return features

    def extract_numeric_features(self, url: str) -> list:
        """Extract only numeric features for ML model input."""
        features = self.extract(url)
        numeric_keys = [
            "url_length", "domain_length", "path_length",
            "num_dots", "num_hyphens", "num_underscores",
            "num_slashes", "num_question_marks", "num_equals",
            "num_ampersands", "num_at_symbols", "num_special_chars",
            "num_digits_in_domain", "num_subdomains",
            "has_https", "has_ip_address", "has_at_symbol",
            "has_double_slash_redirect", "has_port", "has_hex_encoding",
            "suspicious_keyword_count", "has_suspicious_keywords",
            "digit_ratio", "special_char_ratio",
            "is_suspicious_tld", "has_login_form_pattern", "is_shortened",
        ]
        return [features[k] for k in numeric_keys]

    @staticmethod
    def get_feature_names() -> list:
        """Return the ordered list of numeric feature names."""
        return [
            "url_length", "domain_length", "path_length",
            "num_dots", "num_hyphens", "num_underscores",
            "num_slashes", "num_question_marks", "num_equals",
            "num_ampersands", "num_at_symbols", "num_special_chars",
            "num_digits_in_domain", "num_subdomains",
            "has_https", "has_ip_address", "has_at_symbol",
            "has_double_slash_redirect", "has_port", "has_hex_encoding",
            "suspicious_keyword_count", "has_suspicious_keywords",
            "digit_ratio", "special_char_ratio",
            "is_suspicious_tld", "has_login_form_pattern", "is_shortened",
        ]

    def _count_suspicious_keywords(self, url: str) -> int:
        return sum(1 for kw in self.suspicious_keywords if kw in url)

    def _get_suspicious_keywords(self, url: str) -> list:
        return [kw for kw in self.suspicious_keywords if kw in url]

    @staticmethod
    def _has_ip(domain: str) -> bool:
        ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        return bool(ip_pattern.match(domain.split(":")[0]))

    @staticmethod
    def _digit_ratio(url: str) -> float:
        if len(url) == 0:
            return 0.0
        return len(re.findall(r"\d", url)) / len(url)

    @staticmethod
    def _special_char_ratio(url: str) -> float:
        if len(url) == 0:
            return 0.0
        return len(re.findall(r"[^a-zA-Z0-9]", url)) / len(url)

    @staticmethod
    def _get_tld(domain: str) -> str:
        parts = domain.split(".")
        if len(parts) >= 2:
            return "." + parts[-1]
        return ""

    @staticmethod
    def _is_shortened_url(domain: str) -> bool:
        shorteners = [
            "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
            "is.gd", "buff.ly", "adf.ly", "bit.do", "mcaf.ee",
            "su.pr", "tiny.cc", "cutt.ly", "rb.gy", "shorturl.at",
            "v.gd", "qr.ae", "lnkd.in", "db.tt", "j.mp",
        ]
        return domain.lower() in shorteners


# Singleton
url_feature_extractor = URLFeatureExtractor()
