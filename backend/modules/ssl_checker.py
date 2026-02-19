"""
SSL Validation Module
Checks SSL certificate validity, issuer, and expiry.
"""
import ssl
import socket
from datetime import datetime
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


class SSLChecker:
    """Validates SSL certificates for domains."""

    @staticmethod
    async def check(domain: str, port: int = 443) -> Dict[str, Any]:
        """
        Check SSL certificate for a domain.
        Returns validity, issuer, expiry, and risk contribution.
        """
        result = {
            "ssl_valid": None,
            "ssl_issuer": None,
            "ssl_expiry": None,
            "ssl_self_signed": None,
            "ssl_days_until_expiry": None,
            "risk_contribution": 0.0,
            "error": None,
        }

        try:
            # Remove port if present in domain
            clean_domain = domain.split(":")[0]
            if clean_domain.startswith("www."):
                clean_domain_no_www = clean_domain[4:]
            else:
                clean_domain_no_www = clean_domain

            context = ssl.create_default_context()
            with socket.create_connection((clean_domain, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                    cert = ssock.getpeercert()

                    # Check validity
                    result["ssl_valid"] = True

                    # Get issuer
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    result["ssl_issuer"] = issuer.get("organizationName", "Unknown")

                    # Check if self-signed
                    subject = dict(x[0] for x in cert.get("subject", []))
                    result["ssl_self_signed"] = (
                        issuer.get("organizationName") == subject.get("organizationName")
                        and issuer.get("commonName") == subject.get("commonName")
                    )

                    # Get expiry date
                    not_after = cert.get("notAfter")
                    if not_after:
                        expiry_date = datetime.strptime(
                            not_after, "%b %d %H:%M:%S %Y %Z"
                        )
                        result["ssl_expiry"] = expiry_date.isoformat()
                        days_left = (expiry_date - datetime.utcnow()).days
                        result["ssl_days_until_expiry"] = days_left

                        # Risk based on SSL
                        if days_left < 0:
                            result["ssl_valid"] = False
                            result["risk_contribution"] = 20.0
                        elif days_left < 30:
                            result["risk_contribution"] = 10.0
                        elif result["ssl_self_signed"]:
                            result["risk_contribution"] = 15.0
                        else:
                            result["risk_contribution"] = 0.0

        except ssl.SSLCertVerificationError as e:
            logger.warning(f"SSL verification failed for {domain}: {e}")
            result["ssl_valid"] = False
            result["error"] = "SSL certificate verification failed"
            result["risk_contribution"] = 25.0

        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
            logger.warning(f"SSL connection failed for {domain}: {e}")
            result["ssl_valid"] = False
            result["error"] = f"Connection failed: {type(e).__name__}"
            result["risk_contribution"] = 15.0

        except Exception as e:
            logger.error(f"SSL check error for {domain}: {e}")
            result["error"] = str(e)
            result["risk_contribution"] = 10.0

        return result
