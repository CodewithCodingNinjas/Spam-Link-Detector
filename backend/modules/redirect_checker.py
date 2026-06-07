"""
Redirect Chain Checker Module
Follows HTTP redirects up to 10 hops, analyses the chain for risk signals.
"""
import asyncio
import logging
from typing import Dict, Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

MAX_REDIRECTS = 10
REQUEST_TIMEOUT = 8.0


class RedirectChecker:
    """
    Follows redirect chains and evaluates risk based on:
    - Number of redirects (more = riskier)
    - Cross-domain jumps in the chain
    - Final destination differing from origin
    """

    async def check(self, url: str) -> Dict[str, Any]:
        """
        Follow the redirect chain for *url* and return a risk report.

        Returns
        -------
        {
            "redirect_count": int,
            "final_url": str,
            "cross_domain_redirects": int,
            "redirect_chain": [str, ...],
            "risk_contribution": float,   # 0–30
        }
        """
        redirect_chain: list[str] = [url]
        initial_domain = self._extract_domain(url)

        try:
            async with httpx.AsyncClient(
                follow_redirects=False,
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": "Mozilla/5.0 (compatible; ScamDetector/1.0)"},
            ) as client:
                current_url = url
                cross_domain_count = 0

                for _ in range(MAX_REDIRECTS):
                    try:
                        response = await client.get(current_url)
                    except Exception as exc:
                        logger.debug(f"Request error during redirect follow: {exc}")
                        break

                    if response.status_code in (301, 302, 303, 307, 308):
                        next_url = response.headers.get("location", "").strip()
                        if not next_url:
                            break
                        # Resolve relative redirects
                        if next_url.startswith("/"):
                            parsed = urlparse(current_url)
                            next_url = f"{parsed.scheme}://{parsed.netloc}{next_url}"

                        next_domain = self._extract_domain(next_url)
                        current_domain = self._extract_domain(current_url)
                        if next_domain != current_domain:
                            cross_domain_count += 1

                        redirect_chain.append(next_url)
                        current_url = next_url
                    else:
                        break

        except Exception as exc:
            logger.warning(f"RedirectChecker unexpected error for {url}: {exc}")

        final_url = redirect_chain[-1]
        redirect_count = len(redirect_chain) - 1
        final_domain = self._extract_domain(final_url)
        domain_changed = final_domain != initial_domain

        risk = self._score(redirect_count, cross_domain_count, domain_changed)

        return {
            "redirect_count": redirect_count,
            "final_url": final_url,
            "cross_domain_redirects": cross_domain_count,
            "redirect_chain": redirect_chain,
            "domain_changed": domain_changed,
            "risk_contribution": round(risk, 1),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_domain(url: str) -> str:
        try:
            parsed = urlparse(url)
            host = parsed.netloc or url.split("/")[0]
            return host.split(":")[0].lower()
        except Exception:
            return url.lower()

    @staticmethod
    def _score(redirect_count: int, cross_domain: int, domain_changed: bool) -> float:
        """Return a 0–30 risk contribution."""
        score = 0.0

        # Redirect depth
        if redirect_count >= 1:
            score += 5
        if redirect_count >= 3:
            score += 5
        if redirect_count >= 6:
            score += 5

        # Cross-domain hops
        score += min(cross_domain * 5, 15)

        # Final domain differs from initial
        if domain_changed:
            score += 5

        return min(score, 30.0)


# Singleton
redirect_checker = RedirectChecker()
