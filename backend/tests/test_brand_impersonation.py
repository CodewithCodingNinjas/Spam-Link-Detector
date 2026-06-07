"""
Tests for brand-impersonation detection and the risk-engine override contract.

The risk engine's high-confidence override reads brand_result["similarity_score"]
on a 0-100 scale. These tests pin that key name and scale so the override (which
was previously dead code due to a wrong key name) cannot silently break again.
"""
import pytest

from modules.brand_impersonation import BrandImpersonationDetector


@pytest.fixture(scope="module")
def det():
    return BrandImpersonationDetector()


async def test_legit_brand_not_flagged(det):
    r = await det.analyze("https://www.paypal.com/signin")
    assert r["impersonation_risk"] is False


async def test_lookalike_domain_flagged(det):
    r = await det.analyze("http://paypal-secure-verify.com/login")
    assert r["impersonation_risk"] is True
    assert r["impersonation_target"] is not None


async def test_result_exposes_similarity_score_key(det):
    """Risk engine override depends on this exact key + 0-100 scale."""
    r = await det.analyze("http://paytm-login-verify.tk/account")
    assert "similarity_score" in r
    assert 0.0 <= r["similarity_score"] <= 100.0
    # The wrong key the buggy override used must NOT be what we rely on.
    assert "impersonation_similarity" not in r


async def test_high_similarity_triggers_strong_contribution(det):
    r = await det.analyze("http://gooogle-account.com/login")
    if r["impersonation_risk"]:
        assert r["risk_contribution"] >= 15.0
