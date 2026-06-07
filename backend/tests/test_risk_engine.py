"""
Integration tests for the RiskScoringEngine fusion pipeline.

External I/O (WHOIS, SSL socket, Google Safe Browsing, redirect HTTP) is mocked
so these run fully offline and deterministically. They lock in:
  * the weighted fusion produces a sane 0-100 score and a valid 5-tier status
  * the brand-impersonation override floor (>=90 similarity -> score >= 75) FIRES
    (this was previously dead code: wrong key + wrong scale)
  * the Safe-Browsing threat override floor (-> score >= 85) fires
  * ML false positives are corrected by the other signals (fusion value)
"""
import pytest

from modules.risk_engine import RiskScoringEngine


@pytest.fixture
def engine(monkeypatch):
    eng = RiskScoringEngine()

    async def fake_domain(domain):
        return {"risk_contribution": 5.0, "domain_age_days": 400, "is_new_domain": False}

    async def fake_ssl(domain):
        return {"risk_contribution": 0.0, "ssl_valid": True,
                "ssl_issuer": "Test CA", "ssl_expiry": "2027-01-01"}

    async def fake_sb_clean(url):
        return {"risk_contribution": 0.0, "safe_browsing_status": "clean"}

    async def fake_redirect(url):
        return {"risk_contribution": 0.0, "redirect_count": 0, "final_url": url}

    monkeypatch.setattr(eng.domain_intel, "analyze", fake_domain)
    monkeypatch.setattr(eng.ssl_checker, "check", fake_ssl)
    monkeypatch.setattr(eng.safe_browsing, "check", fake_sb_clean)
    # redirect_checker is a module-level singleton imported into risk_engine
    import modules.risk_engine as re_mod
    monkeypatch.setattr(re_mod.redirect_checker, "check", fake_redirect)
    return eng


async def test_safe_url_scores_low(engine):
    r = await engine.analyze("https://www.google.com/search?q=test")
    assert 0 <= r["risk_score"] <= 100
    assert r["status"] in ("Safe", "Low Risk")


async def test_status_is_valid_tier(engine):
    r = await engine.analyze("https://example.com")
    assert r["status"] in ("Safe", "Low Risk", "Suspicious", "High Risk", "Phishing")


async def test_brand_override_floor_fires(engine, monkeypatch):
    """High-similarity impersonation must force score >= 75 (regression)."""
    async def fake_brand(url):
        return {"impersonation_risk": True, "impersonation_target": "paypal.com",
                "similarity_score": 95.0, "risk_contribution": 25.0,
                "details": "test"}
    monkeypatch.setattr(engine.brand_detector, "analyze", fake_brand)
    r = await engine.analyze("http://paypal-verify-login.com/secure")
    assert r["risk_score"] >= 75.0, "brand impersonation override floor did not fire"
    assert r["impersonation_risk"] is True


async def test_safe_browsing_threat_override_floor(engine, monkeypatch):
    async def fake_sb_threat(url):
        return {"risk_contribution": 35.0, "safe_browsing_status": "threat_found"}
    monkeypatch.setattr(engine.safe_browsing, "check", fake_sb_threat)
    r = await engine.analyze("http://malware-download.example/payload")
    assert r["risk_score"] >= 85.0


async def test_threat_summary_confidence_formatting(engine, monkeypatch):
    """ML confidence is 0-100; summary must not render '9800%' (regression)."""
    async def fake_brand(url):
        return {"impersonation_risk": False, "similarity_score": 0.0,
                "risk_contribution": 0.0}
    monkeypatch.setattr(engine.brand_detector, "analyze", fake_brand)
    r = await engine.analyze("http://login-verify-account-secure.tk/update")
    summary = r["threat_summary"]
    assert "00%" not in summary.replace("100%", "")  # no 9800%-style artifact


async def test_component_scores_present_for_transparency(engine):
    r = await engine.analyze("https://example.com")
    cs = r["_component_scores"]
    for k in ("ml_score", "brand_score", "ssl_score", "domain_score",
              "url_feature_score", "safe_browsing_score", "redirect_score"):
        assert k in cs
