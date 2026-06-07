"""
Unit tests for URLFeatureExtractor.

Critical invariant under test: the numeric feature vector length MUST equal
len(get_feature_names()). A mismatch here is exactly the bug that previously
caused the trained model (27 features) to silently fail against a 31-feature
inference vector and fall back to rules.
"""
import math
import pytest

from modules.url_features import URLFeatureExtractor


@pytest.fixture(scope="module")
def ex():
    return URLFeatureExtractor()


def test_feature_vector_length_matches_names(ex):
    names = URLFeatureExtractor.get_feature_names()
    vec = ex.extract_numeric_features("https://example.com/path?a=1")
    assert len(vec) == len(names), (
        f"feature vector ({len(vec)}) != feature names ({len(names)}); "
        "this mismatch silently disables the ML model at inference time"
    )


def test_feature_vector_is_all_numeric(ex):
    vec = ex.extract_numeric_features("https://example.com/login")
    assert all(isinstance(v, (int, float)) for v in vec)


def test_https_and_ip_detection(ex):
    f = ex.extract("https://93.184.216.34/login")
    assert f["has_https"] == 1
    assert f["has_ip_address"] == 1


def test_http_no_https_flag(ex):
    f = ex.extract("http://example.com")
    assert f["has_https"] == 0


def test_punycode_homograph_flag(ex):
    f = ex.extract("http://xn--pple-43d.com")  # 'аpple' homograph
    assert f["has_punycode"] == 1


def test_suspicious_tld_and_keywords(ex):
    f = ex.extract("http://secure-verify-login.tk/account/update")
    assert f["is_suspicious_tld"] == 1
    assert f["suspicious_keyword_count"] >= 2
    assert "verify" in f["found_keywords"]


def test_shortener_detection(ex):
    f = ex.extract("https://bit.ly/abc123")
    assert f["is_shortened"] == 1


def test_at_symbol_detection(ex):
    f = ex.extract("http://user@evil.com/login")
    assert f["has_at_symbol"] == 1


def test_shannon_entropy_bounds(ex):
    f = ex.extract("https://example.com")
    assert 0.0 <= f["shannon_entropy"] <= 8.0  # bits/char never exceeds log2(alphabet)


def test_empty_pathological_url_does_not_crash(ex):
    vec = ex.extract_numeric_features("http://a")
    assert len(vec) == len(URLFeatureExtractor.get_feature_names())
