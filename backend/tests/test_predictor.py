"""
Tests for the ML predictor and its contract with the feature extractor.

These guard the regression where the saved model's feature count drifted away
from the live extractor's output, silently disabling ML inference.
"""
import pytest

from modules.url_features import URLFeatureExtractor
from ml.predictor import get_predictor


@pytest.fixture(scope="module")
def predictor():
    return get_predictor()


@pytest.fixture(scope="module")
def ex():
    return URLFeatureExtractor()


def test_model_is_loaded(predictor):
    # If this fails, run: python ml/build_dataset.py && python ml/train_model.py
    assert predictor.is_loaded(), "trained model not found; build dataset + train first"


def test_model_feature_count_matches_extractor(predictor):
    """The saved model must accept exactly the live feature-vector width."""
    if not predictor.is_loaded() or not predictor.metadata:
        pytest.skip("model/metadata unavailable")
    n_model = predictor.metadata.get("n_features")
    n_live = len(URLFeatureExtractor.get_feature_names())
    assert n_model == n_live, (
        f"model expects {n_model} features but extractor emits {n_live}"
    )


def test_prediction_shape(predictor, ex):
    vec = ex.extract_numeric_features("https://www.google.com")
    r = predictor.predict(vec)
    assert r["prediction"] in ("Safe", "Phishing", "Unknown")
    assert 0.0 <= r["probability"] <= 1.0
    assert 0.0 <= r["confidence"] <= 100.0


def test_metadata_metrics_are_honest(predictor):
    """Guard against the old synthetic-data signature (AUC == 1.0 exactly)."""
    if not predictor.metadata:
        pytest.skip("no metadata")
    metrics = predictor.metadata.get("test_metrics", {})
    if "roc_auc" in metrics:
        assert metrics["roc_auc"] < 1.0, (
            "AUC of exactly 1.0 is the synthetic-data fingerprint; "
            "retrain on the real dataset"
        )
        assert metrics["accuracy"] < 1.0
    assert "real" in str(predictor.metadata.get("data_source", "")).lower()
