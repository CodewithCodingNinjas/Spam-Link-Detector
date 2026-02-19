"""
ML Prediction Module
Loads the trained model and provides predictions.
"""
import os
import numpy as np
import joblib
import json
import logging
from typing import Dict, Any, Optional

from config import settings

logger = logging.getLogger(__name__)


class PhishingPredictor:
    """Loads and uses the trained ML model for phishing detection."""

    def __init__(self):
        self.model = None
        self.metadata = None
        self.loaded = False
        self._load_model()

    def _load_model(self):
        """Load the trained model from disk."""
        try:
            model_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "model",
                "phishing_model.joblib",
            )
            metadata_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "model",
                "model_metadata.json",
            )

            if os.path.exists(model_path):
                self.model = joblib.load(model_path)
                self.loaded = True
                logger.info(f"ML model loaded from {model_path}")

                if os.path.exists(metadata_path):
                    with open(metadata_path, "r") as f:
                        self.metadata = json.load(f)
                    logger.info(f"Model metadata: {self.metadata}")
            else:
                logger.warning(
                    f"ML model not found at {model_path}. "
                    "Run 'python ml/train_model.py' to train the model."
                )

        except Exception as e:
            logger.error(f"Error loading ML model: {e}")
            self.loaded = False

    def predict(self, features: list) -> Dict[str, Any]:
        """
        Make a prediction on URL features.
        
        Args:
            features: List of numeric features from URLFeatureExtractor.
            
        Returns:
            Dict with prediction, probability, and confidence.
        """
        result = {
            "prediction": "Unknown",
            "probability": 0.5,
            "confidence": 0.0,
            "model_loaded": self.loaded,
        }

        if not self.loaded or self.model is None:
            logger.warning("ML model not loaded, using rule-based fallback")
            return self._rule_based_prediction(features)

        try:
            X = np.array(features).reshape(1, -1)
            prediction = self.model.predict(X)[0]
            probabilities = self.model.predict_proba(X)[0]

            phishing_prob = probabilities[1]
            confidence = max(probabilities) * 100

            result["prediction"] = "Phishing" if prediction == 1 else "Safe"
            result["probability"] = round(float(phishing_prob), 4)
            result["confidence"] = round(float(confidence), 2)

        except Exception as e:
            logger.error(f"ML prediction error: {e}")
            result = self._rule_based_prediction(features)

        return result

    def _rule_based_prediction(self, features: list) -> Dict[str, Any]:
        """Fallback rule-based prediction when ML model is unavailable."""
        from modules.url_features import URLFeatureExtractor

        feature_names = URLFeatureExtractor.get_feature_names()
        feature_dict = dict(zip(feature_names, features))

        risk_score = 0.0

        # URL length
        if feature_dict.get("url_length", 0) > 75:
            risk_score += 10
        if feature_dict.get("url_length", 0) > 100:
            risk_score += 10

        # Has IP address
        if feature_dict.get("has_ip_address", 0):
            risk_score += 20

        # No HTTPS
        if not feature_dict.get("has_https", 0):
            risk_score += 10

        # Has @ symbol
        if feature_dict.get("has_at_symbol", 0):
            risk_score += 15

        # Suspicious keywords
        risk_score += feature_dict.get("suspicious_keyword_count", 0) * 5

        # Suspicious TLD
        if feature_dict.get("is_suspicious_tld", 0):
            risk_score += 15

        # Many subdomains
        if feature_dict.get("num_subdomains", 0) > 2:
            risk_score += 10

        # Double slash redirect
        if feature_dict.get("has_double_slash_redirect", 0):
            risk_score += 10

        # Many special characters
        if feature_dict.get("num_special_chars", 0) > 3:
            risk_score += 5

        # Shortened URL
        if feature_dict.get("is_shortened", 0):
            risk_score += 10

        # Normalize to 0-1
        probability = min(risk_score / 100.0, 1.0)

        return {
            "prediction": "Phishing" if probability > 0.5 else "Safe",
            "probability": round(probability, 4),
            "confidence": round(max(probability, 1 - probability) * 100, 2),
            "model_loaded": False,
        }

    def is_loaded(self) -> bool:
        return self.loaded


# Singleton (lazy loaded)
_predictor = None


def get_predictor() -> PhishingPredictor:
    global _predictor
    if _predictor is None:
        _predictor = PhishingPredictor()
    return _predictor
