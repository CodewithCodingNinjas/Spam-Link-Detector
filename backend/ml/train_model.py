"""
ML Model Training Script
Trains a phishing URL detection model using URL features.
Run this script to generate the model files.

Usage:
    python train_model.py
"""
import os
import sys
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    roc_auc_score,
)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import joblib
import json

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules.url_features import URLFeatureExtractor


def generate_synthetic_dataset(n_samples: int = 5000) -> pd.DataFrame:
    """
    Generate a synthetic dataset for training when no real dataset is available.
    In production, replace this with a real phishing URL dataset from Kaggle.
    """
    np.random.seed(42)
    feature_names = URLFeatureExtractor.get_feature_names()

    # Generate legitimate URLs features
    n_legit = n_samples // 2
    legit_features = {
        "url_length": np.random.normal(45, 15, n_legit).clip(15, 100).astype(int),
        "domain_length": np.random.normal(12, 4, n_legit).clip(5, 30).astype(int),
        "path_length": np.random.normal(15, 8, n_legit).clip(0, 50).astype(int),
        "num_dots": np.random.choice([1, 2, 3], n_legit, p=[0.4, 0.4, 0.2]),
        "num_hyphens": np.random.choice([0, 1], n_legit, p=[0.7, 0.3]),
        "num_underscores": np.random.choice([0, 1], n_legit, p=[0.9, 0.1]),
        "num_slashes": np.random.choice([2, 3, 4], n_legit, p=[0.3, 0.4, 0.3]),
        "num_question_marks": np.random.choice([0, 1], n_legit, p=[0.7, 0.3]),
        "num_equals": np.random.choice([0, 1, 2], n_legit, p=[0.6, 0.3, 0.1]),
        "num_ampersands": np.random.choice([0, 1], n_legit, p=[0.8, 0.2]),
        "num_at_symbols": np.zeros(n_legit, dtype=int),
        "num_special_chars": np.random.choice([0, 1, 2], n_legit, p=[0.5, 0.3, 0.2]),
        "num_digits_in_domain": np.random.choice([0, 1, 2], n_legit, p=[0.6, 0.3, 0.1]),
        "num_subdomains": np.random.choice([0, 1], n_legit, p=[0.6, 0.4]),
        "has_https": np.random.choice([0, 1], n_legit, p=[0.1, 0.9]),
        "has_ip_address": np.zeros(n_legit, dtype=int),
        "has_at_symbol": np.zeros(n_legit, dtype=int),
        "has_double_slash_redirect": np.zeros(n_legit, dtype=int),
        "has_port": np.zeros(n_legit, dtype=int),
        "has_hex_encoding": np.random.choice([0, 1], n_legit, p=[0.9, 0.1]),
        "suspicious_keyword_count": np.random.choice([0, 1], n_legit, p=[0.85, 0.15]),
        "has_suspicious_keywords": np.random.choice([0, 1], n_legit, p=[0.85, 0.15]),
        "digit_ratio": np.random.normal(0.05, 0.03, n_legit).clip(0, 0.3),
        "special_char_ratio": np.random.normal(0.15, 0.05, n_legit).clip(0, 0.4),
        "is_suspicious_tld": np.random.choice([0, 1], n_legit, p=[0.95, 0.05]),
        "has_login_form_pattern": np.random.choice([0, 1], n_legit, p=[0.9, 0.1]),
        "is_shortened": np.random.choice([0, 1], n_legit, p=[0.95, 0.05]),
    }

    # Generate phishing URLs features
    n_phish = n_samples - n_legit
    phish_features = {
        "url_length": np.random.normal(80, 25, n_phish).clip(30, 200).astype(int),
        "domain_length": np.random.normal(25, 8, n_phish).clip(10, 60).astype(int),
        "path_length": np.random.normal(30, 12, n_phish).clip(5, 80).astype(int),
        "num_dots": np.random.choice([2, 3, 4, 5], n_phish, p=[0.2, 0.3, 0.3, 0.2]),
        "num_hyphens": np.random.choice([1, 2, 3, 4], n_phish, p=[0.3, 0.3, 0.2, 0.2]),
        "num_underscores": np.random.choice([0, 1, 2], n_phish, p=[0.5, 0.3, 0.2]),
        "num_slashes": np.random.choice([3, 4, 5, 6], n_phish, p=[0.2, 0.3, 0.3, 0.2]),
        "num_question_marks": np.random.choice([0, 1, 2], n_phish, p=[0.4, 0.4, 0.2]),
        "num_equals": np.random.choice([0, 1, 2, 3], n_phish, p=[0.3, 0.3, 0.2, 0.2]),
        "num_ampersands": np.random.choice([0, 1, 2], n_phish, p=[0.5, 0.3, 0.2]),
        "num_at_symbols": np.random.choice([0, 1], n_phish, p=[0.8, 0.2]),
        "num_special_chars": np.random.choice([1, 2, 3, 4, 5], n_phish, p=[0.1, 0.2, 0.3, 0.2, 0.2]),
        "num_digits_in_domain": np.random.choice([0, 1, 2, 3, 4], n_phish, p=[0.2, 0.2, 0.3, 0.2, 0.1]),
        "num_subdomains": np.random.choice([1, 2, 3, 4], n_phish, p=[0.3, 0.3, 0.2, 0.2]),
        "has_https": np.random.choice([0, 1], n_phish, p=[0.5, 0.5]),
        "has_ip_address": np.random.choice([0, 1], n_phish, p=[0.7, 0.3]),
        "has_at_symbol": np.random.choice([0, 1], n_phish, p=[0.8, 0.2]),
        "has_double_slash_redirect": np.random.choice([0, 1], n_phish, p=[0.7, 0.3]),
        "has_port": np.random.choice([0, 1], n_phish, p=[0.85, 0.15]),
        "has_hex_encoding": np.random.choice([0, 1], n_phish, p=[0.6, 0.4]),
        "suspicious_keyword_count": np.random.choice([1, 2, 3, 4], n_phish, p=[0.3, 0.3, 0.2, 0.2]),
        "has_suspicious_keywords": np.ones(n_phish, dtype=int),
        "digit_ratio": np.random.normal(0.15, 0.06, n_phish).clip(0, 0.5),
        "special_char_ratio": np.random.normal(0.25, 0.08, n_phish).clip(0, 0.6),
        "is_suspicious_tld": np.random.choice([0, 1], n_phish, p=[0.4, 0.6]),
        "has_login_form_pattern": np.random.choice([0, 1], n_phish, p=[0.3, 0.7]),
        "is_shortened": np.random.choice([0, 1], n_phish, p=[0.7, 0.3]),
    }

    # Create DataFrames
    df_legit = pd.DataFrame(legit_features)
    df_legit["label"] = 0  # Safe

    df_phish = pd.DataFrame(phish_features)
    df_phish["label"] = 1  # Phishing

    # Combine
    df = pd.concat([df_legit, df_phish], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    return df


def train_and_save_model(dataset_path: str = None):
    """
    Train the phishing detection model and save it.
    
    Args:
        dataset_path: Path to CSV dataset. If None, uses synthetic data.
    """
    feature_names = URLFeatureExtractor.get_feature_names()

    # Load or generate dataset
    if dataset_path and os.path.exists(dataset_path):
        print(f"Loading dataset from {dataset_path}...")
        df = pd.read_csv(dataset_path)
        # Ensure all required features exist
        for f in feature_names:
            if f not in df.columns:
                print(f"Warning: Feature '{f}' not in dataset, filling with 0")
                df[f] = 0
    else:
        print("Generating synthetic dataset...")
        df = generate_synthetic_dataset(n_samples=10000)

    print(f"Dataset shape: {df.shape}")
    print(f"Label distribution:\n{df['label'].value_counts()}")

    # Prepare features and labels
    X = df[feature_names].values
    y = df["label"].values

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Train multiple models and pick the best
    models = {
        "RandomForest": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1,
            )),
        ]),
        "GradientBoosting": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", GradientBoostingClassifier(
                n_estimators=150,
                max_depth=8,
                learning_rate=0.1,
                random_state=42,
            )),
        ]),
        "LogisticRegression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(
                max_iter=1000,
                random_state=42,
                C=1.0,
            )),
        ]),
    }

    best_model_name = None
    best_model = None
    best_score = 0

    for name, model in models.items():
        print(f"\n{'='*50}")
        print(f"Training {name}...")

        # Cross-validation
        cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring="accuracy")
        print(f"CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

        # Fit on full training set
        model.fit(X_train, y_train)

        # Evaluate on test set
        y_pred = model.predict(X_test)
        y_proba = model.predict_proba(X_test)[:, 1]

        accuracy = accuracy_score(y_test, y_pred)
        auc = roc_auc_score(y_test, y_proba)

        print(f"Test Accuracy: {accuracy:.4f}")
        print(f"Test AUC-ROC: {auc:.4f}")
        print(f"\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))
        print(f"Confusion Matrix:")
        print(confusion_matrix(y_test, y_pred))

        if auc > best_score:
            best_score = auc
            best_model = model
            best_model_name = name

    print(f"\n{'='*50}")
    print(f"Best Model: {best_model_name} (AUC: {best_score:.4f})")

    # Save the best model
    model_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model")
    os.makedirs(model_dir, exist_ok=True)

    model_path = os.path.join(model_dir, "phishing_model.joblib")
    joblib.dump(best_model, model_path)
    print(f"Model saved to: {model_path}")

    # Save model metadata
    metadata = {
        "model_name": best_model_name,
        "auc_score": round(best_score, 4),
        "feature_names": feature_names,
        "n_features": len(feature_names),
        "training_samples": len(X_train),
        "test_samples": len(X_test),
    }
    metadata_path = os.path.join(model_dir, "model_metadata.json")
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"Metadata saved to: {metadata_path}")

    return best_model, feature_names


if __name__ == "__main__":
    # Check if a dataset path is provided as argument
    dataset_path = sys.argv[1] if len(sys.argv) > 1 else None
    train_and_save_model(dataset_path)
