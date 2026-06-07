"""
ML Model Training Script (real-data edition)
============================================
Trains a phishing-URL detection model on REAL labelled URLs and reports honest,
defensible metrics.

Previous versions trained on a synthetic distribution whose two classes were
hand-separated, yielding a meaningless AUC of 1.0. This version:

  1. Loads a feature CSV produced by build_dataset.py from genuine phishing
     feeds (OpenPhish, Phishing.Database) and legitimate top-sites domains.
  2. Trains RandomForest / GradientBoosting / LogisticRegression with stratified
     5-fold cross-validation.
  3. Selects the best model by mean CV ROC-AUC (NOT test AUC) to avoid test-set
     leakage in model selection.
  4. Reports accuracy, precision, recall, F1, ROC-AUC, confusion matrix, and the
     full classification report on a held-out test set.
  5. Persists the model, the ordered feature list, AND the honest metrics into
     model_metadata.json so the API and synopsis can quote real numbers.

The feature ordering is taken from URLFeatureExtractor.get_feature_names(), so
the trained model ALWAYS matches the live inference feature vector (this fixes
the previous 27-vs-31 feature-count mismatch that silently disabled the model).

Usage:
    python build_dataset.py            # fetch real URLs -> data/urls_dataset.csv
    python train_model.py              # train on that CSV
    python train_model.py path.csv     # train on a custom CSV
"""
import os
import sys
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import joblib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules.url_features import URLFeatureExtractor  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CSV = os.path.join(HERE, "data", "urls_dataset.csv")


def load_dataset(csv_path: str, feature_names: list):
    if not os.path.exists(csv_path):
        print(f"ERROR: dataset not found at {csv_path}")
        print("Run:  python ml/build_dataset.py   to fetch real URLs first.")
        sys.exit(1)

    df = pd.read_csv(csv_path)
    missing = [f for f in feature_names if f not in df.columns]
    if missing:
        print(f"ERROR: dataset is missing required feature columns: {missing}")
        sys.exit(1)
    if "label" not in df.columns:
        print("ERROR: dataset has no 'label' column.")
        sys.exit(1)

    # Drop rows with NaN in the modelled columns
    df = df.dropna(subset=feature_names + ["label"]).reset_index(drop=True)
    return df


def train_and_save_model(dataset_path: str = None):
    feature_names = URLFeatureExtractor.get_feature_names()
    csv_path = dataset_path or DEFAULT_CSV

    df = load_dataset(csv_path, feature_names)
    print(f"Dataset: {csv_path}")
    print(f"Shape: {df.shape}")
    print(f"Label distribution:\n{df['label'].value_counts()}\n")

    X = df[feature_names].values.astype(float)
    y = df["label"].values.astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    models = {
        "RandomForest": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", RandomForestClassifier(
                n_estimators=300, max_depth=18, min_samples_split=4,
                min_samples_leaf=2, max_features="sqrt",
                class_weight="balanced", random_state=42, n_jobs=-1,
            )),
        ]),
        "GradientBoosting": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", GradientBoostingClassifier(
                n_estimators=200, max_depth=4, learning_rate=0.08, random_state=42,
            )),
        ]),
        "LogisticRegression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(
                max_iter=2000, C=1.0, class_weight="balanced", random_state=42,
            )),
        ]),
    }

    best_name, best_model, best_cv = None, None, -1.0
    cv_table = {}

    for name, model in models.items():
        print("=" * 60)
        print(f"Training {name} (stratified 5-fold CV)...")
        cv_scores = cross_val_score(
            model, X_train, y_train, cv=5, scoring="roc_auc", n_jobs=-1
        )
        cv_mean, cv_std = float(cv_scores.mean()), float(cv_scores.std())
        cv_table[name] = {"cv_auc_mean": round(cv_mean, 4), "cv_auc_std": round(cv_std, 4)}
        print(f"  CV ROC-AUC: {cv_mean:.4f} (+/- {cv_std:.4f})")
        if cv_mean > best_cv:
            best_cv, best_model, best_name = cv_mean, model, name

    print("=" * 60)
    print(f"Selected (by CV ROC-AUC): {best_name}\n")

    # Fit best model on full train split, evaluate ONCE on held-out test set
    best_model.fit(X_train, y_train)
    y_pred = best_model.predict(X_test)
    y_proba = best_model.predict_proba(X_test)[:, 1]

    metrics = {
        "accuracy":  round(float(accuracy_score(y_test, y_pred)), 4),
        "precision": round(float(precision_score(y_test, y_pred)), 4),
        "recall":    round(float(recall_score(y_test, y_pred)), 4),
        "f1":        round(float(f1_score(y_test, y_pred)), 4),
        "roc_auc":   round(float(roc_auc_score(y_test, y_proba)), 4),
    }
    cm = confusion_matrix(y_test, y_pred)

    print("Held-out TEST set performance (real URLs):")
    for k, v in metrics.items():
        print(f"  {k:10s}: {v}")
    print("\nClassification report:")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))
    print("Confusion matrix [rows=true, cols=pred] (Safe, Phishing):")
    print(cm)

    # Feature importances (tree models only)
    importances = None
    clf = best_model.named_steps["clf"]
    if hasattr(clf, "feature_importances_"):
        importances = sorted(
            zip(feature_names, [round(float(i), 4) for i in clf.feature_importances_]),
            key=lambda t: t[1], reverse=True,
        )
        print("\nTop 10 features by importance:")
        for fname, imp in importances[:10]:
            print(f"  {fname:24s} {imp}")

    # Persist model + honest metadata
    model_dir = os.path.join(HERE, "model")
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, "phishing_model.joblib")
    joblib.dump(best_model, model_path)

    metadata = {
        "model_name": best_name,
        "data_source": "real (OpenPhish + Phishing.Database + top-100k legit domains)",
        "cv_selection": cv_table,
        "test_metrics": metrics,
        "confusion_matrix": {
            "true_safe":     {"pred_safe": int(cm[0][0]), "pred_phishing": int(cm[0][1])},
            "true_phishing": {"pred_safe": int(cm[1][0]), "pred_phishing": int(cm[1][1])},
        },
        "feature_names": feature_names,
        "n_features": len(feature_names),
        "training_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "top_features": importances[:15] if importances else None,
    }
    with open(os.path.join(model_dir, "model_metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"\nModel saved   -> {model_path}")
    print(f"Metadata saved-> {os.path.join(model_dir, 'model_metadata.json')}")
    return best_model, feature_names, metrics


if __name__ == "__main__":
    dataset_path = sys.argv[1] if len(sys.argv) > 1 else None
    train_and_save_model(dataset_path)
