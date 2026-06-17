"""
PhishGuard AI - Model Trainer
Trains, evaluates, and saves phishing detection models.
"""

import os
import json
import logging
import time
from pathlib import Path
from typing import Dict, Tuple, Any

import joblib
import numpy as np
import pandas as pd
from sklearn.naive_bayes import GaussianNB
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix, classification_report
)
from sklearn.pipeline import Pipeline

from ml.feature_extractor import extract_features, features_to_vector, get_feature_names

logger = logging.getLogger(__name__)

MODELS_DIR = Path("models")
MODELS_DIR.mkdir(exist_ok=True)

BEST_MODEL_PATH = MODELS_DIR / "phishguard_best.pkl"
SCALER_PATH = MODELS_DIR / "scaler.pkl"
META_PATH = MODELS_DIR / "model_meta.json"


# ── Data Preparation ───────────────────────────────────────────────────────────

def load_dataset(csv_path: str) -> Tuple[np.ndarray, np.ndarray]:
    """
    Load and prepare dataset from CSV.

    Expected columns (flexible):
        - 'subject', 'body', 'sender', 'reply_to', 'headers' (text)
        - 'label': 1 = phishing, 0 = safe (or 'phishing'/'safe' strings)

    Returns:
        X: feature matrix (n_samples, n_features)
        y: label vector (n_samples,)
    """
    logger.info(f"Loading dataset from {csv_path}")
    df = pd.read_csv(csv_path)

    # Normalise label column
    if "label" not in df.columns:
        raise ValueError("Dataset must contain a 'label' column (0=safe, 1=phishing).")

    df["label"] = df["label"].apply(
        lambda x: 1 if str(x).strip().lower() in ("1", "phishing", "spam") else 0
    )

    # Fill missing text columns
    for col in ("subject", "body", "sender", "reply_to", "headers"):
        if col not in df.columns:
            df[col] = ""
        else:
            df[col] = df[col].fillna("")

    logger.info(f"Dataset: {len(df)} rows | "
                f"{df['label'].sum()} phishing | {(df['label']==0).sum()} safe")

    X_list = []
    for _, row in df.iterrows():
        feats = extract_features(
            subject=str(row["subject"]),
            body=str(row["body"]),
            sender=str(row["sender"]),
            reply_to=str(row["reply_to"]),
            headers=str(row["headers"])
        )
        X_list.append(features_to_vector(feats))

    X = np.array(X_list, dtype=np.float64)
    y = df["label"].values.astype(int)
    return X, y


def generate_synthetic_dataset(n_samples: int = 2000) -> Tuple[np.ndarray, np.ndarray]:
    """
    Generate a synthetic training dataset for demo/testing purposes.
    Produces realistic feature distributions for phishing vs safe emails.
    """
    logger.info(f"Generating synthetic dataset with {n_samples} samples")
    rng = np.random.RandomState(42)
    n_phish = n_samples // 2
    n_safe = n_samples - n_phish

    def phishing_row() -> list:
        return [
            rng.randint(1, 8),         # num_urls
            rng.choice([0, 1, 2], p=[0.3, 0.5, 0.2]),  # num_ip_urls
            rng.choice([0, 1], p=[0.4, 0.6]),           # num_shortener_urls
            rng.choice([0, 1, 2], p=[0.3, 0.5, 0.2]),  # num_suspicious_tld
            rng.choice([0, 1], p=[0.5, 0.5]),           # num_misleading_domain
            rng.randint(1, 5),         # max_subdomains
            rng.choice([0, 1], p=[0.7, 0.3]),           # has_at_in_url
            rng.choice([0, 1], p=[0.4, 0.6]),           # has_long_url
            rng.randint(2, 8),         # urgency_score
            rng.randint(1, 5),         # credential_score
            rng.randint(1, 6),         # suspicious_phrase_score
            rng.uniform(3.5, 5.0),    # body_entropy
            rng.randint(3, 12),        # exclamation_count
            rng.randint(0, 5),         # dollar_count
            rng.choice([0, 1], p=[0.3, 0.7]),           # html_present
            rng.choice([0, 1, 2], p=[0.4, 0.4, 0.2]),  # html_form_count
            rng.randint(2, 15),        # html_link_count
            rng.choice([0, 1], p=[0.6, 0.4]),           # has_obfuscation
            rng.randint(0, 3),         # misspelling_count
            rng.randint(50, 300),      # word_count
            rng.uniform(0.2, 0.5),    # caps_ratio
            rng.uniform(0.3, 0.7),    # subject_caps_ratio
            rng.randint(20, 80),       # subject_length
            rng.randint(200, 2000),   # body_length
            rng.choice([0, 1], p=[0.3, 0.7]),           # free_provider
            rng.choice([0, 1], p=[0.5, 0.5]),           # domain_mismatch
            rng.choice([0, 1], p=[0.3, 0.7]),           # has_reply_to
            rng.randint(1, 5),         # subject_urgency
            rng.randint(1, 4),         # subject_exclamation
        ]

    def safe_row() -> list:
        return [
            rng.randint(0, 3),         # num_urls
            0,                          # num_ip_urls
            0,                          # num_shortener_urls
            0,                          # num_suspicious_tld
            0,                          # num_misleading_domain
            rng.randint(0, 2),         # max_subdomains
            0,                          # has_at_in_url
            rng.choice([0, 1], p=[0.9, 0.1]),           # has_long_url
            rng.randint(0, 2),         # urgency_score
            0,                          # credential_score
            rng.randint(0, 2),         # suspicious_phrase_score
            rng.uniform(3.0, 4.5),    # body_entropy
            rng.randint(0, 2),         # exclamation_count
            rng.randint(0, 1),         # dollar_count
            rng.choice([0, 1], p=[0.5, 0.5]),           # html_present
            0,                          # html_form_count
            rng.randint(0, 5),         # html_link_count
            0,                          # has_obfuscation
            0,                          # misspelling_count
            rng.randint(100, 800),     # word_count
            rng.uniform(0.05, 0.15),  # caps_ratio
            rng.uniform(0.0, 0.2),    # subject_caps_ratio
            rng.randint(10, 60),       # subject_length
            rng.randint(300, 3000),   # body_length
            rng.choice([0, 1], p=[0.6, 0.4]),           # free_provider
            0,                          # domain_mismatch
            rng.choice([0, 1], p=[0.7, 0.3]),           # has_reply_to
            0,                          # subject_urgency
            0,                          # subject_exclamation
        ]

    X_phish = np.array([phishing_row() for _ in range(n_phish)], dtype=np.float64)
    X_safe = np.array([safe_row() for _ in range(n_safe)], dtype=np.float64)
    X = np.vstack([X_phish, X_safe])
    y = np.array([1] * n_phish + [0] * n_safe, dtype=int)

    # Shuffle
    idx = rng.permutation(len(y))
    return X[idx], y[idx]


# ── Model Definitions ──────────────────────────────────────────────────────────

def get_models() -> Dict[str, Any]:
    """Return the three candidate models."""
    return {
        "NaiveBayes": GaussianNB(),
        "LogisticRegression": LogisticRegression(
            max_iter=1000,
            C=1.0,
            solver="lbfgs",
            random_state=42
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=150,
            max_depth=12,
            min_samples_split=5,
            random_state=42,
            n_jobs=-1
        ),
    }


# ── Training & Evaluation ──────────────────────────────────────────────────────

def evaluate_model(
    model, X_test: np.ndarray, y_test: np.ndarray
) -> Dict[str, float]:
    """Compute comprehensive evaluation metrics."""
    y_pred = model.predict(X_test)
    try:
        y_prob = model.predict_proba(X_test)[:, 1]
        auc = roc_auc_score(y_test, y_prob)
    except AttributeError:
        auc = 0.0

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

    return {
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_test, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_test, y_pred, zero_division=0), 4),
        "auc_roc": round(auc, 4),
        "true_positives": int(tp),
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
    }


def train_all_models(
    X: np.ndarray,
    y: np.ndarray,
    test_size: float = 0.2
) -> Dict[str, Any]:
    """
    Train all candidate models and return results + best model.

    Returns:
        {
            "results": { model_name: metrics_dict },
            "best_model_name": str,
            "best_model": fitted model,
            "scaler": StandardScaler,
            "X_test": ..., "y_test": ...
        }
    """
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=42, stratify=y
    )

    # Scale features (helps Logistic Regression and NB)
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    models = get_models()
    results = {}
    best_f1 = -1.0
    best_name = ""
    best_model = None

    for name, model in models.items():
        logger.info(f"Training {name}...")
        t0 = time.time()
        model.fit(X_train_s, y_train)
        elapsed = round(time.time() - t0, 2)

        metrics = evaluate_model(model, X_test_s, y_test)
        metrics["training_time_s"] = elapsed

        # Cross-validation F1
        cv_scores = cross_val_score(model, X_train_s, y_train, cv=5, scoring="f1")
        metrics["cv_f1_mean"] = round(cv_scores.mean(), 4)
        metrics["cv_f1_std"] = round(cv_scores.std(), 4)

        results[name] = metrics
        logger.info(f"  {name}: accuracy={metrics['accuracy']}, "
                    f"f1={metrics['f1']}, auc={metrics['auc_roc']}")

        if metrics["f1"] > best_f1:
            best_f1 = metrics["f1"]
            best_name = name
            best_model = model

    logger.info(f"Best model: {best_name} (F1={best_f1})")

    return {
        "results": results,
        "best_model_name": best_name,
        "best_model": best_model,
        "scaler": scaler,
        "X_test": X_test_s,
        "y_test": y_test,
    }


def save_best_model(
    model,
    scaler: StandardScaler,
    model_name: str,
    metrics: Dict[str, float],
    all_results: Dict[str, Any]
) -> None:
    """Persist the best model, scaler, and metadata."""
    MODELS_DIR.mkdir(exist_ok=True)
    joblib.dump(model, BEST_MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    meta = {
        "model_name": model_name,
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "feature_names": get_feature_names(),
        "best_metrics": metrics,
        "all_results": all_results,
        "version": "1.0.0"
    }
    with open(META_PATH, "w") as f:
        json.dump(meta, f, indent=2)
    logger.info(f"Model saved → {BEST_MODEL_PATH}")
    logger.info(f"Scaler saved → {SCALER_PATH}")
    logger.info(f"Metadata saved → {META_PATH}")


def load_model() -> Tuple[Any, StandardScaler, Dict]:
    """Load the saved best model, scaler, and metadata."""
    if not BEST_MODEL_PATH.exists():
        raise FileNotFoundError(
            "No trained model found. Run 'phishguard train' first."
        )
    model = joblib.load(BEST_MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    with open(META_PATH) as f:
        meta = json.load(f)
    return model, scaler, meta


def run_training_pipeline(csv_path: str | None = None) -> Dict[str, Any]:
    """
    End-to-end training pipeline.

    Args:
        csv_path: Path to CSV dataset. If None, uses synthetic data.

    Returns:
        Summary dict with model comparison and best model info.
    """
    if csv_path:
        X, y = load_dataset(csv_path)
    else:
        logger.info("No dataset provided — using synthetic training data.")
        X, y = generate_synthetic_dataset(n_samples=3000)

    train_output = train_all_models(X, y)
    best = train_output["best_model"]
    best_name = train_output["best_model_name"]
    best_metrics = train_output["results"][best_name]
    scaler = train_output["scaler"]

    save_best_model(best, scaler, best_name, best_metrics, train_output["results"])

    return {
        "best_model": best_name,
        "metrics": best_metrics,
        "all_results": train_output["results"],
        "message": f"Training complete. Best model: {best_name} (F1={best_metrics['f1']})"
    }
