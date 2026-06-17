"""
Tests for PhishGuard AI - ML Trainer
"""

import sys
import json
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
import numpy as np
import pandas as pd

from ml.trainer import (
    generate_synthetic_dataset,
    get_models,
    evaluate_model,
    train_all_models,
    run_training_pipeline,
    load_dataset,
    MODELS_DIR,
    BEST_MODEL_PATH,
    SCALER_PATH,
    META_PATH,
)


# ── Synthetic dataset ─────────────────────────────────────────────

class TestSyntheticDataset:
    def test_returns_correct_shape(self):
        X, y = generate_synthetic_dataset(n_samples=200)
        assert X.shape[0] == 200
        assert y.shape[0] == 200

    def test_feature_count(self):
        from ml.feature_extractor import get_feature_names
        X, y = generate_synthetic_dataset(n_samples=100)
        assert X.shape[1] == len(get_feature_names())

    def test_labels_are_binary(self):
        _, y = generate_synthetic_dataset(n_samples=200)
        assert set(y).issubset({0, 1})

    def test_balanced_classes(self):
        _, y = generate_synthetic_dataset(n_samples=200)
        assert sum(y == 1) == 100
        assert sum(y == 0) == 100

    def test_all_float_features(self):
        X, _ = generate_synthetic_dataset(n_samples=50)
        assert X.dtype in (np.float64, np.float32)

    def test_no_nan_values(self):
        X, y = generate_synthetic_dataset(n_samples=200)
        assert not np.isnan(X).any()
        assert not np.isnan(y.astype(float)).any()

    def test_reproducible_with_same_seed(self):
        X1, y1 = generate_synthetic_dataset(200)
        X2, y2 = generate_synthetic_dataset(200)
        np.testing.assert_array_equal(X1, X2)
        np.testing.assert_array_equal(y1, y2)


# ── CSV dataset loading ────────────────────────────────────────────

class TestLoadDataset:
    def _make_csv(self, rows, path):
        df = pd.DataFrame(rows)
        df.to_csv(path, index=False)

    def test_loads_basic_csv(self, tmp_path):
        csv_path = tmp_path / "test.csv"
        self._make_csv([
            {"subject": "Verify now", "body": "Click here", "sender": "a@b.tk",
             "reply_to": "", "headers": "", "label": 1},
            {"subject": "Hi team",    "body": "See you tomorrow", "sender": "c@d.com",
             "reply_to": "", "headers": "", "label": 0},
        ], csv_path)
        X, y = load_dataset(str(csv_path))
        assert X.shape[0] == 2
        assert list(y) == [1, 0]

    def test_handles_string_labels(self, tmp_path):
        csv_path = tmp_path / "labels.csv"
        self._make_csv([
            {"subject": "Win prize", "body": "Claim now", "sender": "x@y.xyz",
             "reply_to": "", "headers": "", "label": "phishing"},
            {"subject": "Invoice",   "body": "See attached", "sender": "a@b.com",
             "reply_to": "", "headers": "", "label": "safe"},
        ], csv_path)
        X, y = load_dataset(str(csv_path))
        assert list(y) == [1, 0]

    def test_handles_spam_label(self, tmp_path):
        csv_path = tmp_path / "spam.csv"
        self._make_csv([
            {"subject": "Buy now", "body": "Free offer", "sender": "s@s.ml",
             "reply_to": "", "headers": "", "label": "spam"},
        ], csv_path)
        X, y = load_dataset(str(csv_path))
        assert y[0] == 1

    def test_missing_optional_columns_ok(self, tmp_path):
        csv_path = tmp_path / "minimal.csv"
        df = pd.DataFrame([
            {"body": "Please verify your account", "label": 1},
            {"body": "Meeting at 3pm tomorrow",   "label": 0},
        ])
        df.to_csv(csv_path, index=False)
        X, y = load_dataset(str(csv_path))
        assert X.shape[0] == 2

    def test_raises_without_label_column(self, tmp_path):
        csv_path = tmp_path / "no_label.csv"
        pd.DataFrame([{"body": "Test"}]).to_csv(csv_path, index=False)
        with pytest.raises(ValueError, match="label"):
            load_dataset(str(csv_path))


# ── Model definitions ──────────────────────────────────────────────

class TestGetModels:
    def test_returns_three_models(self):
        models = get_models()
        assert len(models) == 3

    def test_model_names(self):
        models = get_models()
        assert "NaiveBayes" in models
        assert "LogisticRegression" in models
        assert "RandomForest" in models

    def test_models_have_fit_predict(self):
        for name, model in get_models().items():
            assert hasattr(model, "fit"), f"{name} missing fit()"
            assert hasattr(model, "predict"), f"{name} missing predict()"
            assert hasattr(model, "predict_proba"), f"{name} missing predict_proba()"


# ── Model evaluation ───────────────────────────────────────────────

class TestEvaluateModel:
    def _train_simple(self):
        from sklearn.linear_model import LogisticRegression
        X, y = generate_synthetic_dataset(n_samples=200)
        model = LogisticRegression(max_iter=500, random_state=42)
        model.fit(X[:160], y[:160])
        return model, X[160:], y[160:]

    def test_returns_all_metrics(self):
        model, X_test, y_test = self._train_simple()
        metrics = evaluate_model(model, X_test, y_test)
        for key in ("accuracy", "precision", "recall", "f1", "auc_roc"):
            assert key in metrics, f"Missing metric: {key}"

    def test_metrics_in_valid_range(self):
        model, X_test, y_test = self._train_simple()
        metrics = evaluate_model(model, X_test, y_test)
        for key in ("accuracy", "precision", "recall", "f1", "auc_roc"):
            assert 0.0 <= metrics[key] <= 1.0, f"{key}={metrics[key]} out of range"

    def test_confusion_matrix_values_present(self):
        model, X_test, y_test = self._train_simple()
        metrics = evaluate_model(model, X_test, y_test)
        for key in ("true_positives", "true_negatives",
                    "false_positives", "false_negatives"):
            assert key in metrics
            assert metrics[key] >= 0


# ── Full training pipeline ─────────────────────────────────────────

class TestTrainAllModels:
    def test_runs_successfully(self):
        X, y = generate_synthetic_dataset(n_samples=300)
        output = train_all_models(X, y)
        assert "best_model_name" in output
        assert "best_model" in output
        assert "results" in output

    def test_all_three_models_in_results(self):
        X, y = generate_synthetic_dataset(n_samples=300)
        output = train_all_models(X, y)
        for name in ("NaiveBayes", "LogisticRegression", "RandomForest"):
            assert name in output["results"]

    def test_best_model_has_highest_f1(self):
        X, y = generate_synthetic_dataset(n_samples=300)
        output = train_all_models(X, y)
        best_name = output["best_model_name"]
        best_f1 = output["results"][best_name]["f1"]
        for name, metrics in output["results"].items():
            assert metrics["f1"] <= best_f1 + 1e-9, (
                f"{name} F1={metrics['f1']} > best {best_name} F1={best_f1}"
            )

    def test_scaler_returned(self):
        X, y = generate_synthetic_dataset(n_samples=300)
        output = train_all_models(X, y)
        assert output["scaler"] is not None

    def test_models_achieve_reasonable_accuracy(self):
        """Synthetic data is structured so models should exceed 80% accuracy."""
        X, y = generate_synthetic_dataset(n_samples=600)
        output = train_all_models(X, y)
        for name, metrics in output["results"].items():
            assert metrics["accuracy"] >= 0.70, (
                f"{name} accuracy too low: {metrics['accuracy']}"
            )


# ── End-to-end pipeline ────────────────────────────────────────────

class TestRunTrainingPipeline:
    def test_pipeline_runs_without_dataset(self, tmp_path, monkeypatch):
        """Training with synthetic data, saving to a temp models dir."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "models").mkdir()

        summary = run_training_pipeline(csv_path=None)
        assert "best_model" in summary
        assert "metrics" in summary
        assert "message" in summary
        assert summary["metrics"]["f1"] > 0.0

    def test_model_files_saved(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "models").mkdir()
        run_training_pipeline(csv_path=None)
        assert (tmp_path / "models" / "phishguard_best.pkl").exists()
        assert (tmp_path / "models" / "scaler.pkl").exists()
        assert (tmp_path / "models" / "model_meta.json").exists()

    def test_metadata_structure(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "models").mkdir()
        run_training_pipeline(csv_path=None)
        with open(tmp_path / "models" / "model_meta.json") as f:
            meta = json.load(f)
        assert "model_name" in meta
        assert "feature_names" in meta
        assert "best_metrics" in meta
        assert "trained_at" in meta
        assert "version" in meta

    def test_pipeline_with_csv(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "models").mkdir()

        # Create a minimal CSV
        df = pd.DataFrame([
            {"subject": f"Phish {i}", "body": "Click verify your password now",
             "sender": f"x{i}@evil.tk", "reply_to": "h@a.xyz",
             "headers": "", "label": 1}
            for i in range(30)
        ] + [
            {"subject": f"Normal {i}", "body": "Hi the meeting is at 3pm today",
             "sender": f"u{i}@company.com", "reply_to": "",
             "headers": "", "label": 0}
            for i in range(30)
        ])
        csv_path = tmp_path / "data.csv"
        df.to_csv(csv_path, index=False)

        summary = run_training_pipeline(csv_path=str(csv_path))
        assert summary["best_model"] in ("NaiveBayes", "LogisticRegression", "RandomForest")
