"""
Tests for PhishGuard AI - REST API
"""

import sys
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from app import create_app
from app.database import init_db


@pytest.fixture
def app(tmp_path, monkeypatch):
    """Create a test Flask app with isolated tmp directory."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "models").mkdir()
    (tmp_path / "phishguard.db").touch()

    application = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret-key",
        "WTF_CSRF_ENABLED": False,
    })
    init_db()
    yield application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def trained_app(app, tmp_path):
    """App fixture with a trained model available."""
    with app.app_context():
        from ml.trainer import run_training_pipeline
        run_training_pipeline(csv_path=None)
    return app


@pytest.fixture
def trained_client(trained_app):
    return trained_app.test_client()


# ── Health endpoint ────────────────────────────────────────────────

class TestHealthEndpoint:
    def test_returns_200(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200

    def test_returns_json(self, client):
        r = client.get("/api/health")
        data = json.loads(r.data)
        assert data["status"] == "ok"

    def test_service_name(self, client):
        r = client.get("/api/health")
        data = json.loads(r.data)
        assert "PhishGuard" in data["service"]

    def test_version_field(self, client):
        r = client.get("/api/health")
        data = json.loads(r.data)
        assert "version" in data

    def test_model_ready_false_before_training(self, client):
        r = client.get("/api/health")
        data = json.loads(r.data)
        assert data["model_ready"] is False

    def test_model_ready_true_after_training(self, trained_client):
        r = trained_client.get("/api/health")
        data = json.loads(r.data)
        assert data["model_ready"] is True


# ── Train endpoint ─────────────────────────────────────────────────

class TestTrainEndpoint:
    def test_train_with_synthetic_data(self, client):
        r = client.post("/api/train")
        assert r.status_code == 200

    def test_train_returns_best_model(self, client):
        r = client.post("/api/train")
        data = json.loads(r.data)
        assert "best_model" in data
        assert data["best_model"] in (
            "NaiveBayes", "LogisticRegression", "RandomForest"
        )

    def test_train_returns_metrics(self, client):
        r = client.post("/api/train")
        data = json.loads(r.data)
        assert "metrics" in data
        assert "f1" in data["metrics"]
        assert "accuracy" in data["metrics"]

    def test_train_returns_all_results(self, client):
        r = client.post("/api/train")
        data = json.loads(r.data)
        assert "all_results" in data
        for name in ("NaiveBayes", "LogisticRegression", "RandomForest"):
            assert name in data["all_results"]

    def test_train_with_csv_upload(self, client, tmp_path):
        import pandas as pd, io
        df = pd.DataFrame(
            [{"subject": "Phish", "body": "Verify password now click here urgent",
              "sender": "x@evil.tk", "reply_to": "h@other.xyz", "headers": "", "label": 1}] * 20 +
            [{"subject": "Hello", "body": "Meeting at 3pm see you tomorrow",
              "sender": "user@corp.com", "reply_to": "", "headers": "", "label": 0}] * 20
        )
        csv_bytes = df.to_csv(index=False).encode()
        data = {"dataset": (io.BytesIO(csv_bytes), "data.csv", "text/csv")}
        r = client.post("/api/train", content_type="multipart/form-data", data=data)
        assert r.status_code == 200


# ── Analyze endpoint ───────────────────────────────────────────────

class TestAnalyzeEndpoint:
    PHISHING_PAYLOAD = {
        "subject": "URGENT: Your account is suspended",
        "body": (
            "Dear customer your account has been suspended. "
            "Click http://192.168.1.1/verify to restore. "
            "Enter your password and credit card number immediately! "
            "Act now within 24 hours or lose access!!!"
        ),
        "sender": "security@paypa1-alert.tk",
        "reply_to": "collect@evil-harvest.xyz",
    }

    SAFE_PAYLOAD = {
        "subject": "Q3 planning meeting",
        "body": "Hi everyone, the Q3 planning meeting is confirmed for Friday at 2pm. Please prepare your slides.",
        "sender": "manager@company.com",
        "reply_to": "",
    }

    def test_analyze_requires_trained_model(self, client):
        r = client.post("/api/analyze",
                        json=self.PHISHING_PAYLOAD,
                        content_type="application/json")
        assert r.status_code == 503

    def test_analyze_returns_200(self, trained_client):
        r = trained_client.post("/api/analyze",
                                json=self.PHISHING_PAYLOAD,
                                content_type="application/json")
        assert r.status_code == 200

    def test_analyze_returns_classification(self, trained_client):
        r = trained_client.post("/api/analyze",
                                json=self.PHISHING_PAYLOAD,
                                content_type="application/json")
        data = json.loads(r.data)
        assert data["classification"] in ("PHISHING", "SAFE")

    def test_analyze_returns_probability(self, trained_client):
        r = trained_client.post("/api/analyze",
                                json=self.PHISHING_PAYLOAD,
                                content_type="application/json")
        data = json.loads(r.data)
        assert "phishing_probability" in data
        assert 0.0 <= data["phishing_probability"] <= 1.0

    def test_analyze_returns_risk_level(self, trained_client):
        r = trained_client.post("/api/analyze",
                                json=self.PHISHING_PAYLOAD,
                                content_type="application/json")
        data = json.loads(r.data)
        assert "risk" in data
        assert data["risk"]["level"] in ("critical", "high", "medium", "low")

    def test_analyze_returns_indicators(self, trained_client):
        r = trained_client.post("/api/analyze",
                                json=self.PHISHING_PAYLOAD,
                                content_type="application/json")
        data = json.loads(r.data)
        assert "indicators" in data
        assert isinstance(data["indicators"], list)

    def test_analyze_returns_confidence(self, trained_client):
        r = trained_client.post("/api/analyze",
                                json=self.PHISHING_PAYLOAD,
                                content_type="application/json")
        data = json.loads(r.data)
        assert "confidence" in data

    def test_analyze_empty_body_returns_400(self, trained_client):
        r = trained_client.post("/api/analyze",
                                json={},
                                content_type="application/json")
        assert r.status_code == 400

    def test_safe_email_classifiable(self, trained_client):
        r = trained_client.post("/api/analyze",
                                json=self.SAFE_PAYLOAD,
                                content_type="application/json")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data["classification"] in ("PHISHING", "SAFE")

    def test_phishing_probability_higher_for_phish(self, trained_client):
        r_phish = trained_client.post("/api/analyze",
                                      json=self.PHISHING_PAYLOAD,
                                      content_type="application/json")
        r_safe = trained_client.post("/api/analyze",
                                     json=self.SAFE_PAYLOAD,
                                     content_type="application/json")
        phish_prob = json.loads(r_phish.data)["phishing_probability"]
        safe_prob  = json.loads(r_safe.data)["phishing_probability"]
        assert phish_prob > safe_prob

    def test_analyze_eml_upload(self, trained_client):
        import io
        raw_eml = (
            "From: attacker@evil.tk\n"
            "To: victim@company.com\n"
            "Subject: URGENT verify your account now\n"
            "Reply-To: harvest@other.xyz\n\n"
            "Dear customer please verify your password and credit card immediately. "
            "Click http://192.168.1.1/login to act now or account suspended!!!"
        )
        data = {"eml_file": (io.BytesIO(raw_eml.encode()), "test.eml", "message/rfc822")}
        r = trained_client.post("/api/analyze",
                                content_type="multipart/form-data", data=data)
        assert r.status_code == 200
        result = json.loads(r.data)
        assert "classification" in result


# ── History & stats endpoints ──────────────────────────────────────

class TestHistoryEndpoint:
    def test_history_returns_200(self, client):
        r = client.get("/api/history")
        assert r.status_code == 200

    def test_history_returns_list(self, client):
        r = client.get("/api/history")
        data = json.loads(r.data)
        assert "results" in data
        assert isinstance(data["results"], list)

    def test_history_after_analysis(self, trained_client):
        trained_client.post("/api/analyze",
                            json={"body": "Verify your password now urgently"},
                            content_type="application/json")
        r = trained_client.get("/api/history")
        data = json.loads(r.data)
        assert data["count"] >= 1

    def test_history_limit_param(self, trained_client):
        # Insert some analyses
        for _ in range(5):
            trained_client.post("/api/analyze",
                                json={"body": "Test email content here"},
                                content_type="application/json")
        r = trained_client.get("/api/history?limit=3")
        data = json.loads(r.data)
        assert len(data["results"]) <= 3


class TestStatsEndpoint:
    def test_stats_returns_200(self, client):
        r = client.get("/api/stats")
        assert r.status_code == 200

    def test_stats_fields(self, client):
        r = client.get("/api/stats")
        data = json.loads(r.data)
        assert "total" in data
        assert "phishing" in data
        assert "safe" in data
        assert "phishing_rate" in data
