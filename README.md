# 🛡️ PhishGuard AI

> **AI-powered phishing email detection tool for security professionals**
> Built for Kali Linux · Python 3.12 · MIT License · v1.0.0

[![CI/CD](https://github.com/yourusername/phishguard/actions/workflows/ci.yml/badge.svg)](https://github.com/yourusername/phishguard/actions)
[![Coverage](https://codecov.io/gh/yourusername/phishguard/branch/main/graph/badge.svg)](https://codecov.io/gh/yourusername/phishguard)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](Dockerfile)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Installation (Kali Linux)](#-installation-kali-linux)
- [Quick Start](#-quick-start)
- [Web Dashboard](#-web-dashboard)
- [REST API](#-rest-api)
- [CLI Tool](#-cli-tool)
- [Machine Learning](#-machine-learning)
- [Docker Deployment](#-docker-deployment)
- [Testing](#-testing)
- [Project Structure](#-project-structure)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🔍 Overview

PhishGuard AI is a full-stack, open-source phishing email detection platform that combines **rule-based heuristics** with **machine learning** to classify emails as `PHISHING` or `SAFE`. It is designed for:

- 🔐 **Security analysts** conducting email triage
- 🎓 **Researchers** studying phishing patterns
- 🛡️ **Blue teams** building automated detection pipelines
- 📚 **Students** learning applied cybersecurity and ML

PhishGuard AI provides **explainable AI output** — every detection comes with a plain-English explanation of *why* an email was flagged, a confidence score, and a risk level (Low / Medium / High / Critical).

---

## ✨ Features

### 🔎 Email Analysis
| Feature | Description |
|---|---|
| IP-based URL detection | Flags URLs using raw IP addresses instead of domain names |
| URL shortener detection | Identifies bit.ly, tinyurl.com, and 20+ other shorteners |
| Suspicious TLD detection | Flags .xyz, .tk, .ml, .cf, and other abuse-prone TLDs |
| Brand impersonation | Detects PayPal, Amazon, Google, Microsoft lookalike domains |
| Urgency keyword scoring | Quantifies pressure tactics ("act now", "account suspended") |
| Credential harvesting | Identifies password/credit card/SSN collection attempts |
| HTML form detection | Flags email-embedded forms designed to steal data |
| Obfuscated link detection | Catches JavaScript redirects and `eval()`-based tricks |
| Sender/Reply-To mismatch | Detects when reply goes to a different domain than sender |
| Header analysis | Parses raw `.eml` headers for anomalies |
| Entropy analysis | Detects encoded or obfuscated email body content |

### 🤖 Machine Learning
- **Three models** trained and compared: Naive Bayes, Logistic Regression, Random Forest
- **Automatic best-model selection** based on F1 score
- **29 engineered features** extracted per email
- **Cross-validation** with 5-fold CV reporting
- **Explainable AI** — feature-level explanations for every prediction

### 📊 Risk Levels
| Level | Probability | Meaning |
|---|---|---|
| 🟢 LOW | 0–40% | Email appears safe |
| 🟡 MEDIUM | 40–65% | Suspicious — review carefully |
| 🟠 HIGH | 65–85% | Likely phishing |
| 🔴 CRITICAL | 85–100% | Almost certainly phishing |

### 🌐 Web Dashboard
- Upload `.eml` files or paste email content
- Visual risk gauge with animated probability meter
- Colour-coded threat indicator cards with severity badges
- Full analysis history with pagination
- One-click model training with CSV dataset support

### 🔌 REST API
- `POST /api/analyze` — classify email (JSON or .eml upload)
- `POST /api/train`   — train/retrain the model
- `GET  /api/health`  — service health and model status
- `GET  /api/history` — paginated analysis history
- `GET  /api/stats`   — aggregate detection statistics

### 💻 CLI Tool
```bash
phishguard scan    suspicious.eml
phishguard train   dataset.csv
phishguard version
phishguard api     --host 0.0.0.0 --port 5000
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        PhishGuard AI v1.0.0                     │
├───────────────────┬─────────────────────┬───────────────────────┤
│   Web Dashboard   │     REST API        │     CLI Tool          │
│   (Flask/BS5)     │   /api/analyze      │  phishguard scan      │
│                   │   /api/train        │  phishguard train     │
│  ┌─────────────┐  │   /api/health       │  phishguard api       │
│  │ Upload .eml │  │   /api/history      │                       │
│  │ Paste text  │  │   /api/stats        │                       │
│  │ View result │  │                     │                       │
│  │ History     │  │                     │                       │
│  └──────┬──────┘  └──────────┬──────────┘─────────┬────────────┘
│         │                    │                     │            │
├─────────▼────────────────────▼─────────────────────▼────────────┤
│                     Core Analysis Engine                         │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │              Feature Extractor (29 features)                │ │
│  │  URL Analysis · Keyword Scoring · HTML Parsing              │ │
│  │  Entropy · Sender Analysis · Header Inspection              │ │
│  └───────────────────────────┬─────────────────────────────────┘ │
│                              │                                   │
│  ┌───────────────────────────▼─────────────────────────────────┐ │
│  │                  ML Prediction Engine                       │ │
│  │  ┌─────────────┐ ┌──────────────────┐ ┌─────────────────┐  │ │
│  │  │ Naive Bayes │ │Logistic Regress. │ │  Random Forest  │  │ │
│  │  └─────────────┘ └──────────────────┘ └────────┬────────┘  │ │
│  │                      Best model auto-selected ──┘           │ │
│  └───────────────────────────┬─────────────────────────────────┘ │
│                              │                                   │
│  ┌───────────────────────────▼─────────────────────────────────┐ │
│  │              Explainability Engine                          │ │
│  │  Risk Level · Confidence · Indicator Cards · Plain English  │ │
│  └───────────────────────────┬─────────────────────────────────┘ │
│                              │                                   │
├──────────────────────────────▼───────────────────────────────────┤
│                      SQLite Database                             │
│              Analysis history · Stats · Metadata                 │
└──────────────────────────────────────────────────────────────────┘
```

---

## 🐧 Installation (Kali Linux)

### Prerequisites

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install Python 3.12 (Kali 2024+ ships with it)
sudo apt install -y python3.12 python3.12-venv python3-pip git curl

# Verify Python version
python3 --version   # Should show Python 3.12.x
```

### Method 1 — Git Clone (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/phishguard.git
cd phishguard

# 2. Create and activate a virtual environment
python3.12 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 4. Install PhishGuard as a CLI tool
pip install -e .

# 5. Verify installation
phishguard version
```

### Method 2 — Docker (Zero-dependency)

```bash
# Pull and run with Docker
git clone https://github.com/yourusername/phishguard.git
cd phishguard/docker

# Build and start
docker compose up --build -d

# PhishGuard is now running at http://localhost:5000
```

### Method 3 — pip install

```bash
pip install phishguard-ai
phishguard version
```

---

## 🚀 Quick Start

### Step 1 — Train the Model

Before analyzing emails, the ML model must be trained:

```bash
# Using built-in synthetic training data (recommended for getting started)
phishguard train

# OR using your own labeled CSV dataset
phishguard train datasets/my_emails.csv
```

Training output:
```
──────────────────────────────────────────────────────────────
  Model Comparison
──────────────────────────────────────────────────────────────
  Model                  Accuracy       F1  AUC-ROC    Time(s)
  NaiveBayes               0.8734   0.8712   0.9201     0.03s
  LogisticRegression       0.9156   0.9143   0.9678     0.21s
  RandomForest ★           0.9467   0.9451   0.9834     1.42s
──────────────────────────────────────────────────────────────

  ✓  Best model: RandomForest (F1=0.9451)
     Saved → models/phishguard_best.pkl
```

### Step 2 — Scan an Email

```bash
# Scan a .eml file
phishguard scan suspicious.eml

# Scan with full indicator details
phishguard scan suspicious.eml --verbose

# Output as JSON (for scripting/automation)
phishguard scan suspicious.eml --json
```

### Step 3 — Start the Web Dashboard

```bash
phishguard api
# Open http://127.0.0.1:5000 in your browser
```

---

## 🌐 Web Dashboard

### Screenshots

> *[Screenshot: Dashboard overview with stats and recent history]*

> *[Screenshot: Email analysis form — paste and upload tabs]*

> *[Screenshot: Result page — risk gauge, threat indicators, feature breakdown]*

> *[Screenshot: Training page — model comparison table]*

### Usage

1. Navigate to `http://127.0.0.1:5000`
2. Click **Analyze** in the top navigation
3. Either:
   - **Paste** the email subject, sender, and body into the form, or
   - **Upload** a `.eml` file from your file system
4. Click **Analyze Now**
5. View your result with:
   - Verdict banner (PHISHING / SAFE)
   - Animated probability gauge
   - Risk level badge (LOW / MEDIUM / HIGH / CRITICAL)
   - Confidence rating
   - Threat indicator cards with severity labels
   - Feature breakdown table

---

## 🔌 REST API

### Base URL
```
http://localhost:5000/api
```

### Authentication
No authentication required for local deployment. For production, add a reverse proxy (nginx) with authentication.

---

### `GET /api/health`

Check service status and model availability.

**Response:**
```json
{
  "status": "ok",
  "service": "PhishGuard AI",
  "version": "1.0.0",
  "model_ready": true,
  "model_name": "RandomForest",
  "model_trained_at": "2024-11-15T14:32:00Z"
}
```

---

### `POST /api/analyze`

Classify an email as PHISHING or SAFE.

**Request (JSON):**
```bash
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "URGENT: Your account has been suspended",
    "body":    "Dear customer, click http://192.168.1.45/verify and enter your password now!!!",
    "sender":  "security@paypa1-alert.tk",
    "reply_to": "collect@evil-harvest.xyz"
  }'
```

**Request (.eml file upload):**
```bash
curl -X POST http://localhost:5000/api/analyze \
  -F "eml_file=@suspicious.eml"
```

**Response:**
```json
{
  "classification": "PHISHING",
  "is_phishing": true,
  "phishing_probability": 0.967,
  "phishing_probability_pct": 96.7,
  "confidence": "Very High",
  "risk": {
    "level": "critical",
    "label": "🔴 CRITICAL"
  },
  "indicators": [
    {
      "indicator": "IP-based URL detected",
      "detail": "Found 1 URL(s) using raw IP addresses instead of domain names — a classic phishing technique.",
      "severity": "high"
    },
    {
      "indicator": "Credential harvesting language",
      "detail": "Found 2 phrases requesting login credentials, passwords, or personal information.",
      "severity": "high"
    },
    {
      "indicator": "Sender/Reply-To domain mismatch",
      "detail": "The sender address domain differs from the Reply-To address.",
      "severity": "high"
    }
  ],
  "indicator_count": 3,
  "model_info": {
    "name": "RandomForest",
    "version": "1.0.0",
    "trained_at": "2024-11-15T14:32:00Z"
  }
}
```

---

### `POST /api/train`

Train or retrain the ML model.

**Request (synthetic data):**
```bash
curl -X POST http://localhost:5000/api/train
```

**Request (with CSV dataset):**
```bash
curl -X POST http://localhost:5000/api/train \
  -F "dataset=@my_emails.csv"
```

**Response:**
```json
{
  "best_model": "RandomForest",
  "metrics": {
    "accuracy": 0.9467,
    "precision": 0.9512,
    "recall": 0.9389,
    "f1": 0.9451,
    "auc_roc": 0.9834
  },
  "all_results": {
    "NaiveBayes":          { "accuracy": 0.8734, "f1": 0.8712 },
    "LogisticRegression":  { "accuracy": 0.9156, "f1": 0.9143 },
    "RandomForest":        { "accuracy": 0.9467, "f1": 0.9451 }
  },
  "message": "Training complete. Best model: RandomForest (F1=0.9451)"
}
```

---

### `GET /api/history?limit=20&offset=0`

Retrieve paginated analysis history.

---

### `GET /api/stats`

Get aggregate detection statistics.

**Response:**
```json
{
  "total": 142,
  "phishing": 87,
  "safe": 55,
  "phishing_rate": 61.3,
  "by_risk": {
    "critical": 34,
    "high": 28,
    "medium": 25,
    "low": 55
  }
}
```

---

## 💻 CLI Tool

### `phishguard scan`

```bash
# Basic scan
phishguard scan email.eml

# Verbose — shows full indicator descriptions
phishguard scan email.eml --verbose

# JSON output for scripting
phishguard scan email.eml --json

# Suppress ASCII banner
phishguard scan email.eml --no-banner

# Exit codes: 0 = safe, 1 = phishing (use in scripts/automation)
phishguard scan email.eml && echo "Safe" || echo "Phishing detected"
```

**Scan output:**
```
──────────────────────────────────────────────────────────────
  VERDICT : ⚠  PHISHING DETECTED
──────────────────────────────────────────────────────────────
  Probability : 96.7% phishing
  Confidence  : Very High
  Risk Level  : CRITICAL
  Model       : RandomForest
──────────────────────────────────────────────────────────────

  🚩 Threat Indicators (4 found)

  [CRITICAL ]  Embedded HTML form
  [HIGH     ]  IP-based URL detected
  [HIGH     ]  Credential harvesting language
  [MEDIUM   ]  High urgency language
```

---

### `phishguard train`

```bash
# Train with synthetic data (3000 samples)
phishguard train

# Train with your own dataset
phishguard train datasets/phishing_corpus.csv

# Suppress banner
phishguard train --no-banner
```

**CSV format:**
```csv
subject,body,sender,reply_to,headers,label
"URGENT verify now","Click here to verify password...","x@evil.tk","h@other.xyz","","1"
"Team meeting at 3pm","Hi all, the meeting is confirmed...","boss@company.com","","","0"
```

---

### `phishguard version`

```bash
phishguard version

#   PhishGuard AI  v1.0.0
#   MIT License | github.com/yourusername/phishguard
#
#   Model      : RandomForest
#   Trained at : 2024-11-15T14:32:00Z
#   Features   : 29
#   Accuracy   : 0.9467
#   F1 Score   : 0.9451
```

---

### `phishguard api`

```bash
# Start on default host/port (127.0.0.1:5000)
phishguard api

# Bind to all interfaces (for remote access)
phishguard api --host 0.0.0.0 --port 8080

# Development mode with auto-reload
phishguard api --debug
```

---

## 🤖 Machine Learning

### Feature Engineering (29 features)

| Category | Features |
|---|---|
| **URL** | num_urls, num_ip_urls, num_shortener_urls, num_suspicious_tld, num_misleading_domain, max_subdomains, has_at_in_url, has_long_url |
| **Keywords** | urgency_score, credential_score, suspicious_phrase_score |
| **Text** | body_entropy, exclamation_count, dollar_count, misspelling_count, word_count, caps_ratio, subject_caps_ratio, subject_length, body_length |
| **HTML** | html_present, html_form_count, html_link_count, has_obfuscation |
| **Sender** | free_provider, domain_mismatch, has_reply_to |
| **Subject** | subject_urgency, subject_exclamation |

### Models

| Model | Strengths | Typical F1 |
|---|---|---|
| **Naive Bayes** | Fast, interpretable, good baseline | 0.85–0.90 |
| **Logistic Regression** | Linear, great with scaled features | 0.90–0.94 |
| **Random Forest** | Best accuracy, handles feature interactions | 0.93–0.97 |

### Using Your Own Dataset

PhishGuard AI works with any email dataset in CSV format. Popular public datasets:

- [CEAS 2008 Spam Corpus](http://www.cs.jhu.edu/~mdredze/datasets/spam/)
- [Enron Email Dataset](https://www.cs.cmu.edu/~enron/)
- [SpamAssassin Public Corpus](https://spamassassin.apache.org/old/publiccorpus/)
- [Phishing Email Dataset (Kaggle)](https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset)

---

## 🐳 Docker Deployment

### Quick start with Docker Compose

```bash
cd docker

# Start PhishGuard AI
docker compose up -d

# Check status
docker compose ps
docker compose logs -f phishguard

# Stop
docker compose down
```

### Build from source

```bash
# Build image
docker build -t phishguard-ai:latest .

# Run container
docker run -d \
  --name phishguard \
  -p 5000:5000 \
  -v phishguard_models:/app/models \
  -e SECRET_KEY=your-secret-key \
  phishguard-ai:latest

# Train model inside container
docker exec phishguard python -c "
from ml.trainer import run_training_pipeline
run_training_pipeline()
"
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | random | Flask session secret — **change in production** |
| `FLASK_ENV` | `production` | `production` or `development` |
| `FLASK_DEBUG` | `false` | Enable debug mode |
| `PORT` | `5000` | Server port |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

---

## 🧪 Testing

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run all tests with coverage report
pytest

# Run specific test file
pytest tests/test_feature_extractor.py -v

# Run tests matching a pattern
pytest -k "test_phishing" -v

# Generate HTML coverage report
pytest --cov-report=html
open htmlcov/index.html
```

### Test Coverage Targets

| Module | Target |
|---|---|
| `ml/feature_extractor.py` | ≥ 90% |
| `ml/trainer.py` | ≥ 85% |
| `ml/predictor.py` | ≥ 85% |
| `api/routes.py` | ≥ 80% |
| `app/routes.py` | ≥ 80% |

---

## 📁 Project Structure

```
phishguard/
├── app/                          # Flask web application
│   ├── __init__.py               # App factory, limiter setup
│   ├── routes.py                 # Web dashboard routes
│   ├── database.py               # SQLite data layer
│   ├── templates/                # Jinja2 HTML templates
│   │   ├── base.html             # Base layout with navbar
│   │   ├── index.html            # Dashboard
│   │   ├── analyze.html          # Email submission form
│   │   ├── result.html           # Classification result
│   │   ├── history.html          # Analysis history
│   │   ├── train.html            # Model training page
│   │   └── error.html            # Error pages
│   └── static/
│       ├── css/style.css         # Dark cybersecurity theme
│       └── js/app.js             # Frontend interactions
│
├── ml/                           # Machine learning core
│   ├── __init__.py
│   ├── feature_extractor.py      # 29-feature engineering pipeline
│   ├── trainer.py                # Model training & evaluation
│   └── predictor.py              # Inference & explainability
│
├── api/                          # REST API blueprint
│   ├── __init__.py
│   └── routes.py                 # /api/* endpoints
│
├── cli/                          # Command-line interface
│   ├── __init__.py
│   └── phishguard.py             # Click CLI commands
│
├── tests/                        # pytest test suite
│   ├── __init__.py
│   ├── conftest.py               # Shared fixtures
│   ├── test_feature_extractor.py # Feature engineering tests
│   ├── test_trainer.py           # ML training tests
│   └── test_api.py               # REST API tests
│
├── models/                       # Saved ML models (git-ignored)
│   ├── phishguard_best.pkl       # Best trained model
│   ├── scaler.pkl                # Feature scaler
│   └── model_meta.json           # Model metadata & metrics
│
├── datasets/                     # Training data (git-ignored)
│
├── docker/
│   └── docker-compose.yml        # Docker Compose configuration
│
├── .github/
│   └── workflows/
│       └── ci.yml                # GitHub Actions CI/CD
│
├── Dockerfile                    # Multi-stage Docker build
├── wsgi.py                       # Gunicorn WSGI entry point
├── setup.py                      # Package & CLI registration
├── requirements.txt              # Python dependencies
├── pytest.ini                    # Test configuration
├── .env.example                  # Environment variable template
├── .gitignore
├── LICENSE                       # MIT License
└── README.md
```

---

## 🤝 Contributing

Contributions are welcome! PhishGuard AI is an open-source project and we appreciate all help.

### Getting Started

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/phishguard.git
cd phishguard
python3.12 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
pip install -e ".[dev]"
```

### Development Workflow

```bash
# Create a feature branch
git checkout -b feature/your-feature-name

# Make your changes, then run tests
pytest

# Check code style
black .
isort .
flake8 .

# Commit and push
git add .
git commit -m "feat: add your feature description"
git push origin feature/your-feature-name

# Open a Pull Request on GitHub
```

### Contribution Ideas

- 🔍 Add new phishing indicator detectors in `ml/feature_extractor.py`
- 📊 Integrate real phishing datasets for improved accuracy
- 🌐 Add WHOIS domain reputation checking
- 📧 Add SMTP header deep analysis (SPF/DKIM/DMARC validation)
- 🔒 Add API key authentication for production deployments
- 🌍 Add multi-language phishing keyword dictionaries
- 📱 Build a browser extension using the REST API

### Code Standards

- Follow PEP 8 (enforced by `flake8` + `black`)
- All new code must include unit tests
- Maintain ≥ 80% test coverage
- Add docstrings to all public functions
- No hardcoded secrets or credentials

---

## ⚠️ Disclaimer

PhishGuard AI is intended for **defensive security purposes only** — protecting users and organisations from phishing attacks. It is designed for:

- Email security teams triaging suspicious emails
- Security researchers studying phishing patterns
- Organisations building automated email defence pipelines
- Students learning cybersecurity and machine learning

This tool should be used in accordance with applicable laws and regulations. The authors are not responsible for any misuse.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for full text.

Copyright (c) 2024 PhishGuard AI Contributors

---

<div align="center">

**[⭐ Star on GitHub](https://github.com/yourusername/phishguard)** · **[🐛 Report Bug](https://github.com/yourusername/phishguard/issues)** · **[💡 Request Feature](https://github.com/yourusername/phishguard/issues)**

Made with ❤️ for the cybersecurity community

</div>
