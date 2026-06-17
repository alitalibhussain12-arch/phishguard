# Contributing to PhishGuard AI

Thank you for your interest in contributing! This guide covers everything you need to get started.

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Architecture Overview](#architecture-overview)

---

## Code of Conduct

This project follows the [Contributor Covenant](https://www.contributor-covenant.org/). Be respectful, inclusive, and constructive. Harassment or abusive behaviour will not be tolerated.

---

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally
3. **Create a branch** for your feature or bugfix
4. **Make changes** with tests
5. **Open a Pull Request**

---

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/phishguard.git
cd phishguard

# Create virtual environment
python3.12 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install in editable mode with dev dependencies
pip install -r requirements.txt
pip install -e .
pip install black isort flake8 bandit

# Verify everything works
phishguard version
pytest tests/ -v
```

---

## Making Changes

### Branch Naming
- `feature/short-description` — new features
- `fix/short-description` — bug fixes
- `docs/short-description` — documentation only
- `refactor/short-description` — code refactoring

### Commit Messages (Conventional Commits)
```
feat: add DKIM header validation
fix: handle malformed .eml files gracefully
docs: update API endpoint documentation
test: add edge cases for URL shortener detection
refactor: simplify feature vector ordering
```

### Code Style
```bash
# Format code
black .

# Sort imports
isort .

# Lint
flake8 . --max-line-length=100 --exclude=.git,__pycache__,htmlcov,models,datasets

# Security scan
bandit -r . --exclude tests,models,datasets
```

---

## Testing

All contributions **must** include tests. We maintain ≥ 80% test coverage.

```bash
# Run full test suite
pytest

# Run with verbose output
pytest -v

# Run specific module
pytest tests/test_feature_extractor.py -v

# Run tests matching a keyword
pytest -k "test_url" -v

# Check coverage
pytest --cov-report=html
open htmlcov/index.html
```

### Writing Tests

- Place tests in `tests/test_<module_name>.py`
- Use descriptive class names: `class TestUrlShortenerDetection:`
- Use descriptive method names: `def test_detects_bitly_links(self):`
- Cover both positive cases (feature triggers) and negative cases (no false positives)
- Use `tmp_path` and `monkeypatch` fixtures for filesystem isolation

---

## Pull Request Process

1. Ensure all tests pass: `pytest`
2. Ensure code is formatted: `black --check .`
3. Update `README.md` if you added user-facing features
4. Fill in the PR template completely
5. Link any related issues with `Closes #123`
6. Request a review from a maintainer

### PR Checklist
- [ ] Tests pass locally (`pytest`)
- [ ] Code formatted (`black .`, `isort .`)
- [ ] No new linting errors (`flake8 .`)
- [ ] Test coverage maintained ≥ 80%
- [ ] README updated (if applicable)
- [ ] Commit messages follow Conventional Commits format

---

## Architecture Overview

```
PhishGuard AI
├── ml/feature_extractor.py   ← Add new detection features HERE
├── ml/trainer.py             ← Modify training pipeline here
├── ml/predictor.py           ← Modify inference / explainability here
├── api/routes.py             ← Add new API endpoints here
├── app/routes.py             ← Add new web pages here
├── app/templates/            ← Jinja2 HTML templates
├── app/static/css/style.css  ← Dark theme CSS
└── cli/phishguard.py         ← Add new CLI commands here
```

### Adding a New Phishing Indicator

1. Open `ml/feature_extractor.py`
2. Add your detection function following the existing pattern
3. Add the feature to `extract_features()` return dict
4. Add the feature name to `get_feature_names()` list
5. Add the vector position to `features_to_vector()` (must match `get_feature_names()` order)
6. Optionally add an explanation to `explain_features()`
7. Add to the synthetic data generator in `ml/trainer.py`
8. Write tests in `tests/test_feature_extractor.py`

### Adding a New API Endpoint

1. Open `api/routes.py`
2. Add your route using the `@api_bp.route()` decorator
3. Apply `@limiter.limit()` for rate limiting
4. Add tests in `tests/test_api.py`
5. Document the endpoint in `README.md`

---

## Good First Issues

Look for issues tagged `good first issue` on GitHub. These are well-scoped tasks ideal for new contributors:

- Adding new phishing keyword dictionaries for other languages
- Improving the explainability descriptions
- Adding more edge-case tests
- Improving error messages in the CLI
- Adding CSV export for analysis history

---

## Questions?

Open a [GitHub Discussion](https://github.com/yourusername/phishguard/discussions) or file an [Issue](https://github.com/yourusername/phishguard/issues).
