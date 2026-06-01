# Development Guide

## Setup

### Prerequisites

- Python 3.8+
- pip
- Git

### Clone and Install

```bash
git clone https://github.com/Arbeiter-bit/NSA-CampusNetwork.git
cd NSA-CampusNetwork

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

pip install -r requirements.txt
pip install -r requirements-dev.txt  # dev dependencies
```

### Verify Setup

```bash
python check_project.py
python app.py  # Visit http://localhost:5001
```

## Project Structure

```
NSA-CampusNetwork/
├── app.py                  # Flask application entry point
├── utils/                  # Core analysis modules
│   ├── analysis.py         # Traffic analysis & Plotly charts
│   ├── user_profile.py     # User profiling & tag generation
│   ├── ai_security.py      # AI security audit & DeepSeek review
│   ├── ml_anomaly.py       # IsolationForest anomaly detection
│   ├── realtime.py         # SSE replay engine
│   ├── cache.py            # In-memory caching
│   ├── metrics.py          # Prometheus-style metrics
│   ├── constants.py        # Shared constants
│   └── response.py         # Response helpers
├── templates/              # Jinja2 HTML templates
│   ├── index.html          # Home page
│   ├── dashboard.html      # Security dashboard
│   └── realtime.html       # Real-time dashboard
├── data/                   # Data storage
│   ├── traffic.csv         # Sample traffic data
│   └── user_profiles.json  # Generated profiles
├── tests/                  # Test suite
├── docs/                   # Documentation
├── config.yaml             # Application configuration
└── pyproject.toml          # Project metadata & tool config
```

## Running Tests

```bash
# Run all tests
make test

# Or with pytest directly
pytest

# With coverage
pytest --cov=utils --cov-report=term

# Run specific test file
pytest tests/test_analysis.py

# Run tests matching a pattern
pytest -k "ml_anomaly"
```

## Code Style

This project uses:

| Tool      | Purpose            | Config Location     |
| --------- | ------------------ | ------------------- |
| flake8    | Linting            | `.pylintrc`         |
| black     | Formatting         | `pyproject.toml`    |
| isort     | Import ordering    | `pyproject.toml`    |
| mypy      | Type checking      | `mypy.ini`          |
| pre-commit| Hook automation    | `.pre-commit-config.yaml` |

### Conventions

- Line length: 100 characters
- Indentation: 4 spaces
- Type hints required for all function signatures
- Descriptive variable names (avoid single-letter names except in comprehensions)
- Keep functions focused and single-purpose
- Docstrings for public functions and classes

### Pre-commit Hooks

```bash
# Install hooks
pre-commit install

# Run hooks manually
pre-commit run --all-files
```

## Making Contributions

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes with clear commit messages
4. Run tests: `make test`
5. Run linters: `flake8 utils/ tests/`
6. Open a pull request

### Commit Message Format

Follow conventional commits:

```
feat: add new analysis metric for latency
fix: correct timestamp parsing for edge cases
docs: update API endpoint documentation
refactor: extract common validation logic
test: add tests for user profile edge cases
```

## Docker Development

```bash
# Build and run with live reload
docker-compose up --build

# Run tests in Docker
docker-compose exec web pytest
```

## Debugging

- Set `FLASK_DEBUG=true` in `.env` for auto-reload
- Check Flask logs at the configured log level in `config.yaml`
- Use `logger.debug()` for detailed debugging output
- Prometheus metrics available at `/api/metrics`
