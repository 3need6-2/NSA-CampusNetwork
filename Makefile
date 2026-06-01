.PHONY: run dev install test lint format check coverage clean docker-build docker-run backup clean-data help

help:
	@echo "NSA-CampusNetwork - Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make install      Install Python dependencies"
	@echo "  make run          Start Flask application (port 5001)"
	@echo "  make dev          Start Flask in debug mode"
	@echo "  make test         Run tests with pytest"
	@echo "  make lint         Lint Python code with flake8"
	@echo "  make format       Format code with black and isort"
	@echo "  make check        Run lint and typecheck"
	@echo "  make coverage     Run tests with coverage report"
	@echo "  make clean        Remove __pycache__ and .pyc files"
	@echo "  make docker-build Build Docker image"
	@echo "  make docker-run   Run Docker container (port 5001)"
	@echo "  make backup       Create timestamped ZIP backup of data/"
	@echo "  make clean-data   Remove cached analysis data files"

install:
	pip install -r requirements.txt

run:
	python app.py

dev:
	FLASK_ENV=development python app.py

test:
	python -m pytest tests/ -v --tb=short

lint:
	flake8 . --count --show-source --statistics

format:
	black .
	isort .

coverage:
	python -m pytest --cov=. tests/

check: lint
	@echo "--- Typecheck ---"
	-command -v mypy >/dev/null 2>&1 && mypy . || echo "mypy not installed, skipping typecheck"

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete

docker-build:
	docker build -t nsa-campus-network .

docker-run:
	docker run -p 5001:5001 nsa-campus-network

backup:
	python -m utils.backup

clean-data:
	rm -f data/traffic.csv data/user_profiles.json data/analysis.db
	@echo "Cleaned cached analysis data."
