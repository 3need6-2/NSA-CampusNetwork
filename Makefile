.PHONY: run dev install test lint clean docker-build docker-run help

help:
	@echo "NSA-CampusNetwork - Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make install      Install Python dependencies"
	@echo "  make run          Start Flask application (port 5001)"
	@echo "  make dev          Start Flask in debug mode"
	@echo "  make test         Run tests with pytest"
	@echo "  make lint         Lint Python code with flake8"
	@echo "  make clean        Remove __pycache__ and .pyc files"
	@echo "  make docker-build Build Docker image"
	@echo "  make docker-run   Run Docker container (port 5001)"

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

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete

docker-build:
	docker build -t nsa-campus-network .

docker-run:
	docker run -p 5001:5001 nsa-campus-network
