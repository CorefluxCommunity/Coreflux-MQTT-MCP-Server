# Makefile for Coreflux MCP Server

.PHONY: help install install-dev test lint format security build run clean docker-build docker-run docker-stop

# Default target
help:
	@echo "Available targets:"
	@echo "  install      - Install production dependencies"
	@echo "  install-dev  - Install development dependencies"
	@echo "  test         - Run tests"
	@echo "  lint         - Run linting"
	@echo "  format       - Format code"
	@echo "  security     - Run security checks"
	@echo "  build        - Build Docker image"
	@echo "  run          - Run server directly"
	@echo "  clean        - Clean up temporary files"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Run with Docker Compose"
	@echo "  docker-stop  - Stop Docker containers"

# Installation
install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements-dev.txt

# Testing
test:
	pytest tests/ -v --cov=. --cov-report=html

# Code quality
lint:
	flake8 server.py parser.py setup_assistant.py
	mypy server.py parser.py setup_assistant.py

format:
	black server.py parser.py setup_assistant.py

# Security
security:
	bandit -r . -f json -o bandit-report.json
	safety check

# Build and run
build: docker-build

run:
	python server.py

# Docker operations
docker-build:
	docker build -t coreflux-mcp-server:latest .

docker-run:
	docker-compose up -d

docker-stop:
	docker-compose down

# Cleanup
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf build/
	rm -rf dist/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -f bandit-report.json
