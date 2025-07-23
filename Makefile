# Makefile for Coreflux MCP Server

.PHONY: help install install-dev test test-unit test-integration lint format security validate-config build run clean docker-build docker-run docker-stop logs health-check

# Default target
help:
	@echo "Available targets:"
	@echo "  install          - Install production dependencies"
	@echo "  install-dev      - Install development dependencies"
	@echo "  test             - Run all tests"
	@echo "  test-unit        - Run unit tests only"
	@echo "  test-integration - Run integration tests only"
	@echo "  lint             - Run linting"
	@echo "  format           - Format code"
	@echo "  security         - Run security checks"
	@echo "  validate-config  - Validate current configuration"
	@echo "  build            - Build Docker image"
	@echo "  run              - Run server directly"
	@echo "  clean            - Clean up temporary files"
	@echo "  docker-build     - Build Docker image"
	@echo "  docker-run       - Run with Docker Compose"
	@echo "  docker-stop      - Stop Docker containers"
	@echo "  logs             - View Docker logs"
	@echo "  health-check     - Run health check script"

# Installation
install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements-dev.txt
	pre-commit install

# Testing
test: test-unit test-integration

test-unit:
	pytest tests/test_server.py -v --cov=. --cov-report=html --cov-report=term

test-integration:
	pytest tests/ -v -k "integration" --cov=. --cov-report=html

# Code quality
lint:
	flake8 server.py parser.py setup_assistant.py config_validator.py message_processor.py enhanced_logging.py config_schema.py --max-line-length=120
	mypy server.py parser.py setup_assistant.py config_validator.py message_processor.py enhanced_logging.py config_schema.py --ignore-missing-imports

format:
	black server.py parser.py setup_assistant.py config_validator.py message_processor.py enhanced_logging.py config_schema.py healthcheck.py --line-length=120

# Security
security:
	bandit -r . -f json -o bandit-report.json -x tests/
	safety check

# Configuration validation
validate-config:
	python -c "from config_validator import ConfigurationValidator; import logging; logger = logging.getLogger(); validator = ConfigurationValidator(logger); validator.log_configuration_status()"

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

logs:
	docker-compose logs -f coreflux-mcp-server

# Health check
health-check:
	python healthcheck.py

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
	rm -rf logs/*.log*

# Development utilities
setup:
	python setup_assistant.py

check-deps:
	pip-audit

update-deps:
	pip-review --auto

docs:
	sphinx-build -b html docs/ docs/_build/html

# CI/CD simulation
ci: lint security test
	@echo "✅ All CI checks passed"
