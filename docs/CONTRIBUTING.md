# Contributing to Coreflux MCP Server

We welcome contributions to the Coreflux MCP Server! This document provides guidelines for contributing to the project.

## Development Setup

### Prerequisites

- Python 3.11 or higher
- Docker and Docker Compose
- Git

### Local Development

1. **Fork and clone the repository**:
   ```bash
   git clone https://github.com/your-username/Coreflux-MQTT-MCP-Server.git
   cd Coreflux-MQTT-MCP-Server
   ```

2. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install development dependencies**:
   ```bash
   pip install -r requirements-dev.txt
   ```

4. **Set up environment**:
   ```bash
   cp examples/.env.development .env
   # Edit .env with your development configuration
   ```

5. **Run the setup assistant**:
   ```bash
   python setup_assistant.py
   ```

## Development Workflow

### Code Style

We use the following tools to maintain code quality:

- **Black**: Code formatting
- **Flake8**: Linting
- **MyPy**: Type checking
- **Bandit**: Security analysis

Run all checks:
```bash
make lint
make format
make security
```

### Testing

Currently, the project uses manual testing. We welcome contributions to add automated tests:

```bash
# Run tests (when available)
make test

# Run with coverage
pytest --cov=. --cov-report=html
```

### Docker Development

Test your changes with Docker:

```bash
# Build and test locally
make docker-build
make docker-run

# Check logs
docker-compose logs -f

# Stop containers
make docker-stop
```

## Contribution Guidelines

### Pull Request Process

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**:
   - Follow the existing code style
   - Add docstrings for new functions
   - Update documentation if needed

3. **Test your changes**:
   ```bash
   make lint
   make security
   make docker-build
   ```

4. **Commit your changes**:
   ```bash
   git add .
   git commit -m "feat: add your feature description"
   ```

5. **Push and create a Pull Request**:
   ```bash
   git push origin feature/your-feature-name
   ```

### Commit Message Format

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `style:` - Code style changes (formatting, etc.)
- `refactor:` - Code refactoring
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks

Examples:
```
feat: add TLS certificate validation
fix: resolve MQTT connection timeout issue
docs: update deployment guide
chore: update dependencies
```

### Branch Strategy

- `main` - Production-ready code
- `development` - Development branch for new features
- `feature/*` - Feature branches
- `hotfix/*` - Critical bug fixes

## Areas for Contribution

We welcome contributions in the following areas:

### High Priority

- **Automated Testing**: Unit tests, integration tests
- **Performance Optimization**: Connection pooling, caching
- **Error Handling**: Improved error messages and recovery
- **Documentation**: API documentation, tutorials

### Medium Priority

- **Monitoring**: Metrics collection, health checks
- **Configuration**: Environment validation, configuration UI
- **Security**: Enhanced authentication, audit logging
- **Deployment**: Helm charts, Terraform modules

### Lower Priority

- **Features**: Additional MCP tools, MQTT features
- **UI**: Web interface for monitoring
- **Integration**: Additional broker support

## Code Review Process

All contributions must go through code review:

1. **Automated Checks**: CI/CD pipeline runs automatically
2. **Peer Review**: At least one maintainer review required
3. **Testing**: Manual testing in development environment
4. **Documentation**: Ensure documentation is updated

## Documentation

When contributing, please update relevant documentation:

- **README.md**: For user-facing changes
- **DEPLOYMENT.md**: For deployment-related changes
- **SECURITY.md**: For security-related changes
- **Code Comments**: For complex logic
- **CHANGELOG.md**: For all changes

## Security

### Reporting Security Issues

**Do not open public issues for security vulnerabilities.**

Instead:
1. Email the maintainers privately
2. Provide detailed information
3. Allow time for the issue to be addressed
4. Coordinate public disclosure

### Security Guidelines

- Never commit secrets or credentials
- Use environment variables for configuration
- Follow the security guidelines in [SECURITY.md](SECURITY.md)
- Run security checks before submitting

## Getting Help

If you need help or have questions:

- **Issues**: Open a GitHub issue for bugs or feature requests
- **Discussions**: Use GitHub Discussions for questions
- **Documentation**: Check existing documentation first
- **Community**: Join the Coreflux community

## Recognition

Contributors will be recognized in:
- **CHANGELOG.md**: For significant contributions
- **GitHub**: Through GitHub's contributor features
- **Documentation**: In acknowledgments section

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0, the same license as the project.

Thank you for contributing to the Coreflux MCP Server!
