# Coreflux MQTT MCP Server

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![Tests](https://img.shields.io/badge/tests-passing-green.svg)](https://github.com/CorefluxCommunity/Coreflux-MQTT-MCP-Server/actions)
[![Code Quality](https://img.shields.io/badge/code%20quality-A-green.svg)](https://github.com/CorefluxCommunity/Coreflux-MQTT-MCP-Server)

An enterprise-grade Model Context Protocol (MCP) server that provides secure, scalable access to Coreflux MQTT brokers and comprehensive automation capabilities for Claude and other MCP-compatible AI assistants.

## 🚀 Features

### Core Functionality
- 🔌 **MQTT Integration**: Seamless connection to Coreflux MQTT brokers with full TLS support
- 🛠️ **Complete Coreflux API**: Full access to models, actions, rules, and routes
- 🤖 **AI Code Generation**: LOT (Logic Object Tree) code generation via Coreflux Copilot API
- 🔍 **Dynamic Discovery**: Automatic discovery and listing of available actions
- 🏥 **Health Monitoring**: Comprehensive system health checks and monitoring

### Enterprise Features
- 🔒 **Production Security**: Comprehensive log sanitization, input validation, and security features
- ⚡ **Async Processing**: Non-blocking message processing with rate limiting and queue management
- � **Enhanced Logging**: Structured logging with rotation, filtering, and security sanitization
- ✅ **Configuration Validation**: Comprehensive environment and file validation system
- 🧪 **Testing Framework**: Complete unit testing suite with mocking and coverage reporting

### DevOps & Deployment
- 🐳 **Container Ready**: Full Docker and Kubernetes deployment support with health checks
- 🔄 **CI/CD Pipeline**: GitHub Actions with automated testing, security scanning, and quality checks
- 📦 **Development Tools**: Pre-commit hooks, code formatting, linting, and documentation generation
- ⚙️ **Easy Setup**: Interactive setup assistant with validation and testing
- 📚 **Rich Documentation**: API documentation, security guides, and deployment instructions

## Quick Start

### Docker Deployment (Recommended)

1. **Clone and configure**:
   ```bash
   git clone https://github.com/CorefluxCommunity/Coreflux-MQTT-MCP-Server.git
   cd Coreflux-MQTT-MCP-Server
   cp .env.example .env
   # Edit .env with your configuration
   ```

2. **Deploy with Docker**:
   ```bash
   docker-compose up -d
   ```

## 🚀 Quick Start

### Prerequisites

- Python 3.11 or higher
- Docker (optional, for containerized deployment)
- Access to a Coreflux MQTT broker
- Coreflux Copilot API key (optional, for AI assistance)

### Option 1: Docker Deployment (Recommended)

1. **Clone and configure**:
   ```bash
   git clone https://github.com/CorefluxCommunity/Coreflux-MQTT-MCP-Server.git
   cd Coreflux-MQTT-MCP-Server
   cp .env.example .env
   # Edit .env with your configuration
   ```

2. **Deploy with Docker**:
   ```bash
   docker-compose up -d
   ```

3. **Verify deployment**:
   ```bash
   docker-compose logs -f coreflux-mcp-server
   ```

### Option 2: Development Installation

1. **Clone and setup**:
   ```bash
   git clone https://github.com/CorefluxCommunity/Coreflux-MQTT-MCP-Server.git
   cd Coreflux-MQTT-MCP-Server
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   # For development
   pip install -r requirements-dev.txt
   ```

3. **Configure environment**:
   ```bash
   python setup_assistant.py  # Interactive configuration
   # OR
   cp .env.example .env && nano .env  # Manual configuration
   ```

4. **Validate and test**:
   ```bash
   make validate  # Validate configuration
   make test      # Run tests
   ```

5. **Start the server**:
   ```bash
   python server.py
   # OR
   make run
   ```

For detailed deployment instructions, see [DEPLOYMENT.md](DEPLOYMENT.md).

## ⚙️ Configuration

### Interactive Setup Assistant

The server includes a comprehensive setup assistant that guides you through configuration:

```bash
python setup_assistant.py
```

**The assistant helps with:**
- 🔧 MQTT broker connection settings
- 🔐 TLS certificate configuration  
- 🤖 Coreflux Copilot API integration
- 📝 Logging and monitoring setup
- ✅ Configuration validation and testing

**Use the setup assistant when:**
- Creating initial configuration
- Updating existing settings
- Troubleshooting connection issues
- Setting up TLS certificates
- Migrating between environments

### Environment Configuration

Copy `.env.example` to `.env` and configure:

```bash
# MQTT Broker Configuration
MQTT_BROKER=your-broker-host.com
MQTT_PORT=8883
MQTT_USER=your-username
MQTT_PASSWORD=your-password
MQTT_USE_TLS=true

# TLS Configuration (when MQTT_USE_TLS=true)
MQTT_CA_CERT=/path/to/ca.crt
MQTT_CERT_FILE=/path/to/client.crt  
MQTT_KEY_FILE=/path/to/client.key

# Coreflux Copilot API
DO_AGENT_API_KEY=your-api-key-here

# Logging Configuration
LOG_LEVEL=INFO
LOG_FILE=/var/log/coreflux-mcp.log
```

For detailed configuration options, see the [Configuration Guide](SECRET_MANAGEMENT.md).

## 🔌 Connecting Claude to the MCP Server

### Using Claude Desktop

1. **Locate Claude Desktop config file**:
   - macOS/Linux: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Windows: `%USERPROFILE%\AppData\Roaming\Claude\claude_desktop_config.json`

2. **Add server configuration**:
   ```json
   {
     "mcpServers": {
       "coreflux": {
         "command": "python",
         "args": ["/path/to/your/server.py"],
         "env": {
           "MQTT_BROKER": "your-broker-host.com",
           "MQTT_PORT": "8883",
           "MQTT_USER": "your-username", 
           "MQTT_PASSWORD": "your-password",
           "MQTT_USE_TLS": "true",
           "DO_AGENT_API_KEY": "your-copilot-api-key"
         }
       }
     }
   }
   ```

3. **Restart Claude Desktop**

**Security Note**: For production deployments, store secrets in secure environment variables or secret management systems rather than the Claude config file.

### Using Environment Variables

For better security, use environment variables instead of hardcoding credentials:

```json
{
  "mcpServers": {
    "coreflux": {
      "command": "python",
      "args": ["/path/to/your/server.py"],
      "env": {
        "MQTT_BROKER": "${COREFLUX_MQTT_BROKER}",
        "MQTT_PORT": "${COREFLUX_MQTT_PORT}",
        "MQTT_USER": "${COREFLUX_MQTT_USER}",
        "MQTT_PASSWORD": "${COREFLUX_MQTT_PASSWORD}",
        "DO_AGENT_API_KEY": "${COREFLUX_API_KEY}"
      }
    }
  }
}
```

### Testing the Connection

Once configured, test the connection by asking Claude:

```
Can you check the health of the Coreflux MCP server and show me the broker information?
```

Claude should respond with system status and broker details if the connection is successful.

## 🛠️ Available Tools

The server provides the following tools to Claude:

### Core MQTT Tools
- **`publish_to_coreflux`** - Publish messages to MQTT topics with QoS and retention options
- **`get_broker_info`** - Get detailed information about the MQTT broker connection

### AI Assistance Tools  
- **`copilot_assist`** - Query the Coreflux Copilot AI for automation assistance and code generation

### System Management Tools
- **`comprehensive_health_check`** - Perform detailed health checks of all system components

For detailed API documentation, see [API_DOCUMENTATION.md](API_DOCUMENTATION.md).

## 🧪 Development & Testing

### Development Setup

1. **Install development dependencies**:
   ```bash
   pip install -r requirements-dev.txt
   ```

2. **Install pre-commit hooks**:
   ```bash
   pre-commit install
   ```

3. **Run the full development setup**:
   ```bash
   make dev-setup  # Complete development environment setup
   ```

### Testing

Run the comprehensive test suite:

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run specific test categories
make test-unit        # Unit tests only
make test-integration # Integration tests only
```

### Code Quality

Maintain code quality with automated tools:

```bash
# Format code
make format

# Run linters
make lint

# Security scanning
make security-check

# Type checking
make type-check

# Run all quality checks
make quality-check
```

Available development commands:

```bash
# Development workflow
make dev-setup     # Set up complete development environment
make validate      # Validate configuration and environment  
make run           # Start the server with validation
make run-debug     # Start server in debug mode

# Testing and validation
make test          # Run all tests
make test-coverage # Run tests with coverage report
make test-unit     # Run unit tests only
make validate-config # Validate configuration files

# Code quality
make format        # Format code with black and isort
make lint          # Run all linters (flake8, bandit, mypy)
make security-check # Run security scanning
make type-check    # Run type checking with mypy

# Docker operations  
make docker-build  # Build Docker image
make docker-run    # Run in Docker container
make docker-test   # Run tests in Docker

# Documentation
make docs          # Generate documentation
make docs-serve    # Serve documentation locally
```

## 🔧 System Architecture

### Core Components

- **`server.py`** - Main MCP server with tool implementations
- **`config_validator.py`** - Configuration validation and environment checking
- **`message_processor.py`** - Asynchronous MQTT message processing with rate limiting
- **`enhanced_logging.py`** - Structured logging with rotation and security filtering
- **`config_schema.py`** - Pydantic schemas for type-safe configuration
- **`parser.py`** - Sanitization and parsing utilities

### Security Features

- **Input Sanitization** - All inputs are sanitized to prevent injection attacks
- **Log Security** - Automatic sanitization of sensitive data in logs
- **TLS Support** - Full TLS encryption for MQTT connections
- **Configuration Validation** - Comprehensive validation of all configuration parameters
- **Secret Management** - Secure handling of credentials and API keys

### Performance Features

- **Async Processing** - Non-blocking message processing
- **Connection Pooling** - Efficient MQTT connection management
- **Rate Limiting** - Configurable rate limits to prevent abuse
- **Health Monitoring** - Real-time health checks and system monitoring

## 📚 Documentation

- **[API Documentation](API_DOCUMENTATION.md)** - Complete API reference
- **[Deployment Guide](DEPLOYMENT.md)** - Production deployment instructions
- **[Secret Management](SECRET_MANAGEMENT.md)** - Security and secret management guide
- **[Configuration Reference](.env.example)** - Complete configuration options

## 🐳 Docker Deployment

### Quick Start with Docker

```bash
# Clone and configure
git clone https://github.com/CorefluxCommunity/Coreflux-MQTT-MCP-Server.git
cd Coreflux-MQTT-MCP-Server

# Copy and edit environment file
cp .env.example .env
nano .env  # Configure your settings

# Start with Docker Compose
docker-compose up -d

# Check logs
docker-compose logs -f coreflux-mcp-server

# Health check
docker-compose exec coreflux-mcp-server python -c "
import os
os.system('python server.py --health-check')
"
```

### Production Docker Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for comprehensive production deployment instructions including:

- Multi-stage Docker builds
- Kubernetes deployments
- Health checks and monitoring
- Load balancing and scaling
- Security configurations

## 🔑 Coreflux Copilot Integration

The server includes powerful AI assistance through the Coreflux Copilot API:

### Setup

1. **Obtain API Key** from the Coreflux Copilot dashboard
2. **Configure the key**:
   ```bash
   # Option 1: Environment file
   echo "DO_AGENT_API_KEY=your_api_key_here" >> .env
   
   # Option 2: Environment variable
   export DO_AGENT_API_KEY=your_api_key_here
   ```

### Features

- **LOT Code Generation** - Generate Logic Object Tree code from natural language
- **Automation Assistance** - Get help with Coreflux automation tasks
- **Best Practices** - Receive guidance on optimal implementations
- **Troubleshooting** - Get assistance with debugging and optimization

### Usage Examples

Ask Claude to help with Coreflux automation:

```
Generate LOT code for a temperature monitoring system that triggers an alert when the temperature exceeds 75°F
```

```
Help me create a rule that processes sensor data and stores it in a database
```

## 🚀 Advanced Features

### Asynchronous Message Processing

The server includes a robust async message processor that:

- **Prevents Blocking** - Handles messages without blocking the main thread
- **Rate Limiting** - Configurable limits to prevent system overload  
- **Queue Management** - Intelligent queue handling with backpressure
- **Statistics** - Real-time processing metrics and monitoring

### Enhanced Logging System

Comprehensive logging with enterprise features:

- **Structured Logging** - JSON formatted logs for easy parsing
- **Log Rotation** - Automatic log file rotation to manage disk space
- **Security Filtering** - Automatic sanitization of sensitive information
- **Multiple Outputs** - Console, file, and syslog support

### Configuration Validation

Robust validation system that checks:

- **Environment Variables** - Validates all required configuration
- **File Permissions** - Ensures certificate files are accessible
- **Network Connectivity** - Tests MQTT broker connectivity
- **API Availability** - Validates Copilot API access

## 🛡️ Security & Compliance

### Security Features

- **Input Sanitization** - All inputs validated and sanitized
- **TLS Encryption** - Full TLS support for MQTT connections
- **Secret Management** - Secure credential handling
- **Audit Logging** - Comprehensive security event logging
- **Non-root Execution** - Runs with minimal privileges

### Compliance Support

The server supports various compliance requirements:

- **SOC 2** - Security controls and monitoring
- **GDPR** - Data protection and privacy
- **HIPAA** - Healthcare data protection (when properly configured)

For detailed security information, see [SECRET_MANAGEMENT.md](SECRET_MANAGEMENT.md).

## 📊 Monitoring & Health Checks

### Health Check Tool

Comprehensive health monitoring with the `comprehensive_health_check` tool:

```bash
# Manual health check
python server.py --health-check

# Or ask Claude:
# "Please run a comprehensive health check on the Coreflux MCP server"
```

### Monitoring Metrics

The server provides detailed metrics:

- **Connection Status** - MQTT broker connectivity
- **Message Processing** - Queue size and processing rates
- **System Resources** - Memory and CPU usage
- **Error Rates** - Failed operations and error statistics
- **API Status** - Copilot API availability and response times

### Alerting

Configure alerts for:

- Connection failures
- High error rates
- Resource exhaustion
- Security events

## 🤝 Contributing

We welcome contributions! Please see our contribution guidelines:

### Development Process

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Install** development dependencies: `pip install -r requirements-dev.txt`
4. **Setup** pre-commit hooks: `pre-commit install`
5. **Make** your changes with tests
6. **Run** quality checks: `make quality-check`
7. **Commit** your changes: `git commit -am 'Add amazing feature'`
8. **Push** to the branch: `git push origin feature/amazing-feature`
9. **Create** a Pull Request

### Code Standards

- **Python 3.11+** compatibility
- **Type hints** for all functions
- **Comprehensive tests** with >90% coverage
- **Security scanning** with bandit
- **Code formatting** with black and isort
- **Documentation** for all public APIs

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🆘 Support & Troubleshooting

### Common Issues

**Connection Refused**
```
Error: MQTT connection failed
```
- Check broker hostname and port
- Verify network connectivity
- Confirm TLS configuration

**Authentication Failed**
```
Error: Authentication failed
```
- Verify username/password
- Check API key validity
- Confirm broker permissions

**TLS Handshake Failed**
```
Error: TLS handshake failed
```
- Verify certificate paths
- Check certificate validity
- Confirm TLS version compatibility

### Debug Mode

Enable detailed logging for troubleshooting:

```bash
export LOG_LEVEL=DEBUG
python server.py
```

### Getting Help

- **GitHub Issues**: [Report bugs and request features](https://github.com/CorefluxCommunity/Coreflux-MQTT-MCP-Server/issues)
- **Discussions**: [Community support and questions](https://github.com/CorefluxCommunity/Coreflux-MQTT-MCP-Server/discussions)
- **Documentation**: [Complete documentation](./API_DOCUMENTATION.md)
- **Security Issues**: Report to security@coreflux.org

## 🗺️ Roadmap

### Current Status: v1.0.0 ✅

- ✅ Core MQTT functionality
- ✅ Copilot API integration
- ✅ Enterprise security features
- ✅ Comprehensive testing
- ✅ Production deployment support

### Upcoming Features

- **v1.1.0** - Enhanced monitoring and metrics
- **v1.2.0** - Additional Coreflux API endpoints
- **v1.3.0** - WebSocket support for real-time data
- **v2.0.0** - Multi-broker support and federation

---

## 📋 Quick Reference

### Essential Commands

```bash
# Setup and configuration
python setup_assistant.py    # Interactive setup
make validate                 # Validate configuration

# Development
make dev-setup               # Complete dev environment
make test                    # Run all tests
make quality-check           # Run all quality checks

# Deployment
docker-compose up -d         # Docker deployment
make docker-build           # Build Docker image

# Monitoring
make health-check           # System health check
docker-compose logs -f      # View logs
```

### Key Files

- **`server.py`** - Main MCP server
- **`.env`** - Configuration file
- **`requirements.txt`** - Python dependencies
- **`docker-compose.yml`** - Docker deployment
- **`Makefile`** - Development commands

---

**Built with ❤️ by the Coreflux Community**
- `remove_action`: Remove an action event/function
- `run_action`: Run an action event/function
- `remove_all_models`: Remove all models
- `remove_all_actions`: Remove all actions
- `remove_all_routes`: Remove all routes
- `list_discovered_actions`: List all discovered Coreflux actions
- `request_lot_code`: Generate LOT code using Coreflux Copilot API based on natural language prompts

## Debugging and Troubleshooting

The MCP server now starts even if the MQTT broker is not available, allowing you to troubleshoot and configure connections through the MCP tools.

### Connection Status and Recovery

- The server will start successfully even if the MQTT broker is unreachable
- Use the `get_connection_status` tool to check connection health and get troubleshooting guidance
- Use the `setup_mqtt_connection` tool to configure a new broker connection without restarting
- Use the `check_broker_health` or `reconnect_mqtt` tools to test and retry connections

### Available Tools for Connection Management

- `get_connection_status`: Get detailed connection status with troubleshooting guidance
- `setup_mqtt_connection`: Configure a new MQTT broker connection dynamically
- `mqtt_connect`: Connect to a specific MQTT broker with custom parameters
- `check_broker_health`: Test broker connectivity and attempt reconnection
- `reconnect_mqtt`: Force reconnection to the configured broker

### Traditional Troubleshooting Steps

If you encounter issues:

1. Verify your MQTT broker credentials in your Claude configuration
2. Ensure the broker is accessible 
3. Run the setup assistant to verify or update your configuration:
   ```bash
   python setup_assistant.py
   ```
4. Check Claude Desktop logs:
   ```bash
   # Check Claude's logs for errors (macOS/Linux)
   tail -n 20 -f ~/Library/Logs/Claude/mcp*.log
   # Windows PowerShell
   Get-Content -Path "$env:USERPROFILE\AppData\Roaming\Claude\Logs\mcp*.log" -Tail 20 -Wait
   ```
5. Run the server with debug logging:
   ```bash
   # Direct execution with debug logging
   python server.py --mqtt-host localhost --mqtt-port 1883 --log-level DEBUG
   ```

## References and Documentation

- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Production deployment guide
- **[SECURITY.md](SECURITY.md)** - Security guidelines and best practices
- **[MCP Documentation](https://modelcontextprotocol.io/)** - Official MCP documentation
- **[Coreflux Platform](https://coreflux.org/)** - Coreflux automation platform

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to the `development` branch.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Support

- 📖 Documentation: Check the README, DEPLOYMENT.md, and SECURITY.md files
- 🐛 Issues: Report bugs and feature requests on GitHub
- 💬 Community: Join the Coreflux community for discussions
