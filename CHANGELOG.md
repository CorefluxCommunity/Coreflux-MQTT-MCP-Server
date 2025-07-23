# Changelog

All notable changes to the Coreflux MQTT MCP Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Production-ready Docker configuration with multi-stage builds
- Docker Compose configuration with optional MQTT broker
- Kubernetes deployment manifests
- Comprehensive security documentation (SECURITY.md)
- Production deployment guide (DEPLOYMENT.md)
- Log sanitization for sensitive information
- Non-root Docker container execution
- Health checks for container deployments
- Resource limits and security contexts
- Certificate management for TLS connections
- Environment-based configuration management

### Changed
- Updated README.md with production deployment instructions
- Enhanced requirements.txt with version pinning and security considerations
- Improved error handling and logging

### Security
- Implemented comprehensive log sanitization
- Added secure defaults for Docker deployments
- Enhanced certificate handling for TLS connections
- Added security guidelines and best practices documentation

## [1.0.0] - Initial Release

### Added
- Model Context Protocol (MCP) server implementation
- Coreflux MQTT broker integration
- Support for all Coreflux commands (models, actions, rules, routes)
- Dynamic action discovery functionality
- LOT (Logic Object Tree) code generation via Coreflux Copilot API
- Interactive setup assistant
- TLS support for MQTT connections
- Comprehensive configuration options
- Claude Desktop integration guide
- Built-in LOT language documentation

### Features
- `add_rule`, `remove_rule` - Permission rule management
- `add_route`, `remove_route` - Route connection management
- `add_model`, `remove_model` - Model structure management
- `add_action`, `remove_action`, `run_action` - Action management
- `list_discovered_actions` - Action discovery
- `request_lot_code` - AI-powered LOT code generation
- Connection management tools for troubleshooting
