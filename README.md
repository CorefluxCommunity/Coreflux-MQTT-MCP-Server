# Coreflux MQTT MCP Server

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)

A production-ready Model Context Protocol (MCP) server that connects to Coreflux MQTT brokers and provides Coreflux automation capabilities to Claude and other MCP-compatible AI assistants.

## Features

- 🔌 **MQTT Integration**: Seamless connection to Coreflux MQTT brokers with TLS support
- 🛠️ **Complete Coreflux API**: Full access to models, actions, rules, and routes
- 🤖 **AI Code Generation**: LOT (Logic Object Tree) code generation via Coreflux Copilot API
- 🔍 **Dynamic Discovery**: Automatic discovery and listing of available actions
- 🔒 **Production Security**: Comprehensive log sanitization and security features
- 🐳 **Docker Ready**: Full Docker and Kubernetes deployment support
- ⚙️ **Easy Setup**: Interactive setup assistant for quick configuration
- 📚 **Rich Documentation**: Built-in LOT language documentation and examples

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

### Direct Installation

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run setup assistant**:
   ```bash
   python setup_assistant.py
   ```

3. **Start the server**:
   ```bash
   python server.py
   ```

For detailed deployment instructions, see [DEPLOYMENT.md](DEPLOYMENT.md).

## Configuration

### Setup Assistant

The server includes an interactive setup assistant for easy configuration:

- You need to create an initial configuration (.env file)
- You want to update your existing configuration
- You're experiencing connection issues and need to reconfigure

To run the setup assistant:

```bash
python setup_assistant.py
```

**Use the setup assistant when:**
- Creating initial configuration (.env file)
- Updating existing configuration
- Experiencing connection issues
- Setting up TLS certificates

The assistant helps configure:
- MQTT broker settings (host, port, credentials)
- TLS configuration and certificates
- Coreflux Copilot API integration
- Logging preferences

## Connecting Claude to the MCP Server

### Using Claude Desktop Config

1. Create or edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS/Linux) or `%USERPROFILE%\AppData\Roaming\Claude\claude_desktop_config.json` (Windows)
2. Add the following configuration (adjust the paths accordingly):
   ```json
   {
     "mcpServers": {
       "coreflux": {
         "command": "python",
         "args": [
           "/PATH/TO/server.py",
           "--mqtt-host", "localhost", 
           "--mqtt-port", "1883",
           "--mqtt-user", "root",
           "--mqtt-password", "coreflux",
           "--mqtt-client-id", "claude-coreflux-client",
           "--do-agent-api-key", "your_coreflux_copilot_api_key_here"
         ],
         "description": "Coreflux MQTT Broker Control",
         "icon": "🔄",
         "env": {}
       }
     }
   }
   ```
   **Note**: Instead of passing the API key as a command-line argument, you can set it in the `.env` file for better security.
   
   **Tip**: A sample `claude_desktop_config.json` file is included in this repository that you can use as a starting point.
3. Restart Claude Desktop

### Command-Line Arguments

The server accepts the following command-line arguments. These settings can also be configured via the `.env` file using the setup assistant:

| Argument | Description | Default |
|----------|-------------|---------|
| `--mqtt-host` | MQTT broker address | localhost |
| `--mqtt-port` | MQTT broker port | 1883 |
| `--mqtt-user` | MQTT username | - |
| `--mqtt-password` | MQTT password | - |
| `--mqtt-client-id` | MQTT client ID | claude-mcp-client |
| `--mqtt-use-tls` | Enable TLS for MQTT connection | false |
| `--mqtt-ca-cert` | Path to CA certificate file | - |
| `--mqtt-client-cert` | Path to client certificate file | - |
| `--mqtt-client-key` | Path to client key file | - |
| `--do-agent-api-key` | Coreflux Copilot API key | - |
| `--log-level` | Logging level (DEBUG/INFO/WARNING/ERROR/CRITICAL) | INFO |

## Coreflux Copilot API Configuration

The server includes a `request_lot_code` tool that uses the Coreflux Copilot API to generate LOT (Logic Object Tree) code based on natural language prompts. To use this feature, you need to:

1. **Get an API key** from the Coreflux Copilot dashboard
2. **Set the API key** in your `.env` file:
   ```bash
   DO_AGENT_API_KEY=your_coreflux_copilot_api_key_here
   ```
3. **Or pass it as a command-line argument**:
   ```bash
   python server.py --do-agent-api-key your_api_key_here
   ```

**Note**: Without the API key, the LOT code generation feature will not work. The setup assistant will prompt you to configure this when you run it.

**API Endpoint**: The server is pre-configured to connect to the Coreflux Copilot API endpoint. The request format conforms to the chat completions API specification with proper authentication headers.

## Production Deployment

### Docker Deployment

For production environments, use Docker with proper configuration:

```bash
# Copy and customize environment
cp .env.example .env
cp docker-compose.override.yml.example docker-compose.override.yml

# Configure for production
docker-compose up -d
```

### Security Features

- **Log Sanitization**: Automatic redaction of sensitive information in logs
- **TLS Support**: Full TLS encryption for MQTT connections
- **Non-root Containers**: Docker containers run as non-privileged users
- **Secret Management**: Environment-based configuration for sensitive data

See [SECURITY.md](SECURITY.md) for detailed security guidelines and [DEPLOYMENT.md](DEPLOYMENT.md) for production deployment instructions.

## Available Tools

The server provides tools for common Coreflux commands:

- `add_rule`: Add a new permission rule
- `remove_rule`: Remove a permission rule
- `add_route`: Add a new route connection
- `remove_route`: Remove a route connection
- `add_model`: Add a new model structure
- `remove_model`: Remove a model structure
- `add_action`: Add a new action event/function
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
