# Coreflux MCP Server API Documentation

## Overview

The Coreflux MCP Server implements the Model Context Protocol (MCP) to provide AI models with tools for interacting with Coreflux MQTT brokers. This document describes the available tools and their usage.

## API Version

- **MCP Version**: 1.0
- **Server Version**: 1.0.0
- **Python Requirements**: 3.11+

## Base Configuration

### Connection Settings

```json
{
  "mcpServers": {
    "coreflux": {
      "command": "python",
      "args": ["path/to/server.py"],
      "env": {
        "MQTT_BROKER": "your-broker-host",
        "MQTT_PORT": "8883",
        "MQTT_USER": "your-username",
        "MQTT_PASSWORD": "your-password",
        "MQTT_USE_TLS": "true",
        "DO_AGENT_API_KEY": "your-api-key"
      }
    }
  }
}
```

## Available Tools

### 1. publish_to_coreflux

Publishes messages to Coreflux MQTT topics.

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `topic` | string | Yes | MQTT topic to publish to |
| `message` | string | Yes | Message content to publish |
| `qos` | integer | No | Quality of Service level (0, 1, or 2). Default: 0 |
| `retain` | boolean | No | Whether to retain the message. Default: false |

#### Example Usage

```json
{
  "method": "tools/call",
  "params": {
    "name": "publish_to_coreflux",
    "arguments": {
      "topic": "sensors/temperature",
      "message": "25.6",
      "qos": 1,
      "retain": true
    }
  }
}
```

#### Response

```json
{
  "content": [
    {
      "type": "text",
      "text": "Successfully published message to topic 'sensors/temperature' with QoS 1"
    }
  ]
}
```

#### Error Responses

```json
{
  "error": {
    "code": -32000,
    "message": "Failed to publish: Connection timeout"
  }
}
```

### 2. copilot_assist

Sends requests to Coreflux Copilot AI service for assistance.

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | Yes | Question or request for the AI assistant |
| `context` | string | No | Additional context for the query |

#### Example Usage

```json
{
  "method": "tools/call",
  "params": {
    "name": "copilot_assist",
    "arguments": {
      "query": "What is the optimal temperature range for this sensor?",
      "context": "Sensor location: warehouse, Type: DHT22"
    }
  }
}
```

#### Response

```json
{
  "content": [
    {
      "type": "text",
      "text": "Based on the DHT22 sensor specifications and warehouse environment, the optimal temperature range is typically 15-25°C (59-77°F) for accurate readings and equipment longevity."
    }
  ]
}
```

### 3. get_broker_info

Retrieves information about the connected MQTT broker.

#### Parameters

None required.

#### Example Usage

```json
{
  "method": "tools/call",
  "params": {
    "name": "get_broker_info",
    "arguments": {}
  }
}
```

#### Response

```json
{
  "content": [
    {
      "type": "text",
      "text": "Broker: mqtt.coreflux.org:8883\nConnected: Yes\nTLS: Enabled\nClient ID: mcp_client_abc123\nUptime: 2 hours 15 minutes\nLast Activity: 2024-01-15 10:30:25"
    }
  ]
}
```

### 4. comprehensive_health_check

Performs a comprehensive health check of all server components.

#### Parameters

None required.

#### Example Usage

```json
{
  "method": "tools/call",
  "params": {
    "name": "comprehensive_health_check",
    "arguments": {}
  }
}
```

#### Response

```json
{
  "content": [
    {
      "type": "text",
      "text": "=== Comprehensive Health Check ===\n\n✅ Configuration Status: VALID\n✅ MQTT Connection: CONNECTED (mqtt.coreflux.org:8883)\n✅ TLS Security: ENABLED\n✅ Copilot API: ACCESSIBLE\n✅ Message Processor: RUNNING (Queue: 0 messages)\n✅ Logging System: ACTIVE\n\n🔍 System Details:\n- Client ID: mcp_client_abc123\n- Uptime: 2h 15m\n- Messages Processed: 1,247\n- Memory Usage: 45.2 MB\n- CPU Usage: 2.1%\n\n✅ Overall Status: HEALTHY"
    }
  ]
}
```

## Error Handling

### Common Error Codes

| Code | Description | Common Causes |
|------|-------------|---------------|
| -32000 | Server Error | Connection issues, authentication failures |
| -32001 | Invalid Topic | Malformed topic name |
| -32002 | Publish Failed | Network issues, broker unavailable |
| -32003 | API Error | Copilot API issues, invalid API key |
| -32004 | Configuration Error | Missing or invalid configuration |

### Error Response Format

```json
{
  "error": {
    "code": -32000,
    "message": "Human-readable error description",
    "data": {
      "details": "Additional error context",
      "timestamp": "2024-01-15T10:30:25Z"
    }
  }
}
```

## Topic Naming Conventions

### Standard Patterns

- **Sensors**: `sensors/{location}/{type}/{id}`
- **Devices**: `devices/{location}/{type}/{id}`
- **Events**: `events/{category}/{subcategory}`
- **Commands**: `commands/{target}/{action}`

### Examples

```
sensors/warehouse/temperature/DHT22_001
devices/factory/motor/M001/status
events/system/startup
commands/lighting/zone1/on
```

## Quality of Service (QoS) Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| 0 | At most once | Non-critical data, high frequency |
| 1 | At least once | Important data, can handle duplicates |
| 2 | Exactly once | Critical data, no duplicates allowed |

## Security Considerations

### TLS Configuration

- **Required**: TLS 1.2 or higher
- **Certificates**: Proper CA validation
- **Cipher Suites**: Modern, secure algorithms only

### Authentication

- **MQTT**: Username/password authentication
- **API**: Bearer token authentication for Copilot

### Topic Permissions

- **Read**: Subscribe permissions per topic pattern
- **Write**: Publish permissions per topic pattern
- **Admin**: Full access to all topics

## Rate Limiting

### Default Limits

- **Publish Rate**: 100 messages/minute
- **API Requests**: 60 requests/minute
- **Connection Rate**: 10 connections/minute

### Configuration

```python
# In message_processor.py
RATE_LIMIT_MESSAGES = 100  # Messages per minute
RATE_LIMIT_WINDOW = 60     # Time window in seconds
```

## Monitoring and Metrics

### Available Metrics

- **Connection Status**: MQTT broker connectivity
- **Message Count**: Published messages counter
- **Error Rate**: Failed operations percentage
- **Response Time**: API call latencies
- **Queue Size**: Pending message count

### Health Check Endpoints

The comprehensive health check provides:

- Configuration validation status
- MQTT connection health
- TLS security status
- API accessibility
- Message processor status
- System resource usage

## Client Integration Examples

### Python Client

```python
import json
import asyncio
from mcp_client import MCPClient

async def main():
    client = MCPClient()
    await client.connect("path/to/server.py")
    
    # Publish a message
    result = await client.call_tool("publish_to_coreflux", {
        "topic": "sensors/temp/001",
        "message": "23.5",
        "qos": 1
    })
    
    print(result)

asyncio.run(main())
```

### Node.js Client

```javascript
const { MCPClient } = require('@modelcontextprotocol/client');

async function main() {
    const client = new MCPClient();
    await client.connect('python', ['path/to/server.py']);
    
    // Get broker information
    const result = await client.callTool('get_broker_info', {});
    console.log(result);
}

main().catch(console.error);
```

## Development and Testing

### Local Testing

```bash
# Start the server
python server.py

# Test with MCP client
mcp-client test --server "python server.py"
```

### Mock Mode

Set `MOCK_MODE=true` for testing without real MQTT broker:

```bash
export MOCK_MODE=true
python server.py
```

## Changelog

### Version 1.0.0 (2024-01-15)

- Initial release with core functionality
- MQTT publish tool
- Copilot integration
- Health check system
- Configuration validation
- Async message processing
- Enhanced logging

## Support and Troubleshooting

### Common Issues

1. **Connection Refused**
   - Check broker hostname and port
   - Verify network connectivity
   - Confirm TLS configuration

2. **Authentication Failed**
   - Verify username/password
   - Check API key validity
   - Confirm permissions

3. **Publish Timeout**
   - Check QoS settings
   - Verify topic permissions
   - Monitor broker load

### Debug Mode

Enable debug logging:

```bash
export LOG_LEVEL=DEBUG
python server.py
```

### Getting Help

- **GitHub Issues**: [Repository Issues](https://github.com/your-org/coreflux-mcp-server/issues)
- **Documentation**: [Full Documentation](./README.md)
- **Security Issues**: security@your-org.com
