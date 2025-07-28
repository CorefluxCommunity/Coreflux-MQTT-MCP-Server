# Security Guidelines

## Overview

This document outlines security considerations and best practices for the Coreflux MCP Server.

## Log Sanitization

The server implements comprehensive log sanitization to prevent sensitive information from being exposed in log files:

- **API Keys and Tokens**: All API keys, bearer tokens, and authentication tokens are automatically redacted
- **Passwords**: All password fields are sanitized regardless of format
- **Certificates**: Certificate content and file paths are redacted  
- **File Paths**: Sensitive file paths are obfuscated
- **URLs with Credentials**: URLs containing credentials are sanitized

### Sensitive Patterns

The following patterns are automatically detected and sanitized:
- `Bearer <token>` → `Bearer [REDACTED]`
- `api_key: <value>` → `api_key: [REDACTED]`
- `password: <value>` → `password: [REDACTED]`
- Certificate content → `[CERTIFICATE REDACTED]`
- File paths → `[FILE PATH REDACTED]`

## Configuration Security

### Environment Variables

Always use environment variables or `.env` files for sensitive configuration:

```bash
# Good
MQTT_PASSWORD=secret_password
DO_AGENT_API_KEY=your_api_key

# Bad - don't hardcode in source
mqtt_password = "secret_password"
```

### TLS Configuration

When using TLS for MQTT connections:

1. **Use strong certificates**: Ensure certificates are from trusted CAs
2. **Secure certificate storage**: Store certificates outside the application directory
3. **File permissions**: Restrict certificate file permissions (600 or 400)
4. **Certificate rotation**: Implement regular certificate rotation

### Docker Security

When running in Docker:

1. **Non-root user**: The container runs as a non-root user (`mcpserver`)
2. **Read-only certificates**: Certificate volumes are mounted read-only
3. **Resource limits**: Memory and CPU limits are enforced
4. **Security scanning**: Regularly scan the Docker image for vulnerabilities

## Network Security

### MQTT Security

1. **Use TLS**: Always use TLS in production environments
2. **Authentication**: Use strong MQTT credentials
3. **Client certificates**: Consider client certificate authentication for enhanced security
4. **Network isolation**: Run MQTT broker in isolated network segments

### Firewall Rules

Configure firewall rules to restrict access:
- MQTT port (1883/8883): Only from authorized networks
- MCP Server: Only accessible from Claude Desktop or authorized clients

## API Security

### Coreflux Copilot API

1. **API Key Protection**: Store API keys securely using environment variables
2. **Rate Limiting**: Be aware of API rate limits
3. **Request Validation**: All API requests are validated before sending
4. **Error Handling**: API errors are logged without exposing sensitive details

## Deployment Security

### Production Checklist

- [ ] Use environment variables for all sensitive configuration
- [ ] Enable TLS for MQTT connections
- [ ] Use strong, unique passwords
- [ ] Implement proper certificate management
- [ ] Configure appropriate log levels (INFO or WARNING in production)
- [ ] Set up log rotation and retention policies
- [ ] Enable container security scanning
- [ ] Use secrets management for production deployments
- [ ] Implement network segmentation
- [ ] Regular security updates

### Secrets Management

For production deployments, consider using:
- Docker Secrets
- Kubernetes Secrets
- HashiCorp Vault
- Cloud provider secret managers (AWS Secrets Manager, Azure Key Vault, etc.)

## Monitoring and Auditing

### Security Monitoring

1. **Log Analysis**: Monitor logs for authentication failures and suspicious activity
2. **Connection Monitoring**: Track MQTT connection patterns
3. **API Usage**: Monitor Coreflux Copilot API usage for anomalies
4. **Health Checks**: Implement comprehensive health monitoring

### Incident Response

1. **Log Retention**: Maintain logs for forensic analysis
2. **Alerting**: Set up alerts for security events
3. **Containment**: Have procedures for isolating compromised systems
4. **Recovery**: Implement backup and recovery procedures

## Reporting Security Issues

If you discover a security vulnerability, please:

1. **Do not** open a public issue
2. Contact the maintainers privately
3. Provide detailed information about the vulnerability
4. Allow time for the issue to be addressed before public disclosure

## Security Updates

- Regularly update dependencies using `pip install -r requirements.txt --upgrade`
- Monitor security advisories for used packages
- Update base Docker images regularly
- Subscribe to security notifications for Coreflux and related components
