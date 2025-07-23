# Secret Management Guide

## Overview

This document outlines best practices for managing secrets and sensitive information in the Coreflux MCP Server.

## Types of Secrets

The following information is considered sensitive and must be protected:

### Critical Secrets
- **MQTT_PASSWORD** - MQTT broker authentication password
- **DO_AGENT_API_KEY** - Coreflux Copilot API key
- **Certificate private keys** - TLS private key files

### Sensitive Information
- **MQTT_USER** - MQTT username (less critical but should be protected)
- **Certificate files** - TLS certificate and CA files
- **Connection strings** - Complete connection URLs with embedded credentials

## Storage Methods

### 1. Environment Variables (Development)

```bash
# .env file (never commit to git)
MQTT_PASSWORD=your_secure_password
DO_AGENT_API_KEY=your_api_key_here
```

### 2. Docker Secrets (Production)

```yaml
# docker-compose.yml
version: '3.8'
services:
  coreflux-mcp-server:
    secrets:
      - mqtt_password
      - api_key
    environment:
      - MQTT_PASSWORD_FILE=/run/secrets/mqtt_password
      - DO_AGENT_API_KEY_FILE=/run/secrets/api_key

secrets:
  mqtt_password:
    external: true
  api_key:
    external: true
```

Create secrets:
```bash
echo "your_password" | docker secret create mqtt_password -
echo "your_api_key" | docker secret create api_key -
```

### 3. Kubernetes Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: coreflux-mcp-secrets
type: Opaque
stringData:
  mqtt-password: "your_secure_password"
  api-key: "your_api_key"
```

Create from command line:
```bash
kubectl create secret generic coreflux-mcp-secrets \
  --from-literal=mqtt-password='your_password' \
  --from-literal=api-key='your_api_key'
```

### 4. HashiCorp Vault Integration

For enterprise deployments, integrate with HashiCorp Vault:

```python
# Example vault integration (not implemented)
import hvac

def get_secret_from_vault(path: str, key: str) -> str:
    client = hvac.Client(url='https://vault.example.com')
    client.token = os.environ['VAULT_TOKEN']
    
    secret = client.secrets.kv.v2.read_secret_version(path=path)
    return secret['data']['data'][key]
```

## File-based Secrets

### Certificate Files

Store certificate files with restricted permissions:

```bash
# Set secure permissions
chmod 600 /path/to/private.key
chmod 644 /path/to/certificate.crt
chmod 644 /path/to/ca.crt

# Verify ownership
chown app:app /path/to/certificates/*
```

### Directory Structure

```
/etc/coreflux-mcp/
├── certs/
│   ├── ca.crt          (644)
│   ├── client.crt      (644)
│   └── client.key      (600)
└── config/
    └── .env            (600)
```

## Security Best Practices

### 1. Rotation

- **MQTT passwords**: Rotate every 90 days
- **API keys**: Rotate every 6 months
- **Certificates**: Monitor expiration, auto-renew where possible

### 2. Access Control

- Use least-privilege principle
- Separate secrets by environment (dev/staging/prod)
- Audit secret access regularly

### 3. Transmission

- Always use TLS for secret transmission
- Never log secrets (use log sanitization)
- Use secure channels for secret distribution

### 4. Storage

- Encrypt secrets at rest
- Use dedicated secret management systems
- Never commit secrets to version control

## Environment-Specific Configuration

### Development

```bash
# .env file
MQTT_BROKER=localhost
MQTT_PORT=1883
MQTT_USER=dev_user
MQTT_PASSWORD=dev_password
MQTT_USE_TLS=false
DO_AGENT_API_KEY=dev_api_key
LOG_LEVEL=DEBUG
```

### Staging

```bash
# .env file
MQTT_BROKER=staging-mqtt.example.com
MQTT_PORT=8883
MQTT_USER=staging_user
MQTT_PASSWORD=${STAGING_MQTT_PASSWORD}  # From external source
MQTT_USE_TLS=true
MQTT_CA_CERT=/etc/ssl/certs/staging-ca.crt
DO_AGENT_API_KEY=${STAGING_API_KEY}
LOG_LEVEL=INFO
```

### Production

```bash
# .env file (minimal, secrets from external sources)
MQTT_BROKER=prod-mqtt.example.com
MQTT_PORT=8883
MQTT_USER=prod_user
MQTT_PASSWORD_FILE=/run/secrets/mqtt_password
MQTT_USE_TLS=true
MQTT_CA_CERT=/etc/ssl/certs/prod-ca.crt
DO_AGENT_API_KEY_FILE=/run/secrets/api_key
LOG_LEVEL=WARNING
```

## Secret Detection and Prevention

### 1. Pre-commit Hooks

The project includes `detect-secrets` pre-commit hook:

```bash
# Initialize secrets baseline
detect-secrets scan --baseline .secrets.baseline

# Update baseline when adding legitimate secrets
detect-secrets scan --baseline .secrets.baseline --update

# Audit detected secrets
detect-secrets audit .secrets.baseline
```

### 2. CI/CD Pipeline

The GitHub Actions workflow includes secret scanning:

```yaml
- name: Run secret scan
  run: |
    detect-secrets scan --baseline .secrets.baseline
    detect-secrets audit .secrets.baseline --report
```

### 3. Regular Audits

Perform regular secret audits:

```bash
# Check for hardcoded secrets
bandit -r . -f json | jq '.results[] | select(.test_id == "B106")'

# Check git history for secrets
git log -p | grep -i "password\|api.key\|secret"

# Scan for accidentally committed secrets
truffleHog --regex --entropy=False .
```

## Recovery Procedures

### Compromised Secrets

1. **Immediate Actions**:
   - Revoke the compromised secret
   - Generate new secret
   - Update all systems
   - Monitor for unauthorized access

2. **Investigation**:
   - Check access logs
   - Identify potential impact
   - Document incident

3. **Prevention**:
   - Review how secret was exposed
   - Improve processes
   - Update documentation

### Certificate Expiration

1. **Before Expiration**:
   - Monitor certificate expiry dates
   - Set up automated renewal where possible
   - Plan renewal procedures

2. **During Renewal**:
   - Generate new certificate
   - Test in staging environment
   - Deploy with minimal downtime

## Tools and Resources

### Secret Management Tools

- **HashiCorp Vault** - Enterprise secret management
- **AWS Secrets Manager** - AWS-native secret management
- **Azure Key Vault** - Azure-native secret management
- **Kubernetes Secrets** - Container-native secrets
- **Docker Secrets** - Docker Swarm secret management

### Security Scanning Tools

- **detect-secrets** - Pre-commit secret detection
- **bandit** - Python security linting
- **truffleHog** - Git repository secret scanning
- **git-secrets** - AWS git hooks for secret prevention

### Monitoring Tools

- **Vault Audit Logs** - Secret access monitoring
- **CloudTrail** - AWS secret access monitoring
- **Azure Monitor** - Azure secret access monitoring

## Compliance Considerations

### Standards

- **SOC 2** - Security controls for service organizations
- **PCI DSS** - Payment card industry requirements
- **GDPR** - Data protection regulations
- **HIPAA** - Healthcare information protection

### Requirements

- **Encryption at rest** - All secrets must be encrypted when stored
- **Encryption in transit** - All secret transmission must be encrypted
- **Access logging** - All secret access must be logged
- **Regular rotation** - Secrets must be rotated according to policy

## Implementation Checklist

- [ ] Configure environment-specific secret storage
- [ ] Set up certificate management procedures
- [ ] Implement secret rotation schedules
- [ ] Configure access logging and monitoring
- [ ] Set up automated secret scanning
- [ ] Train team on secret management procedures
- [ ] Document incident response procedures
- [ ] Regular security audits and reviews
