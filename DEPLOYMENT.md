# Deployment Guide

## Overview

This guide covers different deployment options for the Coreflux MCP Server in production environments.

## Prerequisites

- Docker and Docker Compose (for containerized deployment)
- Python 3.11+ (for direct deployment)
- Access to a Coreflux MQTT broker
- Coreflux Copilot API key (optional, for LOT code generation)

## Deployment Options

### 1. Docker Deployment (Recommended)

#### Quick Start

1. **Clone the repository**:
   ```bash
   git clone https://github.com/CorefluxCommunity/Coreflux-MQTT-MCP-Server.git
   cd Coreflux-MQTT-MCP-Server
   ```

2. **Create environment configuration**:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Run with Docker Compose**:
   ```bash
   docker-compose up -d
   ```

#### Custom Configuration

1. **Create override file**:
   ```bash
   cp docker-compose.override.yml.example docker-compose.override.yml
   # Edit docker-compose.override.yml for your environment
   ```

2. **Configure environment variables** in `.env`:
   ```bash
   MQTT_BROKER=your-mqtt-broker.com
   MQTT_PORT=8883
   MQTT_USER=your_username
   MQTT_PASSWORD=your_password
   MQTT_USE_TLS=true
   DO_AGENT_API_KEY=your_api_key
   LOG_LEVEL=INFO
   ```

3. **TLS Configuration** (if using TLS):
   ```bash
   # Create certificates directory
   mkdir -p certs
   
   # Copy your certificates
   cp your-ca.crt certs/
   cp your-client.crt certs/
   cp your-client.key certs/
   
   # Set secure permissions
   chmod 600 certs/*
   ```

4. **Deploy**:
   ```bash
   docker-compose up -d
   ```

#### With MQTT Broker

To include a test MQTT broker:

```bash
docker-compose --profile with-broker up -d
```

### 2. Direct Python Deployment

#### Installation

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

#### Production Service (Linux)

Create a systemd service file `/etc/systemd/system/coreflux-mcp.service`:

```ini
[Unit]
Description=Coreflux MCP Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=coreflux
Group=coreflux
WorkingDirectory=/opt/coreflux-mcp-server
Environment=PATH=/opt/coreflux-mcp-server/venv/bin
ExecStart=/opt/coreflux-mcp-server/venv/bin/python server.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=coreflux-mcp

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable coreflux-mcp
sudo systemctl start coreflux-mcp
```

### 3. Kubernetes Deployment

#### Prerequisites

- Kubernetes cluster
- kubectl configured
- Secrets management solution

#### Deployment Files

Create `k8s/namespace.yaml`:
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: coreflux-mcp
```

Create `k8s/secret.yaml`:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: coreflux-mcp-config
  namespace: coreflux-mcp
type: Opaque
stringData:
  MQTT_BROKER: "your-mqtt-broker.com"
  MQTT_USER: "your_username"
  MQTT_PASSWORD: "your_password"
  DO_AGENT_API_KEY: "your_api_key"
```

Create `k8s/deployment.yaml`:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: coreflux-mcp-server
  namespace: coreflux-mcp
spec:
  replicas: 2
  selector:
    matchLabels:
      app: coreflux-mcp-server
  template:
    metadata:
      labels:
        app: coreflux-mcp-server
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: coreflux-mcp-server
        image: coreflux-mcp-server:latest
        imagePullPolicy: Always
        envFrom:
        - secretRef:
            name: coreflux-mcp-config
        env:
        - name: MQTT_PORT
          value: "8883"
        - name: MQTT_USE_TLS
          value: "true"
        - name: LOG_LEVEL
          value: "INFO"
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
              - ALL
```

Deploy:
```bash
kubectl apply -f k8s/
```

## Configuration Management

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `MQTT_BROKER` | MQTT broker hostname | Yes | localhost |
| `MQTT_PORT` | MQTT broker port | No | 1883 |
| `MQTT_USER` | MQTT username | Yes | - |
| `MQTT_PASSWORD` | MQTT password | Yes | - |
| `MQTT_CLIENT_ID` | MQTT client ID | No | Auto-generated |
| `MQTT_USE_TLS` | Enable TLS | No | false |
| `MQTT_CA_CERT` | CA certificate path | No | - |
| `MQTT_CLIENT_CERT` | Client certificate path | No | - |
| `MQTT_CLIENT_KEY` | Client key path | No | - |
| `DO_AGENT_API_KEY` | Coreflux Copilot API key | No | - |
| `LOG_LEVEL` | Logging level | No | INFO |

### Secrets Management

#### Docker Secrets

```yaml
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

#### Kubernetes Secrets

```bash
kubectl create secret generic coreflux-mcp-secrets \
  --from-literal=mqtt-password='your_password' \
  --from-literal=api-key='your_api_key'
```

## Health Monitoring

### Health Checks

The container includes built-in health checks:
- HTTP endpoint: Not available (MCP protocol)
- Process check: Python process validation
- Connection validation: MQTT connectivity

### Monitoring

#### Docker

```bash
# Check container health
docker-compose ps

# View logs
docker-compose logs -f coreflux-mcp-server

# Monitor resources
docker stats coreflux-mcp-server
```

#### Kubernetes

```bash
# Check pod status
kubectl get pods -n coreflux-mcp

# View logs
kubectl logs -f deployment/coreflux-mcp-server -n coreflux-mcp

# Describe pod for details
kubectl describe pod <pod-name> -n coreflux-mcp
```

### Log Management

#### Log Rotation (Docker)

Configure log rotation in `/etc/docker/daemon.json`:

```json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
```

#### Centralized Logging

For production, consider:
- ELK Stack (Elasticsearch, Logstash, Kibana)
- Fluentd
- Prometheus + Grafana
- Cloud logging solutions

## Security Considerations

### Network Security

1. **Use TLS**: Always enable TLS in production
2. **Firewall rules**: Restrict access to necessary ports
3. **Network segmentation**: Isolate MQTT traffic
4. **VPN access**: Use VPN for administrative access

### Container Security

1. **Image scanning**: Regularly scan container images
2. **Non-root user**: Container runs as non-root
3. **Read-only filesystem**: Implement where possible
4. **Resource limits**: Set appropriate CPU/memory limits

### Secrets Security

1. **Environment isolation**: Use separate configs per environment
2. **Secret rotation**: Implement regular secret rotation
3. **Access control**: Limit secret access to necessary services
4. **Audit logging**: Monitor secret access

## Backup and Recovery

### Configuration Backup

```bash
# Backup configuration
tar -czf coreflux-mcp-backup-$(date +%Y%m%d).tar.gz \
  .env docker-compose.yml docker-compose.override.yml certs/

# Restore configuration
tar -xzf coreflux-mcp-backup-YYYYMMDD.tar.gz
```

### Container Image Backup

```bash
# Save container image
docker save coreflux-mcp-server:latest | gzip > coreflux-mcp-image.tar.gz

# Load container image
docker load < coreflux-mcp-image.tar.gz
```

## Troubleshooting

### Common Issues

1. **MQTT Connection Failed**:
   - Check broker connectivity
   - Verify credentials
   - Check TLS configuration
   - Review firewall rules

2. **Permission Denied**:
   - Check file permissions on certificates
   - Verify container user permissions
   - Check SELinux/AppArmor policies

3. **Resource Issues**:
   - Monitor CPU/memory usage
   - Adjust resource limits
   - Check disk space

### Debug Mode

Enable debug logging:

```bash
# Environment variable
LOG_LEVEL=DEBUG

# Command line
python server.py --log-level DEBUG
```

### Support

- Check the [SECURITY.md](SECURITY.md) for security-related issues
- Review logs for detailed error messages
- Consult the main [README.md](README.md) for configuration help
