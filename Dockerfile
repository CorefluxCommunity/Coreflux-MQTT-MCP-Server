# Use Python 3.11 slim image for smaller size
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create non-root user for security
RUN groupadd -r mcpserver && useradd -r -g mcpserver mcpserver

# Set working directory
WORKDIR /app

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY server.py parser.py setup_assistant.py healthcheck.py ./
COPY .env.example ./

# Make healthcheck executable
RUN chmod +x healthcheck.py

# Create directories for certificates and logs
RUN mkdir -p /app/certs /app/logs && \
    chown -R mcpserver:mcpserver /app

# Switch to non-root user
USER mcpserver

# Expose port (if needed for health checks)
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python healthcheck.py || exit 1

# Default command
CMD ["python", "server.py"]
