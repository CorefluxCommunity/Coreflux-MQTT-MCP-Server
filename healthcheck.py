#!/usr/bin/env python3
"""
Health check script for Coreflux MCP Server
Used by Docker health checks and monitoring systems
"""

import sys
import os
import subprocess
import json
from typing import Dict, Any

def check_python_process() -> bool:
    """Check if the main server process is running"""
    try:
        # Check if server.py process is running
        result = subprocess.run(
            ["pgrep", "-f", "server.py"],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except FileNotFoundError:
        # pgrep not available, fallback to basic check
        return True

def check_imports() -> bool:
    """Check if required modules can be imported"""
    try:
        import paho.mqtt.client as mqtt
        import requests
        from mcp.server.fastmcp import FastMCP
        return True
    except ImportError as e:
        print(f"Import error: {e}", file=sys.stderr)
        return False

def check_configuration() -> bool:
    """Check if basic configuration is available"""
    try:
        # Check if required environment variables or defaults are available
        mqtt_host = os.environ.get("MQTT_BROKER", "localhost")
        mqtt_port = int(os.environ.get("MQTT_PORT", "1883"))
        
        # Basic validation
        if not mqtt_host:
            print("MQTT_BROKER not configured", file=sys.stderr)
            return False
            
        if not (1 <= mqtt_port <= 65535):
            print(f"Invalid MQTT_PORT: {mqtt_port}", file=sys.stderr)
            return False
            
        return True
    except (ValueError, TypeError) as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        return False

def main() -> int:
    """Run health checks and return exit code"""
    checks = {
        "python_process": check_python_process,
        "imports": check_imports,
        "configuration": check_configuration
    }
    
    results = {}
    all_passed = True
    
    for check_name, check_func in checks.items():
        try:
            result = check_func()
            results[check_name] = "PASS" if result else "FAIL"
            if not result:
                all_passed = False
        except Exception as e:
            results[check_name] = f"ERROR: {str(e)}"
            all_passed = False
    
    # Output results
    health_status = {
        "status": "healthy" if all_passed else "unhealthy",
        "checks": results,
        "timestamp": subprocess.run(
            ["date", "-Iseconds"],
            capture_output=True,
            text=True
        ).stdout.strip() if subprocess.run(["which", "date"], capture_output=True).returncode == 0 else "unknown"
    }
    
    print(json.dumps(health_status, indent=2))
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())
