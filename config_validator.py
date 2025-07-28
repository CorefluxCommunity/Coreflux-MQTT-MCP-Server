"""
Configuration validation and management for Coreflux MCP Server

This module provides comprehensive configuration validation,
environment variable checking, and secure configuration management.
"""

import os
import logging
import re
from typing import Dict, List, Tuple, Any, Optional
from pathlib import Path
import json

class ConfigurationError(Exception):
    """Raised when configuration validation fails"""
    pass

class ConfigurationValidator:
    """Validates and manages server configuration"""
    
    REQUIRED_MQTT_VARS = ['MQTT_BROKER']
    OPTIONAL_MQTT_VARS = ['MQTT_PORT', 'MQTT_USER', 'MQTT_PASSWORD', 'MQTT_CLIENT_ID']
    TLS_VARS = ['MQTT_CA_CERT', 'MQTT_CLIENT_CERT', 'MQTT_CLIENT_KEY']
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.config = {}
        self.validation_errors = []
        self.validation_warnings = []
    
    def validate_environment(self) -> Tuple[bool, List[str], List[str]]:
        """
        Validate all environment variables and configuration
        Returns: (is_valid, errors, warnings)
        """
        self.validation_errors = []
        self.validation_warnings = []
        
        # Check required variables
        self._check_required_vars()
        
        # Validate MQTT configuration
        self._validate_mqtt_config()
        
        # Validate TLS configuration
        self._validate_tls_config()
        
        # Validate API configuration
        self._validate_api_config()
        
        # Validate logging configuration
        self._validate_logging_config()
        
        # Check file permissions
        self._check_file_permissions()
        
        is_valid = len(self.validation_errors) == 0
        return is_valid, self.validation_errors, self.validation_warnings
    
    def _check_required_vars(self):
        """Check if required environment variables are set"""
        for var in self.REQUIRED_MQTT_VARS:
            value = os.environ.get(var)
            if not value:
                self.validation_errors.append(f"Required environment variable {var} is not set")
            elif var == 'MQTT_BROKER':
                if not self._is_valid_hostname(value):
                    self.validation_errors.append(f"Invalid MQTT_BROKER hostname: {value}")
    
    def _validate_mqtt_config(self):
        """Validate MQTT configuration parameters"""
        # Validate port
        port = os.environ.get('MQTT_PORT', '1883')
        try:
            port_int = int(port)
            if not (1 <= port_int <= 65535):
                self.validation_errors.append(f"MQTT_PORT must be between 1-65535, got: {port}")
        except ValueError:
            self.validation_errors.append(f"MQTT_PORT must be a valid integer, got: {port}")
        
        # Validate client ID
        client_id = os.environ.get('MQTT_CLIENT_ID')
        if client_id:
            if len(client_id) > 65535:  # MQTT spec limit
                self.validation_errors.append(f"MQTT_CLIENT_ID too long (max 65535 chars): {len(client_id)}")
            if not re.match(r'^[a-zA-Z0-9_-]+$', client_id):
                self.validation_warnings.append(f"MQTT_CLIENT_ID contains special characters: {client_id}")
        
        # Check credentials
        mqtt_user = os.environ.get('MQTT_USER')
        mqtt_password = os.environ.get('MQTT_PASSWORD')
        
        if mqtt_user and not mqtt_password:
            self.validation_warnings.append("MQTT_USER set but MQTT_PASSWORD is empty")
        elif mqtt_password and not mqtt_user:
            self.validation_warnings.append("MQTT_PASSWORD set but MQTT_USER is empty")
    
    def _validate_tls_config(self):
        """Validate TLS configuration"""
        use_tls = os.environ.get('MQTT_USE_TLS', 'false').lower() == 'true'
        
        if use_tls:
            ca_cert = os.environ.get('MQTT_CA_CERT')
            client_cert = os.environ.get('MQTT_CLIENT_CERT')
            client_key = os.environ.get('MQTT_CLIENT_KEY')
            
            if not ca_cert:
                self.validation_errors.append("MQTT_USE_TLS=true but MQTT_CA_CERT not specified")
            else:
                if not Path(ca_cert).exists():
                    self.validation_errors.append(f"CA certificate file not found: {ca_cert}")
            
            if client_cert and not Path(client_cert).exists():
                self.validation_errors.append(f"Client certificate file not found: {client_cert}")
            
            if client_key and not Path(client_key).exists():
                self.validation_errors.append(f"Client key file not found: {client_key}")
            
            if client_cert and not client_key:
                self.validation_errors.append("MQTT_CLIENT_CERT specified but MQTT_CLIENT_KEY missing")
            elif client_key and not client_cert:
                self.validation_errors.append("MQTT_CLIENT_KEY specified but MQTT_CLIENT_CERT missing")
    
    def _validate_api_config(self):
        """Validate API configuration"""
        api_key = os.environ.get('DO_AGENT_API_KEY')
        if api_key:
            # Basic API key format validation
            if len(api_key) < 10:
                self.validation_warnings.append("DO_AGENT_API_KEY appears to be too short")
            elif api_key.startswith('your_') or api_key.endswith('_here'):
                self.validation_warnings.append("DO_AGENT_API_KEY appears to be a placeholder value")
    
    def _validate_logging_config(self):
        """Validate logging configuration"""
        log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
        valid_levels = ['NONE', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        
        if log_level not in valid_levels:
            self.validation_errors.append(f"Invalid LOG_LEVEL: {log_level}. Valid options: {valid_levels}")
    
    def _check_file_permissions(self):
        """Check file permissions for certificate files"""
        cert_files = []
        
        for var in self.TLS_VARS:
            cert_path = os.environ.get(var)
            if cert_path and Path(cert_path).exists():
                cert_files.append(cert_path)
        
        for cert_file in cert_files:
            try:
                path = Path(cert_file)
                # Check if file is readable
                if not os.access(cert_file, os.R_OK):
                    self.validation_errors.append(f"Certificate file not readable: {cert_file}")
                
                # Warn about overly permissive permissions (Unix-like systems)
                if hasattr(os, 'stat'):
                    stat_info = path.stat()
                    # Check if file is world-readable (others can read)
                    if stat_info.st_mode & 0o044:
                        self.validation_warnings.append(f"Certificate file has permissive permissions: {cert_file}")
                        
            except Exception as e:
                self.validation_warnings.append(f"Could not check permissions for {cert_file}: {str(e)}")
    
    def _is_valid_hostname(self, hostname: str) -> bool:
        """Validate hostname format"""
        if not hostname or len(hostname) > 253:
            return False
        
        # Allow localhost and IP addresses
        if hostname in ['localhost', '127.0.0.1', '::1']:
            return True
        
        # Basic IP address check
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
            return True
        
        # Basic hostname validation
        if re.match(r'^[a-zA-Z0-9.-]+$', hostname):
            return True
        
        return False
    
    def get_sanitized_config_summary(self) -> Dict[str, Any]:
        """Get a summary of current configuration with sensitive data redacted"""
        summary = {
            'mqtt': {
                'broker': os.environ.get('MQTT_BROKER', 'NOT_SET'),
                'port': os.environ.get('MQTT_PORT', '1883'),
                'user': '[REDACTED]' if os.environ.get('MQTT_USER') else 'NOT_SET',
                'password': '[REDACTED]' if os.environ.get('MQTT_PASSWORD') else 'NOT_SET',
                'client_id': os.environ.get('MQTT_CLIENT_ID', 'AUTO_GENERATED'),
                'use_tls': os.environ.get('MQTT_USE_TLS', 'false'),
            },
            'tls': {
                'ca_cert': '[SET]' if os.environ.get('MQTT_CA_CERT') else 'NOT_SET',
                'client_cert': '[SET]' if os.environ.get('MQTT_CLIENT_CERT') else 'NOT_SET',
                'client_key': '[SET]' if os.environ.get('MQTT_CLIENT_KEY') else 'NOT_SET',
            },
            'api': {
                'do_agent_key': '[SET]' if os.environ.get('DO_AGENT_API_KEY') else 'NOT_SET',
            },
            'logging': {
                'level': os.environ.get('LOG_LEVEL', 'INFO'),
            }
        }
        return summary
    
    def log_configuration_status(self):
        """Log current configuration status"""
        is_valid, errors, warnings = self.validate_environment()
        
        self.logger.info("Configuration validation completed")
        
        if errors:
            self.logger.error(f"Configuration errors found ({len(errors)}):")
            for error in errors:
                self.logger.error(f"  ❌ {error}")
        
        if warnings:
            self.logger.warning(f"Configuration warnings ({len(warnings)}):")
            for warning in warnings:
                self.logger.warning(f"  ⚠️ {warning}")
        
        if is_valid:
            self.logger.info("✅ Configuration validation passed")
        else:
            self.logger.error("❌ Configuration validation failed")
        
        # Log sanitized configuration summary
        config_summary = self.get_sanitized_config_summary()
        self.logger.debug(f"Configuration summary: {json.dumps(config_summary, indent=2)}")
        
        return is_valid
