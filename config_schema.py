"""
Configuration schema and validation for Coreflux MCP Server

This module defines the configuration schema using Pydantic models
for type safety and validation.
"""

from pydantic import BaseModel, Field, validator, root_validator
from typing import Optional, Dict, Any, List
from enum import Enum
from pathlib import Path
import os

class LogLevel(str, Enum):
    """Allowed log levels"""
    NONE = "NONE"
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class MQTTConfig(BaseModel):
    """MQTT connection configuration"""
    broker: str = Field(..., description="MQTT broker hostname or IP address")
    port: int = Field(1883, ge=1, le=65535, description="MQTT broker port")
    user: Optional[str] = Field(None, description="MQTT username")
    password: Optional[str] = Field(None, description="MQTT password")
    client_id: Optional[str] = Field(None, description="MQTT client ID")
    use_tls: bool = Field(False, description="Enable TLS encryption")
    
    @validator('broker')
    def validate_broker(cls, v):
        if not v or not v.strip():
            raise ValueError("MQTT broker cannot be empty")
        return v.strip()
    
    @validator('client_id')
    def validate_client_id(cls, v):
        if v and len(v) > 65535:
            raise ValueError("MQTT client ID too long (max 65535 characters)")
        return v

class TLSConfig(BaseModel):
    """TLS configuration for MQTT"""
    ca_cert: Optional[str] = Field(None, description="Path to CA certificate file")
    client_cert: Optional[str] = Field(None, description="Path to client certificate file")
    client_key: Optional[str] = Field(None, description="Path to client private key file")
    
    @validator('ca_cert', 'client_cert', 'client_key')
    def validate_cert_paths(cls, v):
        if v and not Path(v).exists():
            raise ValueError(f"Certificate file not found: {v}")
        return v
    
    @root_validator
    def validate_client_cert_pair(cls, values):
        client_cert = values.get('client_cert')
        client_key = values.get('client_key')
        
        if bool(client_cert) != bool(client_key):
            raise ValueError("Client certificate and key must be provided together")
        
        return values

class APIConfig(BaseModel):
    """API configuration"""
    do_agent_api_key: Optional[str] = Field(None, description="Coreflux Copilot API key")
    
    @validator('do_agent_api_key')
    def validate_api_key(cls, v):
        if v:
            if len(v) < 10:
                raise ValueError("API key appears to be too short")
            if v.startswith('your_') or v.endswith('_here'):
                raise ValueError("API key appears to be a placeholder value")
        return v

class LoggingConfig(BaseModel):
    """Logging configuration"""
    level: LogLevel = Field(LogLevel.INFO, description="Logging level")
    enable_rotation: bool = Field(True, description="Enable log file rotation")
    max_file_size: int = Field(10 * 1024 * 1024, description="Maximum log file size in bytes")
    backup_count: int = Field(5, ge=0, description="Number of backup log files to keep")
    log_format: str = Field("text", description="Log format (text or json)")
    
    @validator('log_format')
    def validate_log_format(cls, v):
        if v not in ['text', 'json']:
            raise ValueError("Log format must be 'text' or 'json'")
        return v

class ServerConfig(BaseModel):
    """Complete server configuration"""
    mqtt: MQTTConfig
    tls: TLSConfig = TLSConfig()
    api: APIConfig = APIConfig()
    logging: LoggingConfig = LoggingConfig()
    
    # Message processing configuration
    message_buffer_size: int = Field(10000, ge=100, description="Maximum message buffer size")
    rate_limit_threshold: int = Field(50, ge=1, description="Messages per minute per topic limit")
    
    @root_validator
    def validate_tls_requirements(cls, values):
        mqtt = values.get('mqtt')
        tls = values.get('tls')
        
        if mqtt and mqtt.use_tls:
            if not tls or not tls.ca_cert:
                raise ValueError("TLS is enabled but CA certificate is not provided")
        
        return values
    
    @classmethod
    def from_environment(cls) -> 'ServerConfig':
        """Create configuration from environment variables"""
        
        # MQTT configuration
        mqtt_config = {
            'broker': os.environ.get('MQTT_BROKER', 'localhost'),
            'port': int(os.environ.get('MQTT_PORT', '1883')),
            'user': os.environ.get('MQTT_USER'),
            'password': os.environ.get('MQTT_PASSWORD'),
            'client_id': os.environ.get('MQTT_CLIENT_ID'),
            'use_tls': os.environ.get('MQTT_USE_TLS', 'false').lower() == 'true'
        }
        
        # TLS configuration
        tls_config = {
            'ca_cert': os.environ.get('MQTT_CA_CERT'),
            'client_cert': os.environ.get('MQTT_CLIENT_CERT'),
            'client_key': os.environ.get('MQTT_CLIENT_KEY')
        }
        
        # API configuration
        api_config = {
            'do_agent_api_key': os.environ.get('DO_AGENT_API_KEY')
        }
        
        # Logging configuration
        logging_config = {
            'level': os.environ.get('LOG_LEVEL', 'INFO'),
            'log_format': os.environ.get('LOG_FORMAT', 'text').lower()
        }
        
        # Message processing configuration
        message_config = {
            'message_buffer_size': int(os.environ.get('MESSAGE_BUFFER_SIZE', '10000')),
            'rate_limit_threshold': int(os.environ.get('RATE_LIMIT_THRESHOLD', '50'))
        }
        
        return cls(
            mqtt=MQTTConfig(**mqtt_config),
            tls=TLSConfig(**tls_config),
            api=APIConfig(**api_config),
            logging=LoggingConfig(**logging_config),
            **message_config
        )
    
    def to_dict(self, exclude_sensitive: bool = True) -> Dict[str, Any]:
        """Convert to dictionary with optional sensitive data exclusion"""
        config_dict = self.dict()
        
        if exclude_sensitive:
            # Redact sensitive information
            if config_dict.get('mqtt', {}).get('password'):
                config_dict['mqtt']['password'] = '[REDACTED]'
            if config_dict.get('api', {}).get('do_agent_api_key'):
                config_dict['api']['do_agent_api_key'] = '[REDACTED]'
        
        return config_dict
    
    def validate_files(self) -> List[str]:
        """Validate that all referenced files exist"""
        errors = []
        
        if self.tls.ca_cert and not Path(self.tls.ca_cert).exists():
            errors.append(f"CA certificate file not found: {self.tls.ca_cert}")
        
        if self.tls.client_cert and not Path(self.tls.client_cert).exists():
            errors.append(f"Client certificate file not found: {self.tls.client_cert}")
        
        if self.tls.client_key and not Path(self.tls.client_key).exists():
            errors.append(f"Client key file not found: {self.tls.client_key}")
        
        return errors

class ConfigurationManager:
    """Manages server configuration loading and validation"""
    
    def __init__(self):
        self._config: Optional[ServerConfig] = None
        self._validation_errors: List[str] = []
    
    def load_config(self) -> ServerConfig:
        """Load and validate configuration from environment"""
        try:
            self._config = ServerConfig.from_environment()
            
            # Additional file validation
            file_errors = self._config.validate_files()
            if file_errors:
                self._validation_errors.extend(file_errors)
            
            return self._config
            
        except Exception as e:
            self._validation_errors.append(f"Configuration validation failed: {str(e)}")
            raise
    
    def get_config(self) -> Optional[ServerConfig]:
        """Get the current configuration"""
        return self._config
    
    def get_validation_errors(self) -> List[str]:
        """Get validation errors"""
        return self._validation_errors.copy()
    
    def is_valid(self) -> bool:
        """Check if configuration is valid"""
        return self._config is not None and len(self._validation_errors) == 0
    
    def get_config_summary(self) -> Dict[str, Any]:
        """Get a safe configuration summary"""
        if not self._config:
            return {"error": "Configuration not loaded"}
        
        return self._config.to_dict(exclude_sensitive=True)

# Global configuration manager instance
_config_manager: Optional[ConfigurationManager] = None

def get_config_manager() -> ConfigurationManager:
    """Get or create the global configuration manager"""
    global _config_manager
    
    if _config_manager is None:
        _config_manager = ConfigurationManager()
    
    return _config_manager

def load_server_config() -> ServerConfig:
    """Load server configuration (convenience function)"""
    manager = get_config_manager()
    return manager.load_config()
