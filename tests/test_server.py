"""
Unit tests for the Coreflux MCP Server

This module contains comprehensive unit tests for all major components
of the Coreflux MCP Server, including configuration validation,
log sanitization, MQTT handling, and API integration.
"""

import unittest
import os
import logging
import tempfile
import json
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Import the modules to test
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config_validator import ConfigurationValidator, ConfigurationError
import server
import parser
import setup_assistant

class TestConfigurationValidator(unittest.TestCase):
    """Test configuration validation functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.logger = logging.getLogger("test")
        self.validator = ConfigurationValidator(self.logger)
        
        # Store original environment
        self.original_env = os.environ.copy()
        
        # Clear relevant environment variables for clean tests
        env_vars_to_clear = [
            'MQTT_BROKER', 'MQTT_PORT', 'MQTT_USER', 'MQTT_PASSWORD',
            'MQTT_CLIENT_ID', 'MQTT_USE_TLS', 'MQTT_CA_CERT',
            'MQTT_CLIENT_CERT', 'MQTT_CLIENT_KEY', 'DO_AGENT_API_KEY',
            'LOG_LEVEL'
        ]
        for var in env_vars_to_clear:
            if var in os.environ:
                del os.environ[var]
    
    def tearDown(self):
        """Restore original environment"""
        os.environ.clear()
        os.environ.update(self.original_env)
    
    def test_missing_required_mqtt_broker(self):
        """Test validation fails when MQTT_BROKER is missing"""
        is_valid, errors, warnings = self.validator.validate_environment()
        
        self.assertFalse(is_valid)
        self.assertIn("Required environment variable MQTT_BROKER is not set", errors)
    
    def test_valid_minimal_config(self):
        """Test validation passes with minimal valid configuration"""
        os.environ['MQTT_BROKER'] = 'localhost'
        
        is_valid, errors, warnings = self.validator.validate_environment()
        
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)
    
    def test_invalid_mqtt_port(self):
        """Test validation fails with invalid MQTT port"""
        os.environ['MQTT_BROKER'] = 'localhost'
        os.environ['MQTT_PORT'] = '99999'  # Invalid port
        
        is_valid, errors, warnings = self.validator.validate_environment()
        
        self.assertFalse(is_valid)
        self.assertTrue(any("MQTT_PORT must be between 1-65535" in error for error in errors))
    
    def test_invalid_mqtt_port_non_numeric(self):
        """Test validation fails with non-numeric MQTT port"""
        os.environ['MQTT_BROKER'] = 'localhost'
        os.environ['MQTT_PORT'] = 'invalid'
        
        is_valid, errors, warnings = self.validator.validate_environment()
        
        self.assertFalse(is_valid)
        self.assertTrue(any("MQTT_PORT must be a valid integer" in error for error in errors))
    
    def test_tls_config_missing_ca_cert(self):
        """Test validation fails when TLS is enabled but CA cert is missing"""
        os.environ['MQTT_BROKER'] = 'localhost'
        os.environ['MQTT_USE_TLS'] = 'true'
        
        is_valid, errors, warnings = self.validator.validate_environment()
        
        self.assertFalse(is_valid)
        self.assertTrue(any("MQTT_USE_TLS=true but MQTT_CA_CERT not specified" in error for error in errors))
    
    def test_tls_config_cert_file_not_found(self):
        """Test validation fails when certificate file doesn't exist"""
        os.environ['MQTT_BROKER'] = 'localhost'
        os.environ['MQTT_USE_TLS'] = 'true'
        os.environ['MQTT_CA_CERT'] = '/nonexistent/ca.crt'
        
        is_valid, errors, warnings = self.validator.validate_environment()
        
        self.assertFalse(is_valid)
        self.assertTrue(any("CA certificate file not found" in error for error in errors))
    
    def test_valid_tls_config(self):
        """Test validation passes with valid TLS configuration"""
        with tempfile.TemporaryDirectory() as temp_dir:
            ca_cert_path = os.path.join(temp_dir, 'ca.crt')
            Path(ca_cert_path).touch()
            
            os.environ['MQTT_BROKER'] = 'localhost'
            os.environ['MQTT_USE_TLS'] = 'true'
            os.environ['MQTT_CA_CERT'] = ca_cert_path
            
            is_valid, errors, warnings = self.validator.validate_environment()
            
            self.assertTrue(is_valid)
            self.assertEqual(len(errors), 0)
    
    def test_invalid_log_level(self):
        """Test validation fails with invalid log level"""
        os.environ['MQTT_BROKER'] = 'localhost'
        os.environ['LOG_LEVEL'] = 'INVALID'
        
        is_valid, errors, warnings = self.validator.validate_environment()
        
        self.assertFalse(is_valid)
        self.assertTrue(any("Invalid LOG_LEVEL" in error for error in errors))
    
    def test_api_key_placeholder_warning(self):
        """Test warning is generated for placeholder API key"""
        os.environ['MQTT_BROKER'] = 'localhost'
        os.environ['DO_AGENT_API_KEY'] = 'your_api_key_here'
        
        is_valid, errors, warnings = self.validator.validate_environment()
        
        self.assertTrue(is_valid)  # Should be valid but with warning
        self.assertTrue(any("appears to be a placeholder value" in warning for warning in warnings))
    
    def test_hostname_validation(self):
        """Test hostname validation"""
        validator = ConfigurationValidator(self.logger)
        
        # Valid hostnames
        self.assertTrue(validator._is_valid_hostname('localhost'))
        self.assertTrue(validator._is_valid_hostname('127.0.0.1'))
        self.assertTrue(validator._is_valid_hostname('example.com'))
        self.assertTrue(validator._is_valid_hostname('mqtt.example.org'))
        
        # Invalid hostnames
        self.assertFalse(validator._is_valid_hostname(''))
        self.assertFalse(validator._is_valid_hostname(' '))
        self.assertFalse(validator._is_valid_hostname('a' * 300))  # Too long


class TestLogSanitization(unittest.TestCase):
    """Test log sanitization functionality"""
    
    def test_password_sanitization(self):
        """Test that passwords are properly sanitized"""
        test_message = "Connecting with password: secret123"
        sanitized = server.sanitize_log_message(test_message)
        
        self.assertNotIn("secret123", sanitized)
        self.assertIn("[REDACTED]", sanitized)
    
    def test_api_key_sanitization(self):
        """Test that API keys are properly sanitized"""
        test_message = "Using API key: abc123def456"
        sanitized = server.sanitize_log_message(test_message)
        
        self.assertNotIn("abc123def456", sanitized)
        self.assertIn("[REDACTED]", sanitized)
    
    def test_certificate_path_sanitization(self):
        """Test that certificate paths are properly sanitized"""
        test_message = "Loading certificate from /path/to/cert.pem"
        sanitized = server.sanitize_log_message(test_message)
        
        self.assertNotIn("/path/to/cert.pem", sanitized)
        self.assertIn("[CERT_PATH]", sanitized)
    
    def test_bearer_token_sanitization(self):
        """Test that Bearer tokens are properly sanitized"""
        test_message = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        sanitized = server.sanitize_log_message(test_message)
        
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", sanitized)
        self.assertIn("Bearer [REDACTED]", sanitized)
    
    def test_normal_text_unchanged(self):
        """Test that normal text remains unchanged"""
        test_message = "Normal log message without sensitive data"
        sanitized = server.sanitize_log_message(test_message)
        
        self.assertEqual(test_message, sanitized)


class TestJSONParser(unittest.TestCase):
    """Test JSON-RPC message parsing functionality"""
    
    def test_valid_json_parsing(self):
        """Test parsing of valid JSON messages"""
        valid_json = '{"method": "test", "params": {}}'
        result = parser.process_json_rpc_message(valid_json)
        
        self.assertEqual(result['method'], 'test')
        self.assertEqual(result['params'], {})
    
    def test_malformed_json_with_extra_characters(self):
        """Test parsing of JSON with extra characters"""
        malformed_json = '{"method": "test"}extra_chars'
        
        try:
            result = parser.process_json_rpc_message(malformed_json)
            self.assertEqual(result['method'], 'test')
        except Exception:
            self.fail("Should handle malformed JSON gracefully")
    
    def test_completely_invalid_json(self):
        """Test handling of completely invalid JSON"""
        invalid_json = 'not json at all'
        
        with self.assertRaises(Exception):
            parser.process_json_rpc_message(invalid_json)
    
    def test_json_with_bom(self):
        """Test parsing of JSON with BOM character"""
        json_with_bom = '\ufeff{"method": "test"}'
        result = parser.process_json_rpc_message(json_with_bom)
        
        self.assertEqual(result['method'], 'test')


class TestMQTTHandling(unittest.TestCase):
    """Test MQTT connection and message handling"""
    
    @patch('paho.mqtt.client.Client')
    def test_mqtt_connection_setup(self, mock_mqtt_client):
        """Test MQTT connection setup"""
        mock_client = Mock()
        mock_mqtt_client.return_value = mock_client
        
        # Mock successful connection
        mock_client.connect.return_value = 0
        
        # Test connection setup
        with patch('server.args') as mock_args:
            mock_args.mqtt_host = 'localhost'
            mock_args.mqtt_port = 1883
            mock_args.mqtt_user = 'testuser'
            mock_args.mqtt_password = 'testpass'
            mock_args.mqtt_use_tls = False
            
            result = server.setup_mqtt(mock_args)
            
            self.assertTrue(result)
            mock_client.connect.assert_called_once()
    
    def test_message_buffer_management(self):
        """Test MQTT message buffering"""
        # This would test the message buffering functionality
        # Implementation depends on the actual message buffer structure
        pass


class TestHealthCheck(unittest.TestCase):
    """Test health check functionality"""
    
    def test_python_process_check(self):
        """Test Python process health check"""
        # Import healthcheck module
        import healthcheck
        
        result = healthcheck.check_python_process()
        self.assertIsInstance(result, bool)
    
    def test_imports_check(self):
        """Test required imports health check"""
        import healthcheck
        
        result = healthcheck.check_imports()
        self.assertTrue(result)  # Should pass in test environment
    
    def test_configuration_check(self):
        """Test configuration health check"""
        import healthcheck
        
        # Set minimal valid configuration
        os.environ['MQTT_BROKER'] = 'localhost'
        os.environ['MQTT_PORT'] = '1883'
        
        result = healthcheck.check_configuration()
        self.assertTrue(result)


class TestSetupAssistant(unittest.TestCase):
    """Test setup assistant functionality"""
    
    @patch('builtins.input')
    def test_setup_assistant_basic_flow(self, mock_input):
        """Test basic setup assistant flow"""
        # Mock user inputs
        mock_input.side_effect = [
            'test-broker.com',  # MQTT broker
            '8883',             # MQTT port
            'testuser',         # MQTT user
            'testpass',         # MQTT password
            '',                 # Client ID (use default)
            'true',             # Use TLS
            '/path/to/ca.crt',  # CA cert
            '',                 # Client cert (optional)
            '',                 # Client key (optional)
            'test-api-key',     # API key
            'INFO'              # Log level
        ]
        
        # This would test the setup assistant
        # Implementation depends on the actual setup assistant structure
        pass


if __name__ == '__main__':
    # Set up logging for tests
    logging.basicConfig(level=logging.DEBUG)
    
    # Run the tests
    unittest.main(verbosity=2)
