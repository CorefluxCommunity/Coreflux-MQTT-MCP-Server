# Test configuration
import os
import sys

# Add the parent directory to the path so we can import the modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Test environment variables
TEST_ENV = {
    'MQTT_BROKER': 'test-broker.com',
    'MQTT_PORT': '1883',
    'MQTT_USER': 'test_user',
    'MQTT_PASSWORD': 'test_password',
    'MQTT_CLIENT_ID': 'test_client',
    'MQTT_USE_TLS': 'false',
    'DO_AGENT_API_KEY': 'test_api_key',
    'LOG_LEVEL': 'DEBUG'
}
