#!/usr/bin/env python3
"""
Coreflux MQTT MCP Server

A Model Context Protocol (MCP) server that provides integration between Claude and Coreflux MQTT broker.
Supports dynamic action discovery, LOT code generation, and comprehensive MQTT operations.

SECURITY NOTE: This server implements comprehensive log sanitization to prevent sensitive information
(passwords, API keys, certificates, file paths) from being exposed in log files. All logging
functions use automatic sanitization via the safe_log() function and SENSITIVE_PATTERNS.

See SECURITY_LOGGING.md for detailed documentation on log sanitization features.
"""

from mcp.server.fastmcp import FastMCP, Context
import os
import paho.mqtt.client as mqtt
import uuid
import argparse
import requests
import json
import logging
import sys
import time
import threading
from datetime import datetime
from dotenv import load_dotenv
from parser import process_json_rpc_message
from typing import Optional
import pydantic
from pydantic import BaseModel, validator
import re

# Define a custom NONE logging level (higher than CRITICAL)
NONE_LEVEL = 100  # Higher than CRITICAL (50)
logging.addLevelName(NONE_LEVEL, "NONE")

# Log sanitization patterns
SENSITIVE_PATTERNS = [
    # API Keys and tokens (more comprehensive)
    (r'Bearer\s+[A-Za-z0-9\-._~+/]+=*', 'Bearer [REDACTED]'),
    (r'api[_-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9\-._~+/]{8,}["\']?', 'api_key: [REDACTED]'),
    (r'token["\']?\s*[:=]\s*["\']?[A-Za-z0-9\-._~+/]{8,}["\']?', 'token: [REDACTED]'),
    (r'secret["\']?\s*[:=]\s*["\']?[A-Za-z0-9\-._~+/]{8,}["\']?', 'secret: [REDACTED]'),
    (r'authorization["\']?\s*[:=]\s*["\']?[A-Za-z0-9\-._~+/]{8,}["\']?', 'authorization: [REDACTED]'),
    
    # Passwords (more patterns)
    (r'password["\']?\s*[:=]\s*["\']?[^"\'\s]{3,}["\']?', 'password: [REDACTED]'),
    (r'passwd["\']?\s*[:=]\s*["\']?[^"\'\s]{3,}["\']?', 'passwd: [REDACTED]'),
    (r'pwd["\']?\s*[:=]\s*["\']?[^"\'\s]{3,}["\']?', 'pwd: [REDACTED]'),
    (r'pass["\']?\s*[:=]\s*["\']?[^"\'\s]{3,}["\']?', 'pass: [REDACTED]'),
    
    # File paths (more comprehensive)
    (r'[C-Z]:\\[^"\'\s]*(?:key|cert|crt|pem|p12|pfx)[^"\'\s]*', '[CERT_PATH_REDACTED]'),
    (r'[C-Z]:\\Users\\[^\\]+\\[^"\'\s]*', '[USER_PATH_REDACTED]'),
    (r'[C-Z]:\\[^"\'\s]+', '[PATH_REDACTED]'),
    (r'/(?:home|root|usr|opt|etc|var)/[^"\'\s]*(?:key|cert|crt|pem|p12|pfx)[^"\'\s]*', '[CERT_PATH_REDACTED]'),
    (r'/(?:home|root)/[^/]+/[^"\'\s]*', '[USER_PATH_REDACTED]'),
    (r'/(?:home|root|usr|opt|etc|var)/[^"\'\s]+', '[PATH_REDACTED]'),
    
    # URLs with credentials
    (r'https?://[^:\s]+:[^@\s]+@[^/\s]+', 'https://[USER]:[PASS]@[HOST]'),
    (r'ftp://[^:\s]+:[^@\s]+@[^/\s]+', 'ftp://[USER]:[PASS]@[HOST]'),
    
    # Connection strings
    (r'mongodb://[^:\s]+:[^@\s]+@[^/\s]+', 'mongodb://[USER]:[PASS]@[HOST]'),
    (r'mysql://[^:\s]+:[^@\s]+@[^/\s]+', 'mysql://[USER]:[PASS]@[HOST]'),
    (r'postgresql://[^:\s]+:[^@\s]+@[^/\s]+', 'postgresql://[USER]:[PASS]@[HOST]'),
    
    # Certificate content
    (r'-----BEGIN[^-]+-----[^-]+-----END[^-]+-----', '[CERTIFICATE_REDACTED]'),
    
    # MQTT message content that might contain sensitive data
    (r'"payload":\s*"[^"]{100,}"', '"payload": "[PAYLOAD_REDACTED]"'),
    
    # Long hex strings (likely keys/hashes)
    (r'\b[A-Fa-f0-9]{32,}\b', '[HEX_REDACTED]'),
    
    # JWT tokens
    (r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*', '[JWT_REDACTED]'),
    
    # Base64 encoded data (likely sensitive if > 32 chars)
    (r'[A-Za-z0-9+/]{32,}={0,2}', '[BASE64_REDACTED]'),
]

def sanitize_log_message(message: str) -> str:
    """
    Sanitize log messages to remove sensitive information.
    
    Args:
        message: The original log message
        
    Returns:
        Sanitized log message with sensitive data redacted
    """
    if not isinstance(message, str):
        message = str(message)
    
    sanitized = message
    for pattern, replacement in SENSITIVE_PATTERNS:
        sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
    
    return sanitized

def safe_log(logger_func, message: str, *args, **kwargs):
    """
    Safely log a message with automatic sanitization.
    
    Args:
        logger_func: The logger function (logger.info, logger.error, etc.)
        message: The message to log
        *args: Additional arguments for the logger
        **kwargs: Additional keyword arguments for the logger
    """
    try:
        sanitized_message = sanitize_log_message(message)
        logger_func(sanitized_message, *args, **kwargs)
    except Exception as e:
        # Fallback to basic logging if sanitization fails
        try:
            logger_func(f"[LOG_SANITIZATION_ERROR] Original message redacted due to sanitization error: {str(e)}")
        except:
            pass  # Give up if even basic logging fails

def sanitize_function_args(**kwargs) -> dict:
    """
    Sanitize function arguments for logging purposes.
    
    Args:
        **kwargs: Function arguments to sanitize
        
    Returns:
        Dictionary with sanitized argument values
    """
    sanitized = {}
    sensitive_keys = ['password', 'api_key', 'token', 'secret', 'key', 'cert', 'authorization']
    
    for key, value in kwargs.items():
        key_lower = key.lower()
        if any(sensitive in key_lower for sensitive in sensitive_keys):
            sanitized[key] = '[REDACTED]' if value else None
        elif isinstance(value, str) and len(value) > 100:
            # Truncate very long strings and sanitize
            sanitized[key] = sanitize_log_message(value[:100] + '...')
        elif isinstance(value, str):
            sanitized[key] = sanitize_log_message(value)
        else:
            sanitized[key] = value
    
    return sanitized

def log_function_call(func_name: str, **kwargs):
    """
    Safely log a function call with sanitized arguments.
    
    Args:
        func_name: Name of the function being called
        **kwargs: Function arguments to log
    """
    sanitized_args = sanitize_function_args(**kwargs)
    safe_log(logger.debug, f"Function {func_name} called with args: {sanitized_args}")

def is_potentially_sensitive(value: str) -> bool:
    """
    Check if a string value might contain sensitive information.
    
    Args:
        value: String to check
        
    Returns:
        True if the value might be sensitive
    """
    if not isinstance(value, str) or len(value) < 8:
        return False
    
    # Check for patterns that might indicate sensitive data
    sensitive_indicators = [
        r'[A-Za-z0-9]{32,}',  # Long alphanumeric strings (likely keys)
        r'Bearer\s+',         # Bearer tokens
        r'-----BEGIN',        # Certificate start
        r'[A-Za-z0-9+/]{20,}={0,2}',  # Base64 data
        r'eyJ[A-Za-z0-9]',    # JWT tokens
    ]
    
    for pattern in sensitive_indicators:
        if re.search(pattern, value):
            return True
    
    return False

# Load environment variables from .env file if it exists
load_dotenv()

# Import configuration validator
from config_validator import ConfigurationValidator, ConfigurationError

# Import enhanced systems
from message_processor import get_message_processor, MessageProcessor
from enhanced_logging import get_log_manager, setup_logging as enhanced_setup_logging

# Configure logging
def setup_logging(level_name):
    # Special handling for NONE level
    if level_name == "NONE":
        # Disable all logging by setting level to NONE_LEVEL
        level = NONE_LEVEL
    else:
        # Use standard logging levels
        level = getattr(logging, level_name, logging.INFO)
    
    # Create a logger with our app name
    logger = logging.getLogger("CorefluxMCP")
    logger.setLevel(level)
    
    # Remove any existing handlers to avoid duplicates
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Use a format that doesn't conflict with MCP's logging
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    # Add handlers with our formatter
    handlers = [
        logging.FileHandler("coreflux_mcp.log"),
        logging.StreamHandler(sys.stderr)
    ]
    
    for handler in handlers:
        handler.setFormatter(formatter)
        handler.setLevel(level)
        logger.addHandler(handler)
    
    # Don't interfere with the root logger, which MCP might use
    logger.propagate = False
        
    return logger

# Parse command-line arguments
def parse_args():
    parser = argparse.ArgumentParser(description="Coreflux MQTT MCP Server")
    parser.add_argument("--mqtt-host", default=os.environ.get("MQTT_BROKER", "localhost"),
                      help="MQTT broker hostname")
    parser.add_argument("--mqtt-port", type=int, default=int(os.environ.get("MQTT_PORT", "1883")),
                      help="MQTT broker port")
    parser.add_argument("--mqtt-user", default=os.environ.get("MQTT_USER"),
                      help="MQTT username")
    parser.add_argument("--mqtt-password", default=os.environ.get("MQTT_PASSWORD"),
                      help="MQTT password")
    parser.add_argument("--mqtt-client-id", default=os.environ.get("MQTT_CLIENT_ID", f"coreflux-mcp-{uuid.uuid4().hex[:8]}"),
                      help="MQTT client ID")
    parser.add_argument("--mqtt-use-tls", action="store_true", default=os.environ.get("MQTT_USE_TLS", "false").lower() == "true",
                      help="Use TLS for MQTT connection")
    parser.add_argument("--mqtt-ca-cert", default=os.environ.get("MQTT_CA_CERT"),
                      help="Path to CA certificate file for TLS")
    parser.add_argument("--mqtt-client-cert", default=os.environ.get("MQTT_CLIENT_CERT"),
                      help="Path to client certificate file for TLS")
    parser.add_argument("--mqtt-client-key", default=os.environ.get("MQTT_CLIENT_KEY"),
                      help="Path to client key file for TLS")
    parser.add_argument("--do-agent-api-key", default=os.environ.get("DO_AGENT_API_KEY"),
                      help="DigitalOcean Agent Platform API key")
    parser.add_argument("--lot-verifier-api-url", default=os.environ.get("LOT_VERIFIER_API_URL", "http://localhost:8000/validate/code"),
                      help="LOT code verification API endpoint URL")
    parser.add_argument("--log-level", default=os.environ.get("LOG_LEVEL", "INFO"),
                      choices=["NONE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                      help="Set logging level (NONE disables all logging)")
    return parser.parse_args()

# Get command line arguments and setup logging
args = parse_args()
logger = setup_logging(args.log_level)

# Validate configuration before proceeding
config_validator = ConfigurationValidator(logger)
try:
    logger.info("Validating server configuration...")
    is_valid = config_validator.log_configuration_status()
    
    if not is_valid:
        logger.error("Configuration validation failed. Please check your environment variables.")
        logger.info("Run 'python setup_assistant.py' to configure the server.")
        # Don't exit here - allow server to start for configuration tools to work
        logger.warning("Starting server anyway to allow configuration via MCP tools.")
    else:
        logger.info("Configuration validation passed successfully.")
        
except Exception as e:
    logger.error(f"Error during configuration validation: {str(e)}")
    logger.warning("Continuing with startup despite validation error.")

# Configure FastMCP server
mcp = FastMCP(
    "Coreflux Broker",
    description="Connect to a Coreflux MQTT broker and control Coreflux actions, models, and rules",
    dependencies=["paho-mqtt"]
)

# Initialize enhanced message processor
message_processor = get_message_processor(logger)
logger.info("Enhanced message processor initialized")

# Global MQTT client and enhanced message processing
mqtt_client = None
discovered_actions = {}
registered_dynamic_tools = set()  # Keep track of dynamically registered tools
connection_status = {
    "connected": False,
    "last_connection_attempt": None,
    "reconnect_count": 0,
    "last_error": None
}
server_start_time = datetime.now()
mqtt_subscriptions = {}  # Track active subscriptions
mqtt_message_buffer = {}  # Legacy buffer for backward compatibility

# Enhanced message processing
message_processor = None  # Will be initialized with logger

# MQTT connection and message handling
def on_connect(client, userdata, flags, rc, properties=None):
    result_code_map = {
        0: "Connection successful",
        1: "Connection refused - incorrect protocol version",
        2: "Connection refused - invalid client identifier",
        3: "Connection refused - server unavailable",
        4: "Connection refused - bad username or password",
        5: "Connection refused - not authorized"
    }
    
    if rc == 0:
        connection_status["connected"] = True
        connection_status["reconnect_count"] = 0
        connection_status["last_error"] = None
        logger.info(f"Connected to MQTT broker successfully (code: {rc})")
        
        # Subscribe to all action descriptions
        try:
            client.subscribe("$SYS/Coreflux/Actions/+/Description")
            logger.info("Subscribed to Coreflux action descriptions")
        except Exception as e:
            logger.error(f"Failed to subscribe to topics: {str(e)}")
    else:
        connection_status["connected"] = False
        connection_status["last_error"] = result_code_map.get(rc, f"Unknown error code: {rc}")
        logger.error(f"Failed to connect to MQTT broker: {connection_status['last_error']}")

def on_disconnect(client, userdata, rc, properties=None, reason_code=0):
    connection_status["connected"] = False
    if rc == 0:
        logger.info("Disconnected from MQTT broker gracefully")
    else:
        logger.warning(f"Unexpected disconnection from MQTT broker (code: {rc})")
        # Implement reconnection logic
        connection_status["reconnect_count"] += 1
        connection_status["last_connection_attempt"] = datetime.now()

def on_message(client, userdata, msg):
    try:
        # Store message in buffer (legacy support)
        topic = msg.topic
        try:
            payload = msg.payload.decode('utf-8')
        except UnicodeDecodeError:
            payload = str(msg.payload)
        
        # Enhanced message processing
        if message_processor:
            metadata = {
                "qos": msg.qos,
                "retain": msg.retain,
                "timestamp": time.time()
            }
            message_processor.add_message(topic, payload, metadata)
        
        # Legacy buffer (for backward compatibility)
        if topic not in mqtt_message_buffer:
            mqtt_message_buffer[topic] = []
        
        # Add message with timestamp
        mqtt_message_buffer[topic].append({
            "payload": payload,
            "timestamp": time.time(),
            "qos": msg.qos,
            "retain": msg.retain
        })
        
        # Limit buffer size (keep last 100 messages per topic)
        if len(mqtt_message_buffer[topic]) > 100:
            mqtt_message_buffer[topic] = mqtt_message_buffer[topic][-100:]
        
        # Extract action name from topic
        topic_parts = msg.topic.split('/')
        if len(topic_parts) >= 4 and topic_parts[-1] == "Description":
            action_name = topic_parts[-2]
            
            # Log the raw data for debugging
            payload_raw = msg.payload
            safe_log(logger.debug, f"Raw message received: {repr(payload_raw)}")
            
            try:
                # Safe decoding of the payload
                payload_str = payload_raw.decode('utf-8').strip()
                
                # Extract description using more robust parsing
                description = extract_description_safely(payload_str)
                
                # Check if we already have this action
                if action_name in discovered_actions:
                    # Only update the description if it changed
                    if discovered_actions[action_name] != description:
                        discovered_actions[action_name] = description
                        logger.info(f"Updated action description: {action_name} - {description}")
                    return
                    
                # New action discovered
                discovered_actions[action_name] = description
                logger.info(f"Discovered new action: {action_name} - {description}")
                
                # Register a dynamic tool for this action if not already registered
                if action_name not in registered_dynamic_tools:
                    register_dynamic_action_tool(action_name, description)
            
            except UnicodeDecodeError as e:
                logger.error(f"Failed to decode message payload: {str(e)}")
                return
                
    except Exception as e:
        logger.error(f"Error processing MQTT message: {str(e)}", exc_info=True)

# Helper function for safely extracting descriptions from potentially malformed JSON
def extract_description_safely(payload_str):
    """
    Extract description from a payload string that might be JSON or plain text.
    Implements robust parsing to handle malformed JSON gracefully.
    
    Args:
        payload_str: The string to parse
        
    Returns:
        A string representing the description
    """
    # If it's empty, return empty string
    if not payload_str or not payload_str.strip():
        return ""
        
    # If it doesn't look like JSON, just return the string as-is
    if not (payload_str.strip().startswith('{') and payload_str.strip().endswith('}')):
        return payload_str.strip()
    
    # It looks like JSON, try to parse it properly
    try:
        # Parse as JSON using the parser module
        data = process_json_rpc_message(payload_str)
        
        # If it's a dict with a description field, return that
        if isinstance(data, dict) and 'description' in data:
            return data['description']
        
        # Otherwise, return the whole object as a string
        return payload_str
    
    except Exception as e:
        logger.warning(f"JSON parse error: {str(e)}")
        safe_log(logger.debug, f"Problematic payload: {payload_str}")
        
        # Return the payload as-is since we couldn't parse it
        return payload_str

def register_dynamic_action_tool(action_name, description):
    try:
        # Skip if already registered
        if action_name in registered_dynamic_tools:
            return
            
        # Create a unique function name for this action
        tool_func_name = f"run_{action_name}"
        
        # Create function in a safer way - avoid direct string interpolation in exec
        # Create the function text with proper escaping for the docstring
        description_safe = description.replace('\\', '\\\\').replace('"', '\\"')
        
        # Define the function code
        func_code = f'''
@mcp.tool()
async def {tool_func_name}(ctx: Context) -> str:
    """Run the {action_name} action: {description_safe}"""
    response = execute_command(f"-runAction {action_name}")
    logger.info(f"Executed action {action_name}")
    return response
'''
        
        # Execute the code in global scope
        exec(func_code, globals())
        
        # Mark as registered
        registered_dynamic_tools.add(action_name)
        logger.info(f"Registered dynamic tool for action: {action_name} as {tool_func_name}")
    except Exception as e:
        logger.error(f"Failed to register dynamic tool for {action_name}: {str(e)}", exc_info=True)

# Setup MQTT client
def setup_mqtt(args):
    global mqtt_client
    
    # Set logging level from arguments
    try:
        log_level = getattr(logging, args.log_level)
        logger.setLevel(log_level)
        logger.info(f"Log level set to {args.log_level}")
    except AttributeError:
        logger.warning(f"Invalid log level: {args.log_level}, defaulting to INFO")
        logger.setLevel(logging.INFO)
    
    # Use protocol version 5 (MQTT v5) with the newer callback API and unique client ID
    try:
        mqtt_client = mqtt.Client(client_id=args.mqtt_client_id, protocol=mqtt.MQTTv5, callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
        
        # Set up authentication if provided
        if args.mqtt_user and args.mqtt_password:
            mqtt_client.username_pw_set(args.mqtt_user, args.mqtt_password)
            safe_log(logger.debug, f"Using MQTT authentication with username: {args.mqtt_user}")
        
        # Configure TLS if enabled
        if args.mqtt_use_tls:
            # Check if certificate files exist before attempting to use them
            cert_files = [
                (args.mqtt_ca_cert, "CA certificate"),
                (args.mqtt_client_cert, "Client certificate"),
                (args.mqtt_client_key, "Client key")
            ]
            
            missing_files = []
            for cert_path, cert_name in cert_files:
                if cert_path and not os.path.exists(cert_path):
                    missing_files.append(f"{cert_name} at {cert_path}")
            
            if missing_files:
                safe_log(logger.error, f"Missing certificate files: {', '.join(missing_files)}")
                logger.warning("TLS configuration incomplete. MQTT client created but not connected.")
                # Set callbacks but don't attempt connection
                mqtt_client.on_connect = on_connect
                mqtt_client.on_message = on_message
                mqtt_client.on_disconnect = on_disconnect
                return False
                
            mqtt_client.tls_set(
                ca_certs=args.mqtt_ca_cert,
                certfile=args.mqtt_client_cert,
                keyfile=args.mqtt_client_key
            )
            logger.info("TLS configuration enabled for MQTT connection")
        
        # Set callbacks
        mqtt_client.on_connect = on_connect
        mqtt_client.on_message = on_message
        mqtt_client.on_disconnect = on_disconnect
        
        # Attempt to connect to broker
        safe_log(logger.info, f"Attempting to connect to MQTT broker at {args.mqtt_host}:{args.mqtt_port} with client ID: {args.mqtt_client_id}")
        connection_status["last_connection_attempt"] = datetime.now()
        
        # Set a connection timeout
        try:
            mqtt_client.connect(args.mqtt_host, args.mqtt_port, 60)
            mqtt_client.loop_start()
            
            # Wait briefly to check connection status
            max_wait = 3  # seconds
            for _ in range(max_wait * 2):
                if connection_status["connected"]:
                    logger.info("MQTT client connected successfully")
                    return True
                time.sleep(0.5)
            
            # If we get here, we didn't connect within the timeout
            logger.warning(f"MQTT connection not confirmed after {max_wait} seconds, but client initialized")
            logger.info("Use mqtt_connect tool or check_broker_health to retry connection")
            return False
            
        except (ConnectionRefusedError, TimeoutError, OSError) as e:
            logger.warning(f"Failed to connect to MQTT broker: {str(e)}")
            connection_status["last_error"] = str(e)
            logger.info("MQTT client initialized but not connected. Use mqtt_connect tool to retry.")
            return False
        except Exception as e:
            logger.warning(f"MQTT connection error: {str(e)}")
            connection_status["last_error"] = str(e)
            logger.info("MQTT client initialized but not connected. Use mqtt_connect tool to retry.")
            return False
            
    except Exception as e:
        logger.error(f"Error creating MQTT client: {str(e)}", exc_info=True)
        connection_status["last_error"] = str(e)
        logger.warning("MQTT client creation failed. Some tools may not work until connection is established.")
        return False

# Helper function to execute Coreflux commands
def execute_command(command_string, timeout=10.0):
    if not mqtt_client:
        error_msg = "MQTT client not initialized"
        logger.error(error_msg)
        return f"ERROR: {error_msg}"
        
    if not connection_status["connected"]:
        error_msg = "MQTT client not connected"
        logger.error(error_msg)
        return f"ERROR: {error_msg}"
        
    # Event to signal when we receive a response
    response_event = threading.Event()
    response_data = {"payload": None, "error": None}
    
    # Callback for command output messages
    def on_command_output(client, userdata, msg):
        try:
            payload = msg.payload.decode('utf-8')
            response_data["payload"] = payload
            logger.debug(f"Received command output: {payload}")
        except UnicodeDecodeError:
            response_data["payload"] = str(msg.payload)
        except Exception as e:
            response_data["error"] = f"Error processing command output: {str(e)}"
        response_event.set()
    
    try:
        # Subscribe to command output topic
        output_topic = "$SYS/Coreflux/Command/Output"
        mqtt_client.message_callback_add(output_topic, on_command_output)
        
        subscribe_result, mid = mqtt_client.subscribe(output_topic, 0)
        if subscribe_result != mqtt.MQTT_ERR_SUCCESS:
            error_msg = f"Failed to subscribe to command output: {mqtt.error_string(subscribe_result)}"
            logger.error(error_msg)
            return f"ERROR: {error_msg}"
        
        logger.debug(f"Subscribed to {output_topic} for command feedback")
        
        # Small delay to ensure subscription is established
        time.sleep(0.1)
        
        # Publish the command
        publish_result = mqtt_client.publish("$SYS/Coreflux/Command", command_string)
        if publish_result.rc != mqtt.MQTT_ERR_SUCCESS:
            error_msg = f"Failed to publish command: {mqtt.error_string(publish_result.rc)}"
            logger.error(error_msg)
            # Clean up subscription
            mqtt_client.unsubscribe(output_topic)
            mqtt_client.message_callback_remove(output_topic)
            return f"ERROR: {error_msg}"
        
        safe_log(logger.info, f"Published command: {sanitize_log_message(command_string)}")
        
        # Wait for response or timeout
        if response_event.wait(timeout):
            # Response received
            if response_data["error"]:
                logger.error(response_data["error"])
                response = f"ERROR: {response_data['error']}"
            else:
                response = response_data["payload"] or "Command executed (no output)"
                logger.info(f"Command completed successfully")
        else:
            # Timeout
            logger.warning(f"Command response timeout after {timeout} seconds")
            response = f"WARNING: Command sent but no response received within {timeout} seconds"
        
        # Clean up subscription
        mqtt_client.unsubscribe(output_topic)
        mqtt_client.message_callback_remove(output_topic)
        
        return response
        
    except Exception as e:
        error_msg = f"MQTT protocol error while executing command: {str(e)}"
        logger.error(error_msg)
        # Attempt cleanup
        try:
            mqtt_client.unsubscribe(output_topic)
            mqtt_client.message_callback_remove(output_topic)
        except:
            pass
        return f"ERROR: {error_msg}"

# region COREFLUX TOOLS

class StringModel(BaseModel):
    value: str
    @validator('value', pre=True)
    def ensure_string(cls, v):
        if not isinstance(v, str):
            raise ValueError('Value must be a string')
        return v

@mcp.tool()
async def add_rule(rule_definition: str, ctx: Context) -> str:
    try:
        StringModel(value=rule_definition)
    except Exception as e:
        return f"ERROR: rule_definition must be a string: {e}"
    safe_log(logger.info, f"Adding rule: {rule_definition[:50]}..." if len(rule_definition) > 50 else f"Adding rule: {rule_definition}")
    result = execute_command(f"-addRule {rule_definition}")
    try:
        StringModel(value=result)
    except Exception as e:
        return f"ERROR: Output is not a string: {e}"
    return result

@mcp.tool()
async def remove_rule(rule_name: str, ctx: Context) -> str:
    try:
        StringModel(value=rule_name)
    except Exception as e:
        return f"ERROR: rule_name must be a string: {e}"
    logger.info(f"Removing rule: {rule_name}")
    result = execute_command(f"-removeRule {rule_name}")
    try:
        StringModel(value=result)
    except Exception as e:
        return f"ERROR: Output is not a string: {e}"
    return result

@mcp.tool()
async def add_route(ctx: Context) -> str:
    """Add a new route connection"""
    logger.info("Adding new route")
    result = execute_command("-addRoute")
    try:
        StringModel(value=result)
    except Exception as e:
        return f"ERROR: Output is not a string: {e}"
    return result

@mcp.tool()
async def remove_route(route_id: str, ctx: Context) -> str:
    try:
        StringModel(value=route_id)
    except Exception as e:
        return f"ERROR: route_id must be a string: {e}"
    logger.info(f"Removing route: {route_id}")
    result = execute_command(f"-removeRoute {route_id}")
    try:
        StringModel(value=result)
    except Exception as e:
        return f"ERROR: Output is not a string: {e}"
    return result

@mcp.tool()
async def add_model(model_definition: str, ctx: Context) -> str:
    try:
        StringModel(value=model_definition)
    except Exception as e:
        return f"ERROR: model_definition must be a string: {e}"
    safe_log(logger.info, f"Adding model: {model_definition[:50]}..." if len(model_definition) > 50 else f"Adding model: {model_definition}")
    result = execute_command(f"-addModel {model_definition}")
    try:
        StringModel(value=result)
    except Exception as e:
        return f"ERROR: Output is not a string: {e}"
    return result

@mcp.tool()
async def remove_model(model_name: str, ctx: Context) -> str:
    try:
        StringModel(value=model_name)
    except Exception as e:
        return f"ERROR: model_name must be a string: {e}"
    logger.info(f"Removing model: {model_name}")
    result = execute_command(f"-removeModel {model_name}")
    try:
        StringModel(value=result)
    except Exception as e:
        return f"ERROR: Output is not a string: {e}"
    return result

@mcp.tool()
async def add_action(action_definition: str, ctx: Context) -> str:
    try:
        StringModel(value=action_definition)
    except Exception as e:
        return f"ERROR: action_definition must be a string: {e}"
    safe_log(logger.info, f"Adding action: {action_definition[:50]}..." if len(action_definition) > 50 else f"Adding action: {action_definition}")
    result = execute_command(f"-addAction {action_definition}")
    try:
        StringModel(value=result)
    except Exception as e:
        return f"ERROR: Output is not a string: {e}"
    return result

@mcp.tool()
async def remove_action(action_name: str, ctx: Context) -> str:
    try:
        StringModel(value=action_name)
    except Exception as e:
        return f"ERROR: action_name must be a string: {e}"
    logger.info(f"Removing action: {action_name}")
    result = execute_command(f"-removeAction {action_name}")
    try:
        StringModel(value=result)
    except Exception as e:
        return f"ERROR: Output is not a string: {e}"
    return result

@mcp.tool()
async def run_action(action_name: str, ctx: Context) -> str:
    try:
        StringModel(value=action_name)
    except Exception as e:
        return f"ERROR: action_name must be a string: {e}"
    logger.info(f"Running action: {action_name}")
    result = execute_command(f"-runAction {action_name}")
    try:
        StringModel(value=result)
    except Exception as e:
        return f"ERROR: Output is not a string: {e}"
    return result

# @mcp.tool()
# async def remove_all_models(ctx: Context) -> str:
#     """Remove all models from Coreflux"""
#     logger.warning("Removing ALL models - this is a destructive operation")
#     result = execute_command("-removeAllModels")
#     try:
#         StringModel(value=result)
#     except Exception as e:
#         return f"ERROR: Output is not a string: {e}"
#     return result

# @mcp.tool()
# async def remove_all_actions(ctx: Context) -> str:
#     """Remove all actions from Coreflux"""
#     logger.warning("Removing ALL actions - this is a destructive operation")
#     result = execute_command("-removeAllActions")
#     try:
#         StringModel(value=result)
#     except Exception as e:
#         return f"ERROR: Output is not a string: {e}"
#     return result

# @mcp.tool()
# async def remove_all_routes(ctx: Context) -> str:
#     """Remove all routes from Coreflux"""
#     logger.warning("Removing ALL routes - this is a destructive operation")
#     result = execute_command("-removeAllRoutes")
#     try:
#         StringModel(value=result)
#     except Exception as e:
#         return f"ERROR: Output is not a string: {e}"
#     return result

@mcp.tool()
async def lot_diagnostic(diagnostic_value: str, ctx: Context) -> str:
    try:
        StringModel(value=diagnostic_value)
    except Exception as e:
        return f"ERROR: diagnostic_value must be a string: {e}"
    logger.info(f"Setting LOT diagnostic to: {diagnostic_value}")
    result = execute_command(f"-lotDiagnostic {diagnostic_value}")
    try:
        StringModel(value=result)
    except Exception as e:
        return f"ERROR: Output is not a string: {e}"
    return result

@mcp.tool()
async def list_discovered_actions(ctx: Context) -> str:
    """List all discovered Coreflux actions"""
    if not discovered_actions:
        logger.info("No actions discovered yet")
        return "No actions discovered yet."
    
    logger.info(f"Listing {len(discovered_actions)} discovered actions")
    result = "Discovered Coreflux Actions:\n\n"
    for action_name, description in discovered_actions.items():
        tool_status = "✓" if action_name in registered_dynamic_tools else "✗"
        result += f"- {action_name}: {description} [Tool: {tool_status}]\n"
    
    try:
        StringModel(value=result)
    except Exception as e:
        return f"ERROR: Output is not a string: {e}"
    return result

@mcp.tool()
async def get_connection_status(ctx: Context) -> str:
    """Get the current MQTT connection status and guidance for troubleshooting"""
    status = {
        "connected": connection_status["connected"],
        "last_connection_attempt": str(connection_status["last_connection_attempt"]) if connection_status["last_connection_attempt"] else None,
        "reconnect_count": connection_status["reconnect_count"],
        "last_error": connection_status["last_error"],
        "discovered_actions": len(discovered_actions),
        "registered_tools": len(registered_dynamic_tools),
        "mqtt_client_initialized": mqtt_client is not None
    }
    
    # Add troubleshooting guidance
    guidance = []
    if not mqtt_client:
        guidance.append("❌ MQTT client not initialized. This indicates a serious configuration issue.")
        guidance.append("💡 Try running setup_assistant.py to configure your connection.")
    elif not connection_status["connected"]:
        guidance.append("⚠️ MQTT client initialized but not connected.")
        guidance.append("💡 Use mqtt_connect tool to establish connection.")
        guidance.append("💡 Use check_broker_health tool to test and reconnect.")
        if connection_status["last_error"]:
            guidance.append(f"🔍 Last error: {connection_status['last_error']}")
    else:
        guidance.append("✅ MQTT connection is healthy and active.")
        if len(discovered_actions) == 0:
            guidance.append("ℹ️ No Coreflux actions discovered yet. This may be normal for new connections.")
    
    status["troubleshooting_guidance"] = guidance
    
    logger.info(f"Connection status requested: connected={status['connected']}, client_initialized={status['mqtt_client_initialized']}")
    result = json.dumps(status, indent=2)
    try:
        StringModel(value=result)
    except Exception as e:
        return f"ERROR: Output is not a string: {e}"
    return result

@mcp.tool()
def request_lot_code(ctx: Context, query: str, context: str = "") -> str:
    """
    Request LOT code generation from the DigitalOcean Agent Platform API.
    
    This function sends a query to the DigitalOcean Agent Platform to generate
    LOT (Logic Object Tree) code based on the provided query and context.
    
    Args:
        ctx: The MCP context
        query: The query describing what LOT code to generate
        context: Optional context to provide additional information
        
    Returns:
        A formatted string containing the generated LOT code and explanation
    """
    try:
        StringModel(value=query)
        StringModel(value=context)
    except Exception as e:
        return f"ERROR: query/context must be a string: {e}"
    
    # Check if API key is configured
    api_key = args.do_agent_api_key
    if not api_key:
        error_msg = "DigitalOcean Agent Platform API key not configured. Please set DO_AGENT_API_KEY in your .env file or use --do-agent-api-key argument."
        logger.error(error_msg)
        return f"Error: {error_msg}"
    
    # Log function call (API key will be automatically redacted)
    log_function_call("request_lot_code", query=query, context=context, api_key=api_key)
    
    # Coreflux Copilot API endpoint
    api_url = "https://xtov5ljwjkydusw2zpus4yxe.agents.do-ai.run/api/v1/chat/completions"

    # Create payload for Coreflux Copilot
    # The Coreflux Copilot expects a specific chat completion format
    try:
        # Build the user message content
        user_content = f"Generate LOT code for the following query: {query}"
        if context:
            user_content += f"\n\nContext: {context}"
        
        payload = {
            "messages": [
                {
                    "role": "user",
                    "content": user_content
                }
            ],
            "stream": False,
            "include_functions_info": False,
            "include_retrieval_info": True,
            "include_guardrails_info": False
        }
        
        safe_log(logger.debug, f"Sending request to DO Agent Platform: {json.dumps(payload, ensure_ascii=False)[:200]}...")
        safe_log(logger.info, f"Requesting LOT code generation with query: {query[:50]}..." if len(query) > 50 else f"Requesting LOT code generation with query: {query}")
    except Exception as e:
        error_msg = f"Failed to create payload: {str(e)}"
        logger.error(error_msg)
        return f"Error: {error_msg}"
    
    try:
        # Set proper headers for Coreflux Copilot API
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        
        response = requests.post(api_url, json=payload, headers=headers, timeout=30)
        
        # Debug the raw response
        safe_log(logger.debug, f"Raw API response status: {response.status_code}")
        safe_log(logger.debug, f"Raw API response headers: {dict(response.headers)}")
        safe_log(logger.debug, f"Raw API response content: {response.text[:200]}..." if len(response.text) > 200 else response.text)
        
        if response.status_code == 200:
            # Process the response from Coreflux Copilot
            result = process_do_agent_response(response.text)
            try:
                StringModel(value=result)
            except Exception as e:
                return f"ERROR: Output is not a string: {e}"
            return result
        else:
            error_msg = f"API request failed with status {response.status_code}: {response.text}"
            logger.error(error_msg)
            return f"Error: {error_msg}"
    except requests.exceptions.Timeout:
        error_msg = "API request timed out after 30 seconds"
        logger.error(error_msg)
        return f"Error: {error_msg}"
    except requests.exceptions.ConnectionError:
        error_msg = "Connection error occurred when making API request"
        logger.error(error_msg)
        return f"Error: {error_msg}"
    except Exception as e:
        error_msg = f"Error making API request: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"

def process_do_agent_response(response_text):
    """
    Process the response from the DigitalOcean Agent Platform API.
    
    Args:
        response_text: The raw API response text
        
    Returns:
        A formatted string with the processed result, or an error message
    """
    if not response_text or not response_text.strip():
        error_msg = "Empty API response"
        logger.error(error_msg)
        return f"Error: {error_msg}"
    
    # Normalize the response text
    cleaned_text = response_text.strip()
    
    try:
        # Try to parse the response as JSON
        result = json.loads(cleaned_text)
        
        # Log success
        logger.info(f"LOT code generation successful")
        
        # Format the response for output
        formatted_result = format_do_agent_output(result)
        try:
            StringModel(value=formatted_result)
        except Exception as e:
            return f"ERROR: Output is not a string: {e}"
        return formatted_result
        
    except json.JSONDecodeError as e:
        # If it's not JSON, treat it as plain text response
        logger.info(f"Received plain text response from DO Agent Platform")
        # Return the raw text as is
        return cleaned_text
        
    except Exception as e:
        error_msg = f"Error processing API response: {str(e)}"
        logger.error(error_msg)
        safe_log(logger.debug, f"Problematic response: {cleaned_text[:500]}...")
        return f"Error: {error_msg}"

def format_do_agent_output(result):
    """
    Format the Coreflux Copilot response for better readability.
    
    Args:
        result: The parsed result object from the chat completion API
        
    Returns:
        A formatted string with the processed result
    """
    # If it's a string, return it directly
    if isinstance(result, str):
        return result
    
    # If it's not a dict, convert to string
    if not isinstance(result, dict):
        return str(result)
    
    # Initialize output array
    output = []
    
    # Extract fields with safe access
    def safe_get(obj, key, default=""):
        """Safely get a value from a dictionary"""
        if isinstance(obj, dict) and key in obj:
            value = obj[key]
            return value if value is not None else default
        return default
    
    # Handle chat completion response format
    # Look for 'choices' array (standard OpenAI-style chat completion format)
    choices = safe_get(result, "choices")
    if choices and isinstance(choices, list) and len(choices) > 0:
        # Get the first choice
        choice = choices[0]
        if isinstance(choice, dict):
            # Extract the message content
            message = safe_get(choice, "message")
            if isinstance(message, dict):
                content = safe_get(message, "content")
                if content:
                    output.append(content)
                    output.append("")
    
    # If no choices found, check for other common response fields
    if not output:
        # Check for 'response' field (common in agent platforms)
        response_content = safe_get(result, "response")
        if response_content:
            output.append(response_content)
            output.append("")
        
        # Check for 'message' field
        message = safe_get(result, "message")
        if message and message != response_content:
            output.append(message)
            output.append("")
        
        # Check for 'content' field
        content = safe_get(result, "content")
        if content and content != response_content and content != message:
            output.append(content)
            output.append("")
    
    # Check for 'lot_code' field specifically
    lot_code = safe_get(result, "lot_code")
    if lot_code:
        output.append("```lot")
        output.append(lot_code)
        output.append("```")
        output.append("")
    
    # Check for 'code' field
    code = safe_get(result, "code")
    if code and code != lot_code:
        output.append("```")
        output.append(code)
        output.append("```")
        output.append("")
    
    # Add explanation if present
    explanation = safe_get(result, "explanation")
    if explanation:
        output.append("## Explanation")
        output.append(explanation)
        output.append("")
    
    # Add description if present
    description = safe_get(result, "description")
    if description and description != explanation:
        output.append("## Description")
        output.append(description)
        output.append("")
    
    # If we didn't recognize any fields, return the raw object as string
    if not output:
        return json.dumps(result, indent=2)
        
    # Join all parts with newlines and return
    return "\n".join(output).strip()

@mcp.tool()
async def verify_lot_snippet(lot_code: str, description: str = "", ctx: Context = None) -> str:
    """
    Send a LOT code snippet to an API endpoint for verification and feedback.
    
    This function validates LOT syntax, checks for best practices, and provides
    suggestions for improvement through an external verification service.
    
    Args:
        lot_code: The LOT code snippet to verify
        description: Optional description of what the code is supposed to do
        
    Returns:
        A formatted string containing verification results and feedback
    """
    try:
        StringModel(value=lot_code)
        StringModel(value=description)
    except Exception as e:
        return f"ERROR: lot_code/description must be a string: {e}"
    
    # Log function call (no sensitive data in LOT verification)
    log_function_call("verify_lot_snippet", lot_code=lot_code[:50] + "..." if len(lot_code) > 50 else lot_code, description=description)
    
    # Get API endpoint from configuration (configurable for different environments)
    api_url = args.lot_verifier_api_url
    
    # Build the verification payload
    try:
        # Create JSON payload with code and filename fields
        payload = {
            "code": lot_code,
            "filename": f"{description}.lot" if description else "snippet.lot"
        }
        
        safe_log(logger.debug, f"Sending LOT verification request with code length: {len(lot_code)} characters")
        safe_log(logger.info, f"Verifying LOT snippet: {description[:30]}..." if description and len(description) > 30 else f"Verifying LOT snippet")
        
    except Exception as e:
        error_msg = f"Failed to create verification payload: {str(e)}"
        logger.error(error_msg)
        return f"Error: {error_msg}"
    
    try:
        # Set headers for the verification API
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "CorefluxMCP/1.0"
        }
        
        # Make the API request
        response = requests.post(api_url, json=payload, headers=headers, timeout=15)
        
        # Debug the response
        safe_log(logger.debug, f"LOT verification API response status: {response.status_code}")
        safe_log(logger.debug, f"LOT verification API response: {response.text[:200]}..." if len(response.text) > 200 else response.text)
        
        if response.status_code == 200:
            # Process successful verification response
            result = process_lot_verification_response(response.text)
            try:
                StringModel(value=result)
            except Exception as e:
                return f"ERROR: Output is not a string: {e}"
            return result
        elif response.status_code == 400:
            # Bad request - likely syntax error in LOT code
            try:
                error_data = json.loads(response.text)
                error_msg = error_data.get("message", "Invalid LOT syntax")
                logger.warning(f"LOT verification failed: {error_msg}")
                return f"LOT Verification Failed: {error_msg}"
            except json.JSONDecodeError:
                return f"LOT Verification Failed: Invalid request (status 400)"
        else:
            # Handle other error status codes
            error_msg = f"LOT verification API returned status {response.status_code}: {response.text}"
            logger.error(error_msg)
            return f"Error: {error_msg}"
            
    except requests.exceptions.Timeout:
        error_msg = "LOT verification request timed out after 15 seconds"
        logger.error(error_msg)
        return f"Error: {error_msg}"
    except requests.exceptions.ConnectionError:
        error_msg = "Connection error occurred when accessing LOT verification API"
        logger.error(error_msg)
        return f"Error: {error_msg}. Note: This is a temporary API endpoint that may not be available yet."
    except Exception as e:
        error_msg = f"Error making LOT verification request: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"Error: {error_msg}"

def process_lot_verification_response(response_text):
    """
    Process the response from the LOT verification API.
    
    Args:
        response_text: The raw API response text
        
    Returns:
        A formatted string with verification results and feedback
    """
    if not response_text or not response_text.strip():
        error_msg = "Empty verification response"
        logger.error(error_msg)
        return f"Error: {error_msg}"
    
    # Normalize the response text
    cleaned_text = response_text.strip()
    
    try:
        # Parse the verification response as JSON
        result = json.loads(cleaned_text)
        
        logger.info("LOT verification completed successfully")
        
        # Format the verification results for output
        formatted_result = format_lot_verification_output(result)
        try:
            StringModel(value=formatted_result)
        except Exception as e:
            return f"ERROR: Output is not a string: {e}"
        return formatted_result
        
    except json.JSONDecodeError as e:
        # If it's not JSON, treat it as plain text response
        logger.warning(f"Received non-JSON response from LOT verification API")
        return cleaned_text
        
    except Exception as e:
        error_msg = f"Error processing LOT verification response: {str(e)}"
        logger.error(error_msg)
        safe_log(logger.debug, f"Problematic verification response: {cleaned_text[:500]}...")
        return f"Error: {error_msg}"

def format_lot_verification_output(result):
    """
    Format the LOT verification response for better readability.
    
    Args:
        result: The parsed verification result object
        
    Returns:
        A formatted string with verification results and feedback
    """
    # If it's a string, return it directly
    if isinstance(result, str):
        return result
    
    # If it's not a dict, convert to string
    if not isinstance(result, dict):
        return str(result)
    
    # Initialize output array
    output = []
    
    # Helper function for safe dictionary access
    def safe_get(obj, key, default=""):
        """Safely get a value from a dictionary"""
        if isinstance(obj, dict) and key in obj:
            value = obj[key]
            return value if value is not None else default
        return default
    
    # Extract verification status
    status = safe_get(result, "status")
    is_valid = safe_get(result, "valid")
    
    # Add status header
    if status:
        if is_valid:
            output.append(f"✅ LOT Verification Status: {status}")
        else:
            output.append(f"❌ LOT Verification Status: {status}")
    elif is_valid is not None:
        if is_valid:
            output.append("✅ LOT Code is Valid")
        else:
            output.append("❌ LOT Code has Issues")
    
    output.append("")
    
    # Extract and display errors
    errors = safe_get(result, "errors")
    if errors:
        output.append("## 🚨 Errors Found:")
        if isinstance(errors, list):
            for error in errors:
                if isinstance(error, dict):
                    line = error.get("line", "")
                    message = error.get("message", str(error))
                    if line:
                        output.append(f"- Line {line}: {message}")
                    else:
                        output.append(f"- {message}")
                else:
                    output.append(f"- {error}")
        else:
            output.append(f"- {errors}")
        output.append("")
    
    # Extract and display warnings
    warnings = safe_get(result, "warnings")
    if warnings:
        output.append("## ⚠️ Warnings:")
        if isinstance(warnings, list):
            for warning in warnings:
                if isinstance(warning, dict):
                    message = warning.get("message", str(warning))
                    output.append(f"- {message}")
                else:
                    output.append(f"- {warning}")
        else:
            output.append(f"- {warnings}")
        output.append("")
    
    # Extract and display suggestions
    suggestions = safe_get(result, "suggestions")
    if suggestions:
        output.append("## 💡 Suggestions for Improvement:")
        if isinstance(suggestions, list):
            for suggestion in suggestions:
                if isinstance(suggestion, dict):
                    category = suggestion.get("category", "")
                    message = suggestion.get("message", str(suggestion))
                    if category:
                        output.append(f"- **{category}**: {message}")
                    else:
                        output.append(f"- {message}")
                else:
                    output.append(f"- {suggestion}")
        else:
            output.append(f"- {suggestions}")
        output.append("")
    
    # Extract complexity analysis
    complexity = safe_get(result, "complexity")
    if complexity:
        output.append("## 📊 Complexity Analysis:")
        if isinstance(complexity, dict):
            score = complexity.get("score", "")
            level = complexity.get("level", "")
            comments = complexity.get("comments", "")
            
            if score:
                output.append(f"- Complexity Score: {score}")
            if level:
                output.append(f"- Complexity Level: {level}")
            if comments:
                output.append(f"- Comments: {comments}")
        else:
            output.append(f"- {complexity}")
        output.append("")
    
    # Extract best practices feedback
    best_practices = safe_get(result, "best_practices")
    if best_practices:
        output.append("## ✨ Best Practices Feedback:")
        if isinstance(best_practices, list):
            for practice in best_practices:
                output.append(f"- {practice}")
        else:
            output.append(f"- {best_practices}")
        output.append("")
    
    # Extract any general feedback
    feedback = safe_get(result, "feedback")
    if feedback and feedback not in [suggestions, best_practices]:
        output.append("## 📝 Additional Feedback:")
        output.append(feedback)
        output.append("")
    
    # If we didn't extract any meaningful data, return the raw object
    if len(output) <= 2:  # Only status header and empty line
        return json.dumps(result, indent=2)
        
    # Join all parts and return
    return "\n".join(output).strip()

# endregion

# region MCP RESOURCES

# Resources for LOT language documentation
@mcp.resource("lot://documentation/models")
def lot_models_docs() -> str:
    """Documentation for LOT Models"""
    return """
# LOT Language - Model Management Documentation

## 1. Overview
Models in Coreflux use the LOT language syntax to define how data is processed, transformed, and published. Models take input data (triggered by specific topics), process it through expressions, constants, or transformations, and output the results to new MQTT topics.

## 2. Model Syntax
```
DEFINE MODEL <model_name> WITH TOPIC "<output_base_topic>"
    ADD "<property_name>" WITH TOPIC "<input_topic>" [AS TRIGGER]
    ADD "<property_name>" WITH <constant_value>
    ADD "<property_name>" WITH (expression)
```

## 3. Example Model
```
DEFINE MODEL GenericEnergyCost WITH TOPIC "Coreflux/+/+/+/+/energy"
    ADD "total_energy" WITH TOPIC "shellies/+/+/+/+/device/energy" AS TRIGGER
    ADD "energy_price" WITH 3
    ADD "cost" WITH (total_energy * energy_price)
```
"""

@mcp.resource("lot://documentation/rules")
def lot_rules_docs() -> str:
    """Documentation for LOT Rules"""
    return """
# LOT Language - Rule Management Documentation

## 1. Overview
Rules in Coreflux govern user permissions and system actions, ensuring precise control over system operations.

## 2. Rule Syntax
```
DEFINE RULE <rule_name> WITH PRIORITY <priority_value> FOR <action_scope>
    IF <condition> THEN
        ALLOW
    ELSE
        DENY
```

## 3. Example Rule
```
DEFINE RULE SpecificTopicClient WITH PRIORITY 1 FOR Subscribe TO TOPIC "Emanuel/#"
    IF USER IS "Emanuel" THEN
        ALLOW
    ELSE
        DENY
```
"""

@mcp.resource("lot://documentation/actions")
def lot_actions_docs() -> str:
    """Documentation for LOT Actions"""
    return """
# LOT Language - Action Management Documentation

## 1. Overview
LOT scripting language defines Actions—small logic blocks that react to events (time-based or topic-based) and publish data to topics.

## 2. Action Syntax
```
DEFINE ACTION <ActionName>
ON EVERY ... or ON TOPIC ... or only DO 
DO
    IF <expression> THEN
        PUBLISH ...
    ELSE
        PUBLISH ...
```


## 3. Example Action that runs every 5 seconds 
```
DEFINE ACTION StrokeGenerator
ON EVERY 5 SECONDS 
DO
    IF GET TOPIC "Coreflux/Porto/MeetingRoom/Light1/command/switch:0" == "off" THEN
        PUBLISH TOPIC "Coreflux/Porto/MeetingRoom/Light1/command/switch:0" WITH "on"
    ELSE
        PUBLISH TOPIC "Coreflux/Porto/MeetingRoom/Light1/command/switch:0" WITH "off"
```
## 4. Example Action that can be called by run action 
```
DEFINE ACTION TurnLampOff
DO
    PUBLISH TOPIC "Coreflux/Porto/MeetingRoom/Light1/command/switch:0" WITH "off"
DESCRIPTION "Turns a specific topic off"
```



"""

# endregion

# region MQTT TOOLS

class MqttMessageModel(BaseModel):
    message: str

    @validator('message', pre=True)
    def ensure_json_string(cls, v):
        import json
        if isinstance(v, dict):
            return json.dumps(v)
        # Validate that the string is valid JSON
        try:
            json.loads(v)
        except Exception:
            raise ValueError("message must be a valid JSON string")
        return v

@mcp.tool()
async def setup_mqtt_connection(broker: str, port: int = 1883, username: str = None, password: str = None, 
                               client_id: str = None, use_tls: bool = False, ctx: Context = None) -> str:
    """
    Setup and initialize a new MQTT connection with custom parameters.
    This is useful when the server started without a valid MQTT connection.
    
    Args:
        broker: The MQTT broker hostname or IP address
        port: The MQTT broker port (default: 1883)
        username: Optional username for authentication
        password: Optional password for authentication
        client_id: Optional client ID (default: auto-generated)
        use_tls: Whether to use TLS encryption (default: False)
        
    Returns:
        A string indicating success or failure of the setup
    """
    global mqtt_client, args
    
    # Log function call with sanitized arguments (password will be redacted)
    log_function_call("setup_mqtt_connection", broker=broker, port=port, username=username, 
                     password=password, client_id=client_id, use_tls=use_tls)
    
    # Generate client ID if not provided
    if not client_id:
        client_id = f"coreflux-mcp-{uuid.uuid4().hex[:8]}"
    
    # Update global args object with new settings
    args.mqtt_host = broker
    args.mqtt_port = port
    args.mqtt_user = username
    args.mqtt_password = password
    args.mqtt_client_id = client_id
    args.mqtt_use_tls = use_tls
    
    # Disconnect existing client if present
    if mqtt_client:
        try:
            if connection_status["connected"]:
                mqtt_client.disconnect()
            mqtt_client.loop_stop()
            mqtt_client = None
            logger.info("Disconnected from previous MQTT broker")
        except Exception as e:
            logger.warning(f"Error disconnecting from previous broker: {e}")
    
    # Setup new connection
    safe_log(logger.info, f"Setting up new MQTT connection to {broker}:{port}")
    setup_result = setup_mqtt(args)
    
    if setup_result:
        return f"Successfully set up and connected to MQTT broker at {broker}:{port}"
    else:
        return f"MQTT client configured for {broker}:{port} but connection failed. Use check_broker_health to retry."

@mcp.tool()
async def reconnect_mqtt(ctx: Context) -> str:
    """Force a reconnection to the MQTT broker"""
    if mqtt_client is None:
        error_msg = "Cannot reconnect - MQTT client not initialized"
        logger.error(error_msg)
        return f"ERROR: {error_msg}"
        
    try:
        # First disconnect if connected
        if connection_status["connected"]:
            mqtt_client.disconnect()
            
        # Parse args again to get current settings
        args = parse_args()
        
        # Connect with current settings
        logger.info(f"Attempting to reconnect to MQTT broker at {args.mqtt_host}:{args.mqtt_port}")
        connection_status["last_connection_attempt"] = datetime.now()
        mqtt_client.connect(args.mqtt_host, args.mqtt_port, 60)
        
        # Give it a moment to connect
        time.sleep(1)
        
        if connection_status["connected"]:
            logger.info("Reconnection successful")
            return "Successfully reconnected to MQTT broker"
        else:
            logger.warning("Reconnection attempt completed but connection not confirmed")
            return "Reconnection attempt completed but connection not confirmed. Check logs for details."
    except Exception as e:
        error_msg = f"Failed to reconnect: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return f"ERROR: {error_msg}"

@mcp.tool()
async def check_broker_health(ctx: Context) -> str:
    """Check the health of the MQTT broker and attempt to reconnect if needed"""
    if not mqtt_client:
        error_msg = "MQTT client not initialized"
        logger.error(error_msg)
        return f"ERROR: {error_msg}"
        
    if connection_status["connected"]:
        logger.info("MQTT broker connection is healthy")
        return "MQTT broker connection is healthy"
    else:
        logger.warning("MQTT broker connection appears to be down, attempting to reconnect")
        return await reconnect_mqtt(ctx)

@mcp.tool()
async def mqtt_connect(broker: str, port: int = 1883, username: str = None, password: str = None, 
                      client_id: str = None, use_tls: bool = False, ctx: Context = None) -> str:
    """
    Connect to a specific MQTT broker.
    
    Args:
        broker: The MQTT broker hostname or IP address
        port: The MQTT broker port (default: 1883)
        username: Optional username for authentication
        password: Optional password for authentication
        client_id: Optional client ID (default: auto-generated)
        use_tls: Whether to use TLS encryption (default: False)
        
    Returns:
        A string indicating success or failure of the connection attempt
    """
    global mqtt_client
    
    # Generate client ID if not provided
    if not client_id:
        client_id = f"coreflux-mcp-{uuid.uuid4().hex[:8]}"
    
    # Log the attempt
    safe_log(logger.info, f"Attempting to connect to MQTT broker at {broker}:{port} with client ID: {client_id}")
    
    try:
        # Create new client
        mqtt_client = mqtt.Client(client_id=client_id, protocol=mqtt.MQTTv5, 
                                 callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
        
        # Set up authentication if provided
        if username and password:
            mqtt_client.username_pw_set(username, password)
            safe_log(logger.debug, f"Using MQTT authentication with username: {username}")
        
        # Configure TLS if enabled
        if use_tls:
            mqtt_client.tls_set()
            logger.info("TLS configuration enabled for MQTT connection")
        
        # Set callbacks
        mqtt_client.on_connect = on_connect
        mqtt_client.on_message = on_message
        mqtt_client.on_disconnect = on_disconnect
        
        # Connect to broker
        connection_status["last_connection_attempt"] = datetime.now()
        mqtt_client.connect(broker, port, 60)
        mqtt_client.loop_start()
        
        # Wait briefly to check connection status
        max_wait = 3  # seconds
        for _ in range(max_wait * 2):
            if connection_status["connected"]:
                logger.info("MQTT client connected successfully")
                return f"Successfully connected to MQTT broker at {broker}:{port}"
            time.sleep(0.5)
        
        # If we get here, we didn't connect within the timeout
        logger.warning(f"MQTT connection not confirmed after {max_wait} seconds, but loop started")
        return f"Connection attempt completed, but status unclear. Use get_connection_status to verify."
        
    except Exception as e:
        error_msg = f"Failed to connect to MQTT broker: {str(e)}"
        logger.error(error_msg)
        connection_status["last_error"] = str(e)
        return f"ERROR: {error_msg}"

@mcp.tool()
async def mqtt_publish(topic: str, message, qos: int = 0, retain: bool = False, is_json: bool = False, ctx: Context = None) -> str:
    """
    Publish a message to an MQTT topic.
    
    IMPORTANT: Please format the message as a string. If you need to send JSON, please format it as a string with escaped quotes.

    Args:
        topic: The MQTT topic to publish to
        message: The message payload to publish (string or JSON object)
        qos: Quality of Service level (0, 1, or 2)
        retain: Whether the message should be retained by the broker
        is_json: Force message to be treated as JSON (default: auto-detect)
        
    Returns:
        A string confirming successful publication or describing an error
    """
    if not mqtt_client:
        error_msg = "MQTT client not initialized. Use mqtt_connect first."
        logger.error(error_msg)
        return f"ERROR: {error_msg}"
        
    if not connection_status["connected"]:
        error_msg = "MQTT client not connected. Use mqtt_connect first."
        logger.error(error_msg)
        return f"ERROR: {error_msg}"
    
    try:
        # Validate and serialize message as JSON string using Pydantic
        try:
            validated = MqttMessageModel(message=message)
            payload = validated.message
            logger.debug("Message validated and serialized as JSON string")
        except Exception as e:
            error_msg = f"Message validation failed: {e}"
            logger.error(error_msg)
            return f"ERROR: {error_msg}"
        
        # Log the attempt
        safe_log(logger.info, f"Publishing to topic '{topic}' with QoS {qos}, retain={retain}")
        safe_log(logger.debug, f"Message payload: {payload[:100]}{'...' if len(payload) > 100 else ''}")
        
        # Publish the message
        result = mqtt_client.publish(topic, payload, qos=qos, retain=retain)
        if result.rc == mqtt.MQTT_ERR_SUCCESS:
            logger.info(f"Successfully published to '{topic}'")
            return f"Message successfully published to topic '{topic}'"
        else:
            error_msg = f"Failed to publish message: {mqtt.error_string(result.rc)}"
            logger.error(error_msg)
            return f"ERROR: {error_msg}"
    except Exception as e:
        error_msg = f"Error while publishing message: {str(e)}"
        logger.error(error_msg)
        return f"ERROR: {error_msg}"

@mcp.tool()
async def mqtt_subscribe(topic: str, qos: int = 0, ctx: Context = None) -> str:
    """
    Subscribe to an MQTT topic.
    
    Args:
        topic: The MQTT topic to subscribe to (can include wildcards # and +)
        qos: Quality of Service level (0, 1, or 2)
        
    Returns:
        A string confirming successful subscription or describing an error
    """
    if not mqtt_client:
        error_msg = "MQTT client not initialized. Use mqtt_connect first."
        logger.error(error_msg)
        return f"ERROR: {error_msg}"
        
    if not connection_status["connected"]:
        error_msg = "MQTT client not connected. Use mqtt_connect first."
        logger.error(error_msg)
        return f"ERROR: {error_msg}"
    
    try:
        # Log the attempt
        logger.info(f"Subscribing to topic '{topic}' with QoS {qos}")
        
        # Subscribe to the topic
        result, mid = mqtt_client.subscribe(topic, qos)
        if result == mqtt.MQTT_ERR_SUCCESS:
            # Track this subscription
            mqtt_subscriptions[topic] = {
                "qos": qos,
                "subscribed_at": datetime.now().isoformat()
            }
            
            logger.info(f"Successfully subscribed to '{topic}'")
            return f"Successfully subscribed to topic '{topic}' with QoS {qos}"
        else:
            error_msg = f"Failed to subscribe to topic: {mqtt.error_string(result)}"
            logger.error(error_msg)
            return f"ERROR: {error_msg}"
    except Exception as e:
        error_msg = f"Error while subscribing: {str(e)}"
        logger.error(error_msg)
        return f"ERROR: {error_msg}"

@mcp.tool()
async def mqtt_unsubscribe(topic: str, ctx: Context = None) -> str:
    """
    Unsubscribe from an MQTT topic.
    
    Args:
        topic: The MQTT topic to unsubscribe from
        
    Returns:
        A string confirming successful unsubscription or describing an error
    """
    if not mqtt_client:
        error_msg = "MQTT client not initialized. Use mqtt_connect first."
        logger.error(error_msg)
        return f"ERROR: {error_msg}"
        
    if not connection_status["connected"]:
        error_msg = "MQTT client not connected. Use mqtt_connect first."
        logger.error(error_msg)
        return f"ERROR: {error_msg}"
    
    try:
        # Log the attempt
        logger.info(f"Unsubscribing from topic '{topic}'")
        
        # Unsubscribe from the topic
        result, mid = mqtt_client.unsubscribe(topic)
        if result == mqtt.MQTT_ERR_SUCCESS:
            # Remove from tracked subscriptions
            if topic in mqtt_subscriptions:
                del mqtt_subscriptions[topic]
                
            logger.info(f"Successfully unsubscribed from '{topic}'")
            return f"Successfully unsubscribed from topic '{topic}'"
        else:
            error_msg = f"Failed to unsubscribe from topic: {mqtt.error_string(result)}"
            logger.error(error_msg)
            return f"ERROR: {error_msg}"
    except Exception as e:
        error_msg = f"Error while unsubscribing: {str(e)}"
        logger.error(error_msg)
        return f"ERROR: {error_msg}"

@mcp.tool()
async def mqtt_read_messages(topic: Optional[str] = None, max_messages: int = 10, clear_buffer: bool = False, ctx: Context = None) -> str:
    """
    Read messages from the MQTT message buffer.
    
    Args:
        topic: The specific topic to read from (None for all topics)
        max_messages: Maximum number of messages to return per topic (max 100)
        clear_buffer: Whether to clear the message buffer after reading
        
    Returns:
        A formatted string containing the retrieved messages or error information
    """
    if not mqtt_client:
        error_msg = "MQTT client not initialized. Use mqtt_connect first."
        logger.error(error_msg)
        return f"ERROR: {error_msg}"
    
    try:
        # Record start time to prevent hanging
        start_time = time.time()
        timeout_seconds = 10  # 10 second timeout
        
        if not mqtt_message_buffer:
            logger.info("No messages in buffer")
            return "No messages have been received yet."
        
        # Filter by topic if provided
        topics_to_read = [topic] if topic else list(mqtt_message_buffer.keys())
        
        # Limit the number of topics to process to prevent blocking
        if len(topics_to_read) > 10:
            topics_to_read = topics_to_read[:10]
            logger.warning(f"Limited to processing first 10 topics out of {len(mqtt_message_buffer)} available")
        
        # Build result
        result = []
        
        for t in topics_to_read:
            # Check for timeout
            if time.time() - start_time > timeout_seconds:
                logger.warning(f"mqtt_read_messages timed out after {timeout_seconds} seconds")
                result.append(f"⚠️ Operation timed out - showing partial results")
                break
                
            if t in mqtt_message_buffer:
                # Ensure max_messages is positive and reasonable
                safe_max_messages = max(1, min(max_messages, 100)) if max_messages > 0 else 10
                messages = mqtt_message_buffer[t][-safe_max_messages:]
                
                # Format messages for this topic
                result.append(f"Topic: {t}")
                result.append(f"Messages: {len(messages)} (showing last {len(messages)})")
                result.append("-" * 40)
                
                for idx, msg in enumerate(messages):
                    # Check for timeout in inner loop too
                    if time.time() - start_time > timeout_seconds:
                        result.append(f"⚠️ Timeout reached - partial message list")
                        break
                        
                    result.append(f"Message {idx+1}:")
                    # Truncate very long payloads to prevent blocking
                    payload = str(msg['payload'])
                    if len(payload) > 500:
                        payload = payload[:500] + "... (truncated)"
                    result.append(f"  Payload: {payload}")
                    result.append(f"  Timestamp: {datetime.fromtimestamp(msg['timestamp']).isoformat()}")
                    result.append(f"  QoS: {msg['qos']}")
                    result.append(f"  Retain: {msg['retain']}")
                    result.append("-" * 20)
                
                # Clear buffer if requested
                if clear_buffer:
                    mqtt_message_buffer[t] = []
            
        if not result:
            return f"No messages found for topic '{topic}'" if topic else "No messages found"
            
        # Clear all buffer if requested
        if clear_buffer and not topic:
            mqtt_message_buffer.clear()
            
        logger.info(f"Read {len(result)} messages" + (f" from topic '{topic}'" if topic else ""))
        return "\n".join(result)
    except Exception as e:
        error_msg = f"Error while reading messages: {str(e)}"
        logger.error(error_msg)
        return f"ERROR: {error_msg}"

@mcp.tool()
async def mqtt_list_subscriptions(ctx: Context = None) -> str:
    """
    List all active MQTT subscriptions.
    
    Returns:
        A formatted string listing all active subscriptions
    """
    if not mqtt_client:
        error_msg = "MQTT client not initialized. Use mqtt_connect first."
        logger.error(error_msg)
        return f"ERROR: {error_msg}"
        
    if not connection_status["connected"]:
        error_msg = "MQTT client not connected. Use mqtt_connect first."
        logger.error(error_msg)
        return f"ERROR: {error_msg}"
    
    if not mqtt_subscriptions:
        logger.info("No active subscriptions")
        return "No active subscriptions"
        
    # Format the result
    result = ["Active MQTT Subscriptions:"]
    for topic, details in mqtt_subscriptions.items():
        result.append(f"- Topic: {topic}")
        result.append(f"  QoS: {details['qos']}")
        result.append(f"  Subscribed at: {details['subscribed_at']}")
        
    logger.info(f"Listed {len(mqtt_subscriptions)} active subscriptions")
    return "\n".join(result)

@mcp.tool()
async def mqtt_read_topic_once(topic: str, timeout: float = 5.0, qos: int = 0, ctx: Context = None) -> str:
    """
    One-off MQTT topic read: Subscribes to a topic, waits for a single message, then unsubscribes and returns the message.
    This is for single, immediate reads (not continuous monitoring).

    Args:
        topic: The MQTT topic to read from
        timeout: Maximum time (in seconds) to wait for a message (default: 5.0)
        qos: Quality of Service level (0, 1, or 2)
    Returns:
        The first received message payload, or an error/timeout message
    """
    if not mqtt_client:
        error_msg = "MQTT client not initialized. Use mqtt_connect first."
        logger.error(error_msg)
        return f"ERROR: {error_msg}"
    if not connection_status["connected"]:
        error_msg = "MQTT client not connected. Use mqtt_connect first."
        logger.error(error_msg)
        return f"ERROR: {error_msg}"
    event = None
    message_holder = {}
    import threading
    def on_temp_message(client, userdata, msg):
        try:
            message_holder["payload"] = msg.payload.decode("utf-8", errors="replace")
            message_holder["timestamp"] = time.time()
            message_holder["qos"] = msg.qos
            message_holder["retain"] = msg.retain
        except Exception as e:
            message_holder["payload"] = str(msg.payload)
        if event:
            event.set()
    event = threading.Event()
    # Temporarily add a message callback for this topic
    mqtt_client.message_callback_add(topic, on_temp_message)
    try:
        logger.info(f"[One-off] Subscribing to topic '{topic}' for one message (timeout {timeout}s)")
        result, mid = mqtt_client.subscribe(topic, qos)
        if result != mqtt.MQTT_ERR_SUCCESS:
            return f"ERROR: Failed to subscribe: {mqtt.error_string(result)}"
        # Wait for a message or timeout
        got_message = event.wait(timeout)
        mqtt_client.unsubscribe(topic)
        mqtt_client.message_callback_remove(topic)
        if got_message and "payload" in message_holder:
            return f"Received message on '{topic}': {message_holder['payload']}"
        else:
            return f"Timeout: No message received on '{topic}' within {timeout} seconds."
    except Exception as e:
        logger.error(f"Error in mqtt_read_topic_once: {e}")
        return f"ERROR: {e}"

@mcp.tool()
async def mqtt_monitor_topic(topic: str, qos: int = 0, ctx: Context = None) -> str:
    """
    Monitor MQTT topic: Subscribes to a topic for continuous monitoring. Messages will be buffered and can be read using mqtt_read_messages.
    This tool does NOT unsubscribe automatically. Use mqtt_unsubscribe to stop monitoring.

    Args:
        topic: The MQTT topic to monitor
        qos: Quality of Service level (0, 1, or 2)
    Returns:
        Confirmation of subscription or error message
    """
    if not mqtt_client:
        error_msg = "MQTT client not initialized. Use mqtt_connect first."
        logger.error(error_msg)
        return f"ERROR: {error_msg}"
    if not connection_status["connected"]:
        error_msg = "MQTT client not connected. Use mqtt_connect first."
        logger.error(error_msg)
        return f"ERROR: {error_msg}"
    try:
        logger.info(f"[Monitor] Subscribing to topic '{topic}' for monitoring")
        result, mid = mqtt_client.subscribe(topic, qos)
        if result == mqtt.MQTT_ERR_SUCCESS:
            mqtt_subscriptions[topic] = {
                "qos": qos,
                "subscribed_at": datetime.now().isoformat()
            }
            return f"Now monitoring topic '{topic}' (QoS {qos}). Use mqtt_read_messages to view messages."
        else:
            return f"ERROR: Failed to subscribe: {mqtt.error_string(result)}"
    except Exception as e:
        logger.error(f"Error in mqtt_monitor_topic: {e}")
        return f"ERROR: {e}"

# endregion

# @mcp.tool()
# async def comprehensive_health_check(ctx: Context) -> str:
#     """
#     Perform a comprehensive health check of the Coreflux MCP Server
    
#     Checks:
#     - Configuration validation
#     - MQTT connection status
#     - Message processing status
#     - Log system status
#     - System resources
#     - Recent errors
    
#     Returns:
#         A detailed health report with status and recommendations
#     """
#     health_report = {
#         "timestamp": datetime.now().isoformat(),
#         "overall_status": "unknown",
#         "checks": {},
#         "recommendations": [],
#         "statistics": {}
#     }
    
#     all_checks_passed = True
    
#     try:
#         # 1. Configuration Check
#         logger.info("Running comprehensive health check...")
#         config_validator = ConfigurationValidator(logger)
#         is_valid, errors, warnings = config_validator.validate_environment()
        
#         health_report["checks"]["configuration"] = {
#             "status": "pass" if is_valid else "fail",
#             "errors": errors,
#             "warnings": warnings
#         }
        
#         if not is_valid:
#             all_checks_passed = False
#             health_report["recommendations"].append("Fix configuration errors before deployment")
        
#         # 2. MQTT Connection Check
#         mqtt_status = "connected" if connection_status["connected"] else "disconnected"
#         health_report["checks"]["mqtt_connection"] = {
#             "status": mqtt_status,
#             "details": {
#                 "connected": connection_status["connected"],
#                 "last_connection_attempt": connection_status.get("last_connection_attempt"),
#                 "reconnect_count": connection_status.get("reconnect_count", 0),
#                 "last_error": connection_status.get("last_error")
#             }
#         }
        
#         if not connection_status["connected"]:
#             health_report["recommendations"].append("Establish MQTT connection using mqtt_connect tool")
        
#         # 3. Message Processing Check
#         if message_processor:
#             proc_stats = message_processor.get_statistics()
#             health_report["checks"]["message_processing"] = {
#                 "status": "active" if message_processor.processing_active else "inactive",
#                 "statistics": proc_stats
#             }
            
#             # Check processing rate
#             if proc_stats.get("processing_rate", 0) == 0 and proc_stats.get("messages_received", 0) > 0:
#                 all_checks_passed = False
#                 health_report["recommendations"].append("Message processing appears stalled")
#         else:
#             health_report["checks"]["message_processing"] = {
#                 "status": "not_initialized",
#                 "error": "Message processor not available"
#             }
#             all_checks_passed = False
        
#         # 4. Log System Check
#         try:
#             log_manager = get_log_manager()
#             log_stats = log_manager.get_log_stats()
#             health_report["checks"]["logging"] = {
#                 "status": "active",
#                 "statistics": log_stats
#             }
            
#             # Check log file sizes
#             total_size_mb = log_stats.get("total_size_bytes", 0) / (1024 * 1024)
#             if total_size_mb > 100:  # More than 100MB
#                 health_report["recommendations"].append(f"Log files are large ({total_size_mb:.1f}MB), consider cleanup")
                
#         except Exception as e:
#             health_report["checks"]["logging"] = {
#                 "status": "error",
#                 "error": str(e)
#             }
        
#         # 5. Server Uptime and Statistics
#         uptime = datetime.now() - server_start_time
#         health_report["statistics"]["uptime"] = {
#             "seconds": int(uptime.total_seconds()),
#             "human_readable": str(uptime),
#             "start_time": server_start_time.isoformat()
#         }
        
#         # 6. Discovery Statistics
#         health_report["statistics"]["discovery"] = {
#             "discovered_actions": len(discovered_actions),
#             "registered_dynamic_tools": len(registered_dynamic_tools),
#             "active_subscriptions": len(mqtt_subscriptions)
#         }
        
#         # 7. Memory Usage (simple check)
#         import sys
#         try:
#             if hasattr(sys, 'getsizeof'):
#                 buffer_size = sys.getsizeof(mqtt_message_buffer)
#                 health_report["statistics"]["memory"] = {
#                     "message_buffer_bytes": buffer_size,
#                     "topics_in_buffer": len(mqtt_message_buffer)
#                 }
                
#                 if buffer_size > 10 * 1024 * 1024:  # More than 10MB
#                     health_report["recommendations"].append("Message buffer is large, consider clearing old messages")
#         except Exception:
#             pass
        
#         # 8. Recent Errors Check
#         if connection_status.get("last_error"):
#             health_report["checks"]["recent_errors"] = {
#                 "status": "warning",
#                 "last_error": connection_status["last_error"]
#             }
#             health_report["recommendations"].append("Check recent error: " + str(connection_status["last_error"]))
#         else:
#             health_report["checks"]["recent_errors"] = {
#                 "status": "clean"
#             }
        
#         # 9. API Integration Check
#         if os.environ.get('DO_AGENT_API_KEY'):
#             health_report["checks"]["api_integration"] = {
#                 "status": "configured",
#                 "note": "API key is configured"
#             }
#         else:
#             health_report["checks"]["api_integration"] = {
#                 "status": "not_configured",
#                 "note": "DO_AGENT_API_KEY not set"
#             }
#             health_report["recommendations"].append("Configure DO_AGENT_API_KEY for LOT code generation")
        
#         # Overall Status
#         if all_checks_passed and connection_status["connected"]:
#             health_report["overall_status"] = "healthy"
#         elif connection_status["connected"]:
#             health_report["overall_status"] = "degraded"
#         else:
#             health_report["overall_status"] = "unhealthy"
        
#         # Format the response
#         status_emoji = {
#             "healthy": "✅",
#             "degraded": "⚠️",
#             "unhealthy": "❌"
#         }
        
#         result = f"{status_emoji[health_report['overall_status']]} **Coreflux MCP Server Health Check**\n\n"
#         result += f"**Overall Status:** {health_report['overall_status'].upper()}\n"
#         result += f"**Check Time:** {health_report['timestamp']}\n\n"
        
#         # Individual Checks
#         result += "**Component Status:**\n"
#         for check_name, check_data in health_report["checks"].items():
#             status = check_data.get("status", "unknown")
#             emoji = "✅" if status in ["pass", "active", "connected", "clean", "configured"] else \
#                    "⚠️" if status in ["warning", "degraded", "not_configured"] else "❌"
#             result += f"- {emoji} {check_name.replace('_', ' ').title()}: {status}\n"
        
#         # Statistics
#         if health_report["statistics"]:
#             result += "\n**Statistics:**\n"
#             uptime_stats = health_report["statistics"].get("uptime", {})
#             if uptime_stats:
#                 result += f"- Uptime: {uptime_stats.get('human_readable', 'unknown')}\n"
            
#             discovery_stats = health_report["statistics"].get("discovery", {})
#             if discovery_stats:
#                 result += f"- Discovered Actions: {discovery_stats.get('discovered_actions', 0)}\n"
#                 result += f"- Active Subscriptions: {discovery_stats.get('active_subscriptions', 0)}\n"
            
#             if message_processor:
#                 proc_stats = message_processor.get_statistics()
#                 result += f"- Messages Processed: {proc_stats.get('messages_processed', 0)}\n"
#                 result += f"- Processing Rate: {proc_stats.get('processing_rate', 0):.2f} msg/sec\n"
        
#         # Recommendations
#         if health_report["recommendations"]:
#             result += "\n**Recommendations:**\n"
#             for i, rec in enumerate(health_report["recommendations"], 1):
#                 result += f"{i}. {rec}\n"
        
#         if health_report["overall_status"] == "healthy":
#             result += "\n🎉 **All systems operational!**"
        
#         logger.info(f"Health check completed - Status: {health_report['overall_status']}")
#         return result
        
#     except Exception as e:
#         error_msg = f"Error during health check: {str(e)}"
#         logger.error(error_msg)
#         return f"❌ **Health Check Failed**\n\nError: {error_msg}\n\nPlease check server logs for details."

if __name__ == "__main__":
    try:
        logger.info("Starting Coreflux MQTT MCP Server")
        
        # Parse command-line arguments
        args = parse_args()
        
        # Attempt to initialize MQTT connection (non-blocking)
        mqtt_setup_result = setup_mqtt(args)
        if mqtt_setup_result:
            logger.info(f"Server started with client ID: {args.mqtt_client_id}")
            logger.info(f"Connected to MQTT broker at: {args.mqtt_host}:{args.mqtt_port}")
        else:
            logger.warning("Failed to initialize MQTT connection on startup.")
            logger.info("MCP server will start anyway. Use mqtt_connect tool to establish connection later.")
            logger.info("You can also run setup_assistant.py to configure your connection.")
        
        # Run with standard transport (regardless of MQTT connection status)
        logger.info("Starting FastMCP server")
        mcp.run()
    except KeyboardInterrupt:
        logger.info("Server shutdown requested by user")
        if mqtt_client:
            mqtt_client.disconnect()
            mqtt_client.loop_stop()
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Unhandled exception: {str(e)}", exc_info=True)
        if mqtt_client:
            mqtt_client.disconnect()
            mqtt_client.loop_stop()
        sys.exit(1)