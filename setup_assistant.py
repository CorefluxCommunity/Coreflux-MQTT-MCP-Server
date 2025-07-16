import os
import uuid
import logging
from datetime import datetime
from dotenv import load_dotenv
import sys
import argparse

# Define a custom NONE logging level (higher than CRITICAL)
NONE_LEVEL = 100  # Higher than CRITICAL (50)
logging.addLevelName(NONE_LEVEL, "NONE")

# Configure logging
def setup_logging(level_name="INFO"):
    # Special handling for NONE level
    if level_name == "NONE":
        # Disable all logging by setting level to NONE_LEVEL
        level = NONE_LEVEL
    else:
        # Use standard logging levels
        level = getattr(logging, level_name, logging.INFO)
    
    # Use a format that doesn't include 'name' to avoid conflicts
    fmt = '%(asctime)s - %(levelname)s - %(message)s'
    
    # Configure a handler with our format
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(fmt))
    handler.setLevel(level)
    
    # Get logger without setting a basicConfig that might conflict with MCP
    logger = logging.getLogger("CorefluxMCP")
    logger.setLevel(level)
    
    # Remove any existing handlers to avoid duplicates
    for h in logger.handlers[:]:
        logger.removeHandler(h)
    
    # Add our handler
    logger.addHandler(handler)
    
    return logger

# Initialize logger with default settings
logger = setup_logging()

def run_setup_assistant():
    """
    Interactive setup assistant for first-time configuration.
    Creates or updates the .env file with user-provided values.
    """
    print("\n" + "="*50)
    print("Coreflux MCP Server - Setup Assistant")
    print("="*50)
    print("This assistant will help you configure the server by creating or updating the .env file.")
    print("Press Enter to accept the default value shown in brackets [default].")
    print("-"*50)
    
    # Check if .env file exists
    env_file_exists = os.path.isfile(".env")
    env_vars = {}
    
    if env_file_exists:
        print("Existing .env file found. Current values will be shown as defaults.")
        # Read existing values
        with open(".env", "r") as f:
            for line in f:
                if line.strip() and not line.strip().startswith("#"):
                    try:
                        key, value = line.strip().split("=", 1)
                        env_vars[key] = value
                    except ValueError:
                        # Skip lines that don't have a key=value format
                        pass
    
    # MQTT Broker Configuration
    mqtt_broker = input(f"MQTT Broker Host [{ env_vars.get('MQTT_BROKER', 'localhost') }]: ").strip()
    env_vars["MQTT_BROKER"] = mqtt_broker if mqtt_broker else env_vars.get("MQTT_BROKER", "localhost")
    
    mqtt_port = input(f"MQTT Broker Port [{ env_vars.get('MQTT_PORT', '1883') }]: ").strip()
    env_vars["MQTT_PORT"] = mqtt_port if mqtt_port else env_vars.get("MQTT_PORT", "1883")
    
    mqtt_user = input(f"MQTT Username [{ env_vars.get('MQTT_USER', 'root') }]: ").strip()
    env_vars["MQTT_USER"] = mqtt_user if mqtt_user else env_vars.get("MQTT_USER", "root")
    
    mqtt_password = input(f"MQTT Password [{ env_vars.get('MQTT_PASSWORD', 'coreflux') }]: ").strip()
    env_vars["MQTT_PASSWORD"] = mqtt_password if mqtt_password else env_vars.get("MQTT_PASSWORD", "coreflux")
    
    mqtt_client_id = input(f"MQTT Client ID [{ env_vars.get('MQTT_CLIENT_ID', f'coreflux-mcp-{uuid.uuid4().hex[:8]}') }]: ").strip()
    env_vars["MQTT_CLIENT_ID"] = mqtt_client_id if mqtt_client_id else env_vars.get("MQTT_CLIENT_ID", f"coreflux-mcp-{uuid.uuid4().hex[:8]}")
    
    # TLS Configuration
    use_tls = input(f"Use TLS for MQTT connection (true/false) [{ env_vars.get('MQTT_USE_TLS', 'false') }]: ").strip().lower()
    if use_tls in ["true", "false"]:
        env_vars["MQTT_USE_TLS"] = use_tls
    else:
        env_vars["MQTT_USE_TLS"] = env_vars.get("MQTT_USE_TLS", "false")
    
    if env_vars["MQTT_USE_TLS"] == "true":
        ca_cert = input(f"Path to CA Certificate [{ env_vars.get('MQTT_CA_CERT', '') }]: ").strip()
        env_vars["MQTT_CA_CERT"] = ca_cert if ca_cert else env_vars.get("MQTT_CA_CERT", "")
        
        client_cert = input(f"Path to Client Certificate [{ env_vars.get('MQTT_CLIENT_CERT', '') }]: ").strip()
        env_vars["MQTT_CLIENT_CERT"] = client_cert if client_cert else env_vars.get("MQTT_CLIENT_CERT", "")
        
        client_key = input(f"Path to Client Key [{ env_vars.get('MQTT_CLIENT_KEY', '') }]: ").strip()
        env_vars["MQTT_CLIENT_KEY"] = client_key if client_key else env_vars.get("MQTT_CLIENT_KEY", "")
    
    # DigitalOcean Agent Platform API Configuration
    print("\n" + "-"*50)
    print("DigitalOcean Agent Platform API Configuration")
    print("This is required for the LOT code generation feature.")
    print("You can get your API key from the DigitalOcean Agent Platform dashboard.")
    print("-"*50)
    
    do_api_key = input(f"DigitalOcean Agent Platform API Key [{ env_vars.get('DO_AGENT_API_KEY', '') }]: ").strip()
    env_vars["DO_AGENT_API_KEY"] = do_api_key if do_api_key else env_vars.get("DO_AGENT_API_KEY", "")
    
    if not env_vars["DO_AGENT_API_KEY"]:
        print("WARNING: No API key provided. The LOT code generation feature will not work.")
        print("You can add the API key later by editing the .env file.")
    
    # Logging Configuration
    log_level = input(f"Log Level (NONE/DEBUG/INFO/WARNING/ERROR/CRITICAL) [{ env_vars.get('LOG_LEVEL', 'INFO') }]: ").strip().upper()
    valid_log_levels = ["NONE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    if log_level in valid_log_levels:
        env_vars["LOG_LEVEL"] = log_level
    else:
        env_vars["LOG_LEVEL"] = env_vars.get("LOG_LEVEL", "INFO")
    
    # Write to .env file
    with open(".env", "w") as f:
        f.write("# Coreflux MCP Server Configuration\n")
        f.write("# Generated by Setup Assistant\n")
        f.write(f"# {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # MQTT Configuration
        f.write("# MQTT Broker Configuration\n")
        f.write(f"MQTT_BROKER={env_vars['MQTT_BROKER']}\n")
        f.write(f"MQTT_PORT={env_vars['MQTT_PORT']}\n")
        f.write(f"MQTT_USER={env_vars['MQTT_USER']}\n")
        f.write(f"MQTT_PASSWORD={env_vars['MQTT_PASSWORD']}\n")
        f.write(f"MQTT_CLIENT_ID={env_vars['MQTT_CLIENT_ID']}\n\n")
        
        # TLS Configuration
        f.write("# TLS Configuration\n")
        f.write(f"MQTT_USE_TLS={env_vars['MQTT_USE_TLS']}\n")
        if env_vars["MQTT_USE_TLS"] == "true":
            f.write(f"MQTT_CA_CERT={env_vars['MQTT_CA_CERT']}\n")
            f.write(f"MQTT_CLIENT_CERT={env_vars['MQTT_CLIENT_CERT']}\n")
            f.write(f"MQTT_CLIENT_KEY={env_vars['MQTT_CLIENT_KEY']}\n")
        f.write("\n")
        
        # DigitalOcean Agent Platform API Configuration
        f.write("# DigitalOcean Agent Platform API Configuration\n")
        f.write("# Get your API key from DigitalOcean Agent Platform dashboard\n")
        f.write(f"DO_AGENT_API_KEY={env_vars['DO_AGENT_API_KEY']}\n\n")
        
        # Logging Configuration
        f.write("# Logging Configuration\n")
        f.write(f"LOG_LEVEL={env_vars['LOG_LEVEL']}\n")
    
    print("\nConfiguration saved to .env file successfully!")
    print("-"*50)
    print("You can now start the server with: python server.py")
    print("="*50 + "\n")
    
    # Reload environment variables
    load_dotenv(override=True)

def parse_args():
    """Parse command line arguments for setup assistant"""
    parser = argparse.ArgumentParser(description="Coreflux MCP Server Setup Assistant")
    parser.add_argument("--config-file", default=".env",
                      help="Path to configuration file to create/update (default: .env)")
    return parser.parse_args()

if __name__ == "__main__":
    logger.info("Starting Coreflux MCP Setup Assistant")
    args = parse_args()
    
    # Set the working directory to the script's directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    try:
        run_setup_assistant()
        logger.info("Setup completed successfully")
    except KeyboardInterrupt:
        logger.info("Setup aborted by user")
        print("\nSetup has been aborted. Your configuration may be incomplete.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error during setup: {str(e)}", exc_info=True)
        print(f"\nAn error occurred during setup: {str(e)}")
        sys.exit(1)