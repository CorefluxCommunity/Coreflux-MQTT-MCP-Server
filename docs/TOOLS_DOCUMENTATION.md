# Coreflux MCP Server - Complete Tools Documentation

## Table of Contents
- [Overview](#overview)
- [Coreflux Core Management Tools](#coreflux-core-management-tools)
- [MQTT Communication Tools](#mqtt-communication-tools)
- [System Management Tools](#system-management-tools)
- [AI Integration Tools](#ai-integration-tools)
- [Dynamic Action Tools](#dynamic-action-tools)
- [Configuration and Diagnostics](#configuration-and-diagnostics)
- [Example Use Cases](#example-use-cases)

## Overview

The Coreflux MCP Server provides comprehensive tools for managing Coreflux MQTT brokers, IoT devices, and automation systems through the Model Context Protocol (MCP). This server enables AI models to interact with industrial IoT infrastructure, manage device configurations, and automate complex workflows.

### Key Features
- **Real-time MQTT Communication**: Publish, subscribe, and monitor MQTT topics
- **Coreflux Management**: Create and manage rules, models, actions, and routes
- **Dynamic Action Discovery**: Automatically discover and execute Coreflux actions
- **AI-Powered Code Generation**: Generate LOT (Logic Object Tree) code using AI
- **Comprehensive Health Monitoring**: Monitor system health and troubleshoot issues
- **Secure Operations**: Built-in log sanitization and secure credential handling

---

## Coreflux Core Management Tools

These tools provide direct control over Coreflux's core components: Rules, Models, Actions, and Routes. They use the LOT (Logic Object Tree) language for defining system behavior.

### Rules Management

#### `add_rule`
**Description**: Add a new rule to the Coreflux system using LOT language syntax.

**Parameters**:
- `rule_definition` (string): Complete LOT rule definition

**Example Usage**:
```python
# Create a permission rule for specific user access
rule_def = """
DEFINE RULE SpecificTopicClient WITH PRIORITY 1 FOR Subscribe TO TOPIC "Emanuel/#"
    IF USER IS "Emanuel" THEN
        ALLOW
    ELSE
        DENY
"""
result = await add_rule(rule_def)
```

**Use Cases**:
- Define user access permissions for MQTT topics
- Create security policies for device interactions
- Implement quality of service rules
- Set up data validation rules

#### `remove_rule`
**Description**: Remove an existing rule from the Coreflux system.

**Parameters**:
- `rule_name` (string): Name of the rule to remove

**Example Usage**:
```python
# Remove a specific rule
result = await remove_rule("SpecificTopicClient")
```

**Use Cases**:
- Clean up obsolete security rules
- Remove temporary access permissions
- Update system policies by removing old rules

### Models Management

#### `add_model`
**Description**: Add a new data processing model to Coreflux using LOT language.

**Parameters**:
- `model_definition` (string): Complete LOT model definition

**Example Usage**:
```python
# Create an energy cost calculation model
model_def = """
DEFINE MODEL GenericEnergyCost WITH TOPIC "Coreflux/+/+/+/+/energy"
    ADD "total_energy" WITH TOPIC "shellies/+/+/+/+/device/energy" AS TRIGGER
    ADD "energy_price" WITH 3
    ADD "cost" WITH (total_energy * energy_price)
"""
result = await add_model(model_def)
```

**Use Cases**:
- Create data transformation pipelines
- Implement mathematical calculations on sensor data
- Build aggregation models for multi-device scenarios
- Design real-time analytics models

#### `remove_model`
**Description**: Remove an existing model from the Coreflux system.

**Parameters**:
- `model_name` (string): Name of the model to remove

**Example Usage**:
```python
# Remove a specific model
result = await remove_model("GenericEnergyCost")
```

#### `remove_all_models`
**Description**: Remove all models from the Coreflux system (destructive operation).

**Example Usage**:
```python
# Clear all models - use with caution!
result = await remove_all_models()
```

**Use Cases**:
- System reset during development
- Clean slate for new deployment
- Emergency cleanup operations

### Actions Management

#### `add_action`
**Description**: Add a new action to Coreflux using LOT language syntax.

**Parameters**:
- `action_definition` (string): Complete LOT action definition

**Example Usage**:
```python
# Create a periodic light control action
action_def = """
DEFINE ACTION StrokeGenerator
ON EVERY 5 SECONDS 
DO
    IF GET TOPIC "Coreflux/Porto/MeetingRoom/Light1/command/switch:0" == "off" THEN
        PUBLISH TOPIC "Coreflux/Porto/MeetingRoom/Light1/command/switch:0" WITH "on"
    ELSE
        PUBLISH TOPIC "Coreflux/Porto/MeetingRoom/Light1/command/switch:0" WITH "off"
"""
result = await add_action(action_def)
```

**Example 2 - Manual Trigger Action**:
```python
# Create a manual action for turning off lights
action_def = """
DEFINE ACTION TurnLampOff
DO
    PUBLISH TOPIC "Coreflux/Porto/MeetingRoom/Light1/command/switch:0" WITH "off"
DESCRIPTION "Turns a specific topic off"
"""
result = await add_action(action_def)
```

**Use Cases**:
- Implement scheduled automation tasks
- Create emergency shutdown procedures
- Build conditional response systems
- Design periodic maintenance routines

#### `run_action`
**Description**: Execute a specific action in Coreflux.

**Parameters**:
- `action_name` (string): Name of the action to execute

**Example Usage**:
```python
# Execute a specific action
result = await run_action("TurnLampOff")
```

**Use Cases**:
- Manual execution of automation tasks
- Testing action functionality
- Emergency interventions
- On-demand system operations

#### `remove_action`
**Description**: Remove an existing action from the Coreflux system.

**Parameters**:
- `action_name` (string): Name of the action to remove

#### `remove_all_actions`
**Description**: Remove all actions from the Coreflux system (destructive operation).

### Routes Management

#### `add_route`
**Description**: Add a new route connection in Coreflux.

**Example Usage**:
```python
# Add a new communication route
result = await add_route()
```

**Use Cases**:
- Establish new communication pathways
- Connect different system components
- Create redundant communication channels

#### `remove_route`
**Description**: Remove an existing route from the Coreflux system.

**Parameters**:
- `route_id` (string): ID of the route to remove

#### `remove_all_routes`
**Description**: Remove all routes from the Coreflux system (destructive operation).

---

## MQTT Communication Tools

These tools provide comprehensive MQTT functionality for real-time communication with IoT devices and systems.

### Connection Management

#### `setup_mqtt_connection`
**Description**: Setup and initialize a new MQTT connection with custom parameters.

**Parameters**:
- `broker` (string): MQTT broker hostname or IP address
- `port` (int, optional): MQTT broker port (default: 1883)
- `username` (string, optional): Username for authentication
- `password` (string, optional): Password for authentication
- `client_id` (string, optional): Client ID (default: auto-generated)
- `use_tls` (bool, optional): Whether to use TLS encryption (default: False)

**Example Usage**:
```python
# Setup secure MQTT connection
result = await setup_mqtt_connection(
    broker="mqtt.coreflux.org",
    port=8883,
    username="myuser",
    password="mypassword",
    use_tls=True
)
```

**Use Cases**:
- Initial system configuration
- Switching between different MQTT brokers
- Establishing secure connections for production
- Testing connectivity to different environments

#### `mqtt_connect`
**Description**: Connect to a specific MQTT broker with authentication and TLS options.

**Parameters**: Same as `setup_mqtt_connection`

**Use Cases**:
- Quick connection establishment
- Testing different broker configurations
- Reconnecting after network issues

#### `reconnect_mqtt`
**Description**: Force a reconnection to the current MQTT broker.

**Example Usage**:
```python
# Force reconnection
result = await reconnect_mqtt()
```

**Use Cases**:
- Recovering from connection drops
- Refreshing authentication tokens
- Clearing connection state issues

#### `check_broker_health`
**Description**: Check the health of the MQTT broker and attempt to reconnect if needed.

**Example Usage**:
```python
# Check and repair broker connection
result = await check_broker_health()
```

**Use Cases**:
- Automated health monitoring
- Proactive connection maintenance
- Troubleshooting connectivity issues

### Messaging Operations

#### `mqtt_publish`
**Description**: Publish a message to an MQTT topic with quality of service and retention options.

**Parameters**:
- `topic` (string): MQTT topic to publish to
- `message` (string/object): Message payload to publish
- `qos` (int, optional): Quality of Service level (0, 1, or 2) (default: 0)
- `retain` (bool, optional): Whether the message should be retained (default: False)
- `is_json` (bool, optional): Force message to be treated as JSON (default: auto-detect)

**Example Usage**:
```python
# Publish sensor data
result = await mqtt_publish(
    topic="sensors/temperature/room1",
    message="23.5",
    qos=1,
    retain=True
)

# Publish JSON data
result = await mqtt_publish(
    topic="device/config",
    message='{"temperature_threshold": 25, "humidity_threshold": 60}',
    qos=2
)
```

**Use Cases**:
- Sending sensor readings
- Publishing device commands
- Broadcasting system status
- Updating configuration parameters

### Subscription Management

#### `mqtt_subscribe`
**Description**: Subscribe to an MQTT topic to receive messages.

**Parameters**:
- `topic` (string): MQTT topic to subscribe to (supports wildcards)
- `qos` (int, optional): Quality of Service level (default: 0)

**Example Usage**:
```python
# Subscribe to specific sensor
result = await mqtt_subscribe("sensors/temperature/room1", qos=1)

# Subscribe to all sensors using wildcards
result = await mqtt_subscribe("sensors/+/+", qos=1)

# Subscribe to entire topic tree
result = await mqtt_subscribe("building/#", qos=0)
```

**Use Cases**:
- Monitoring device status
- Collecting sensor data
- Tracking system events
- Implementing alerting systems

#### `mqtt_unsubscribe`
**Description**: Unsubscribe from an MQTT topic.

**Parameters**:
- `topic` (string): MQTT topic to unsubscribe from

**Example Usage**:
```python
# Stop monitoring specific topic
result = await mqtt_unsubscribe("sensors/temperature/room1")
```

#### `mqtt_list_subscriptions`
**Description**: List all active MQTT subscriptions.

**Example Usage**:
```python
# View current subscriptions
result = await mqtt_list_subscriptions()
```

**Use Cases**:
- Auditing active subscriptions
- Troubleshooting message reception
- Managing subscription overhead

### Message Monitoring

#### `mqtt_read_messages`
**Description**: Read buffered messages from subscribed topics.

**Parameters**:
- `topic` (string, optional): Specific topic to read from (default: all topics)
- `max_messages` (int, optional): Maximum number of messages to return (default: 10)
- `clear_buffer` (bool, optional): Clear buffer after reading (default: False)

**Example Usage**:
```python
# Read latest messages from all topics
result = await mqtt_read_messages(max_messages=20)

# Read messages from specific topic
result = await mqtt_read_messages(
    topic="sensors/temperature/room1",
    max_messages=5,
    clear_buffer=True
)
```

**Use Cases**:
- Analyzing recent sensor data
- Debugging message flows
- Historical data review
- System monitoring

#### `mqtt_monitor_topic`
**Description**: Start monitoring a specific topic (subscribe and track).

**Parameters**:
- `topic` (string): MQTT topic to monitor
- `qos` (int, optional): Quality of Service level (default: 0)

**Example Usage**:
```python
# Start monitoring critical sensor
result = await mqtt_monitor_topic("sensors/emergency/fire", qos=2)
```

**Use Cases**:
- Real-time alerting
- Critical system monitoring
- Data collection for analysis
- Event tracking

#### `mqtt_read_topic_once`
**Description**: Subscribe to a topic, wait for one message, then unsubscribe.

**Parameters**:
- `topic` (string): MQTT topic to read from
- `timeout` (float, optional): Timeout in seconds (default: 5.0)
- `qos` (int, optional): Quality of Service level (default: 0)

**Example Usage**:
```python
# Get current status of a device
result = await mqtt_read_topic_once(
    topic="devices/thermostat/status",
    timeout=10.0
)
```

**Use Cases**:
- One-time status checks
- Testing device responsiveness
- Sampling current values
- Quick diagnostics

---

## System Management Tools

### Health and Status Monitoring

#### `comprehensive_health_check`
**Description**: Perform a comprehensive health check of all server components including configuration validation, MQTT connection status, message processing, and system resources.

**Example Usage**:
```python
# Get complete system health report
result = await comprehensive_health_check()
```

**Returns**: Detailed health report including:
- Configuration validation status
- MQTT connection health
- Message processing statistics
- Log system status
- Server uptime and statistics
- Memory usage information
- Recent errors and warnings
- Troubleshooting recommendations

**Use Cases**:
- System monitoring dashboards
- Automated health checks
- Troubleshooting system issues
- Performance monitoring
- Preventive maintenance

#### `get_connection_status`
**Description**: Get detailed MQTT connection status and troubleshooting guidance.

**Example Usage**:
```python
# Check connection status with guidance
result = await get_connection_status()
```

**Returns**: JSON formatted status including:
- Connection state
- Last connection attempt
- Reconnection count
- Error details
- Discovered actions count
- Troubleshooting guidance

**Use Cases**:
- Connection troubleshooting
- System status dashboards
- Automated monitoring
- Issue diagnostics

### Discovery and Management

#### `list_discovered_actions`
**Description**: List all Coreflux actions discovered through MQTT topics.

**Example Usage**:
```python
# View all available actions
result = await list_discovered_actions()
```

**Returns**: List of discovered actions with:
- Action names
- Descriptions
- Tool registration status

**Use Cases**:
- System capability discovery
- Available actions inventory
- Dynamic tool management
- System documentation

---

## AI Integration Tools

### LOT Code Generation

#### `request_lot_code`
**Description**: Request LOT (Logic Object Tree) code generation from the DigitalOcean Agent Platform API using AI assistance.

**Parameters**:
- `query` (string): Description of the LOT code to generate
- `context` (string, optional): Additional context for code generation

**Example Usage**:
```python
# Generate a temperature monitoring action
result = await request_lot_code(
    query="Create an action that monitors room temperature and turns on cooling when it exceeds 25°C",
    context="Smart building automation for meeting room"
)

# Generate a complex energy management model
result = await request_lot_code(
    query="Create a model that calculates energy consumption costs and sends alerts when daily costs exceed $50",
    context="Industrial facility with multiple power meters"
)
```

**Returns**: Formatted response containing:
- Generated LOT code
- Explanation of functionality
- Implementation details
- Usage recommendations

**Use Cases**:
- Rapid automation development
- Learning LOT language syntax
- Complex system design
- Code template generation
- AI-assisted programming

**Prerequisites**: Requires `DO_AGENT_API_KEY` environment variable to be configured.

### LOT Code Verification

#### `verify_lot_snippet`
**Description**: Send a LOT code snippet to an API endpoint for verification and feedback. Validates syntax, checks for best practices, and provides suggestions for improvement.

**Parameters**:
- `lot_code` (string): The LOT code snippet to verify
- `description` (string, optional): Description of what the code is supposed to do

**Example Usage**:
```python
# Verify a simple action
lot_code = """
DEFINE ACTION TurnLampOff
DO
    PUBLISH TOPIC "Coreflux/Porto/MeetingRoom/Light1/command/switch:0" WITH "off"
DESCRIPTION "Turns a specific topic off"
"""
result = await verify_lot_snippet(
    lot_code=lot_code,
    description="Simple lamp control action"
)

# Verify a complex model with error checking
lot_code = """
DEFINE MODEL EnergyMonitor WITH TOPIC "energy/costs/+"
    ADD "power_reading" WITH TOPIC "sensors/power/+" AS TRIGGER
    ADD "rate_per_kwh" WITH 0.12
    ADD "daily_cost" WITH (power_reading * rate_per_kwh * 24)
"""
result = await verify_lot_snippet(
    lot_code=lot_code,
    description="Energy cost calculation model"
)
```

**Returns**: Formatted verification response containing:
- ✅/❌ Validation status
- 🚨 **Errors**: Syntax errors and critical issues
- ⚠️ **Warnings**: Potential problems and style issues  
- 💡 **Suggestions**: Recommendations for improvement
- 📊 **Complexity Analysis**: Code complexity metrics
- ✨ **Best Practices**: Feedback on coding standards

**Use Cases**:
- Validate LOT syntax before deployment
- Get suggestions for code improvement
- Learn best practices for LOT development
- Debug complex LOT expressions
- Code quality assurance

**Configuration**: 
- API endpoint configurable via `LOT_VERIFIER_API_URL` environment variable
- Default: `http://localhost:8000/validate/code`
- Command line: `--lot-verifier-api-url`

**API Format**: 
- Sends JSON payload: `{"code": "LOT_CODE", "filename": "DESCRIPTION.lot"}`
- Content-Type: `application/json`
- Expects JSON response with verification results

**Note**: Default endpoint assumes a local validation service running on localhost:8000.

---

## Dynamic Action Tools

The server automatically discovers Coreflux actions and creates dynamic tools for each one. These tools are generated at runtime based on action descriptions received via MQTT.

### Dynamic Tool Creation Process

1. **Discovery**: Server subscribes to `$SYS/Coreflux/Actions/+/Description`
2. **Registration**: When an action description is received, a new tool is automatically created
3. **Execution**: Tools can be called like any other MCP tool to execute the corresponding action

### Generated Tool Pattern

For each discovered action `ActionName`, a tool `run_ActionName` is created:

**Example Generated Tools**:
```python
# If action "EmergencyShutdown" is discovered:
async def run_EmergencyShutdown(ctx: Context) -> str:
    """Run the EmergencyShutdown action: Immediately shuts down all non-critical systems"""
    # Executes: -runAction EmergencyShutdown

# If action "NightMode" is discovered:
async def run_NightMode(ctx: Context) -> str:
    """Run the NightMode action: Activates energy-saving night mode configuration"""
    # Executes: -runAction NightMode
```

**Use Cases**:
- Zero-configuration action execution
- Dynamic system adaptation
- Automated tool generation
- Seamless action integration

---

## Configuration and Diagnostics

### System Diagnostics

#### `lot_diagnostic`
**Description**: Set LOT diagnostic level for debugging and troubleshooting.

**Parameters**:
- `diagnostic_value` (string): Diagnostic level or value

**Example Usage**:
```python
# Enable verbose debugging
result = await lot_diagnostic("verbose")

# Set specific diagnostic mode
result = await lot_diagnostic("network_trace")
```

**Use Cases**:
- System troubleshooting
- Performance analysis
- Network diagnostics
- Development debugging

---

## Example Use Cases

### 1. Smart Building Automation

**Scenario**: Automate lighting, HVAC, and security systems in an office building.

```python
# 1. Setup secure MQTT connection
await setup_mqtt_connection(
    broker="building.mqtt.local",
    port=8883,
    username="building_controller",
    password="secure_password",
    use_tls=True
)

# 2. Create occupancy-based lighting rule
rule = """
DEFINE RULE OccupancyLighting WITH PRIORITY 1 FOR TOPIC "building/+/occupancy"
    IF OCCUPANCY > 0 THEN
        ALLOW lighting_control
    ELSE
        DENY lighting_control
"""
await add_rule(rule)

# 3. Create energy-saving action
action = """
DEFINE ACTION EnergyNightMode
ON EVERY 1 HOUR
DO
    IF GET TOPIC "building/schedule/working_hours" == "false" THEN
        PUBLISH TOPIC "building/hvac/setpoint" WITH "18"
        PUBLISH TOPIC "building/lighting/zones/+/brightness" WITH "10"
"""
await add_action(action)

# 4. Monitor system health
health = await comprehensive_health_check()
```

### 2. Industrial IoT Monitoring

**Scenario**: Monitor industrial equipment and implement predictive maintenance.

```python
# 1. Subscribe to equipment sensors
await mqtt_subscribe("factory/equipment/+/temperature", qos=1)
await mqtt_subscribe("factory/equipment/+/vibration", qos=1)
await mqtt_subscribe("factory/equipment/+/status", qos=2)

# 2. Create predictive maintenance model
model = """
DEFINE MODEL PredictiveMaintenance WITH TOPIC "factory/maintenance/alerts"
    ADD "temperature" WITH TOPIC "factory/equipment/+/temperature" AS TRIGGER
    ADD "vibration" WITH TOPIC "factory/equipment/+/vibration"
    ADD "temp_threshold" WITH 85
    ADD "vib_threshold" WITH 2.5
    ADD "maintenance_needed" WITH (temperature > temp_threshold OR vibration > vib_threshold)
"""
await add_model(model)

# 3. Create emergency shutdown action
emergency_action = """
DEFINE ACTION EmergencyShutdown
DO
    PUBLISH TOPIC "factory/equipment/+/command" WITH "emergency_stop"
    PUBLISH TOPIC "factory/alerts/emergency" WITH "EMERGENCY_SHUTDOWN_ACTIVATED"
DESCRIPTION "Emergency shutdown of all equipment"
"""
await add_action(emergency_action)

# 4. Monitor messages for anomalies
messages = await mqtt_read_messages(
    topic="factory/equipment/+/temperature",
    max_messages=50
)
```

### 3. Smart Home Integration

**Scenario**: Create an intelligent home automation system.

```python
# 1. Generate LOT code using AI
lot_code = await request_lot_code(
    query="Create a smart thermostat action that learns user preferences and adjusts temperature based on occupancy and time of day",
    context="Home automation system with presence sensors and weather data"
)

# 2. Subscribe to home sensors
await mqtt_subscribe("home/+/temperature", qos=1)
await mqtt_subscribe("home/+/humidity", qos=1)
await mqtt_subscribe("home/+/occupancy", qos=1)
await mqtt_subscribe("home/weather/forecast", qos=0)

# 3. Create comfort optimization model
comfort_model = """
DEFINE MODEL ComfortOptimization WITH TOPIC "home/thermostat/target"
    ADD "indoor_temp" WITH TOPIC "home/living_room/temperature" AS TRIGGER
    ADD "outdoor_temp" WITH TOPIC "home/weather/temperature"
    ADD "occupancy" WITH TOPIC "home/+/occupancy"
    ADD "time_of_day" WITH GET_TIME_HOUR()
    ADD "comfort_temp" WITH (
        IF occupancy > 0 AND time_of_day BETWEEN 6 AND 22 THEN 22
        ELSE 18
    )
"""
await add_model(comfort_model)

# 4. Monitor and control home systems
await mqtt_publish("home/thermostat/mode", "auto", qos=1)
status = await get_connection_status()
```

### 4. Agricultural IoT System

**Scenario**: Monitor and automate greenhouse operations.

```python
# 1. Monitor greenhouse conditions
await mqtt_subscribe("greenhouse/+/soil_moisture", qos=1)
await mqtt_subscribe("greenhouse/+/air_temperature", qos=1)
await mqtt_subscribe("greenhouse/+/humidity", qos=1)
await mqtt_subscribe("greenhouse/+/light_level", qos=1)

# 2. Create irrigation automation
irrigation_action = """
DEFINE ACTION AutoIrrigation
ON EVERY 30 MINUTES
DO
    IF GET TOPIC "greenhouse/zone1/soil_moisture" < 30 THEN
        PUBLISH TOPIC "greenhouse/zone1/irrigation/valve" WITH "open"
        PUBLISH TOPIC "greenhouse/zone1/irrigation/duration" WITH "600"
    IF GET TOPIC "greenhouse/zone2/soil_moisture" < 30 THEN
        PUBLISH TOPIC "greenhouse/zone2/irrigation/valve" WITH "open"
        PUBLISH TOPIC "greenhouse/zone2/irrigation/duration" WITH "600"
"""
await add_action(irrigation_action)

# 3. Create climate control model
climate_model = """
DEFINE MODEL GreenhouseClimate WITH TOPIC "greenhouse/climate/control"
    ADD "temperature" WITH TOPIC "greenhouse/+/air_temperature" AS TRIGGER
    ADD "humidity" WITH TOPIC "greenhouse/+/humidity"
    ADD "target_temp" WITH 24
    ADD "target_humidity" WITH 65
    ADD "fan_speed" WITH (
        IF temperature > target_temp THEN
            MIN(100, (temperature - target_temp) * 20)
        ELSE 0
    )
    ADD "humidifier" WITH (humidity < target_humidity)
"""
await add_model(climate_model)

# 4. Get system insights
actions = await list_discovered_actions()
health = await comprehensive_health_check()
```

### 5. Fleet Management System

**Scenario**: Monitor and manage a fleet of vehicles or mobile equipment.

```python
# 1. Connect to fleet management broker
await setup_mqtt_connection(
    broker="fleet.company.com",
    port=8883,
    username="fleet_manager",
    use_tls=True
)

# 2. Subscribe to vehicle telemetry
await mqtt_subscribe("fleet/vehicles/+/location", qos=1)
await mqtt_subscribe("fleet/vehicles/+/fuel_level", qos=1)
await mqtt_subscribe("fleet/vehicles/+/engine_status", qos=2)
await mqtt_subscribe("fleet/vehicles/+/maintenance", qos=1)

# 3. Create fuel monitoring model
fuel_model = """
DEFINE MODEL FuelMonitoring WITH TOPIC "fleet/alerts/fuel"
    ADD "fuel_level" WITH TOPIC "fleet/vehicles/+/fuel_level" AS TRIGGER
    ADD "vehicle_id" WITH EXTRACT_FROM_TOPIC(TOPIC, 2)
    ADD "low_fuel_threshold" WITH 15
    ADD "critical_fuel_threshold" WITH 5
    ADD "alert_level" WITH (
        IF fuel_level <= critical_fuel_threshold THEN "CRITICAL"
        ELSE IF fuel_level <= low_fuel_threshold THEN "WARNING"
        ELSE "OK"
    )
"""
await add_model(fuel_model)

# 4. Create maintenance scheduling action
maintenance_action = """
DEFINE ACTION ScheduleMaintenance
ON TOPIC "fleet/vehicles/+/mileage"
DO
    IF GET TOPIC VALUE > 10000 THEN
        PUBLISH TOPIC "fleet/maintenance/schedule" WITH CONCATENATE(
            '{"vehicle_id":"', EXTRACT_FROM_TOPIC(TOPIC, 2), 
            '","type":"routine","priority":"normal"}'
        )
"""
await add_action(maintenance_action)

# 5. Monitor fleet status
messages = await mqtt_read_messages(
    topic="fleet/vehicles/+/fuel_level",
    max_messages=20
)
```

---

## Best Practices

### Security Considerations
- Always use TLS for production deployments (`use_tls=True`)
- Implement proper authentication with username/password
- Use QoS level 1 or 2 for critical messages
- Regularly monitor system health with `comprehensive_health_check`
- Review discovered actions with `list_discovered_actions`

### Performance Optimization
- Use appropriate QoS levels (0 for non-critical data, 1-2 for important messages)
- Implement message retention sparingly (`retain=True`) for state data only
- Monitor message buffer sizes with `mqtt_read_messages`
- Use wildcard subscriptions efficiently
- Regular health checks to maintain optimal performance

### Error Handling
- Always check connection status before critical operations
- Use `check_broker_health` for automated recovery
- Monitor logs for security sanitization warnings
- Implement retry logic for critical operations
- Use `get_connection_status` for troubleshooting guidance

### Development Workflow
1. Start with `setup_mqtt_connection` or `mqtt_connect`
2. Use `request_lot_code` for AI-assisted development
3. Test actions with `run_action` before automation
4. Monitor system health with `comprehensive_health_check`
5. Use `list_discovered_actions` to track available functionality

This comprehensive toolkit enables sophisticated IoT automation, industrial monitoring, smart building management, and AI-assisted system development through the Coreflux platform.
