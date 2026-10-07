//! Build-time configuration and credentials.
//!
//! Values are injected at compile time via environment variables.

/// Wi-Fi Network SSID (mandatory)
pub const WIFI_SSID: &str = env!("WIFI_SSID");

/// Wi-Fi Password (mandatory)
pub const WIFI_PASS: &str = env!("WIFI_PASS");

/// MQTT Username (mandatory)
pub const MQTT_USER: &str = env!("MQTT_USER");

/// MQTT Password (mandatory)
pub const MQTT_PASSWORD: &str = env!("MQTT_PASSWORD");

/// MQTT Broker Hostname or IP (optional, default: "10.7.1.106")
pub const MQTT_HOST: &str = match option_env!("MQTT_HOST") {
    Some(val) => val,
    None => "10.7.1.106",
};

/// MQTT Broker Port (optional, default: "1883")
pub const MQTT_PORT: &str = match option_env!("MQTT_PORT") {
    Some(val) => val,
    None => "1883",
};

/// Unique Device Identifier (optional, default: "keygate1")
pub const DEVICE_ID: &str = match option_env!("DEVICE_ID") {
    Some(val) => val,
    None => "keygate1",
};

/// Relay Trigger Logic Polarity (optional, default: "true")
pub const RELAY_ACTIVE_LOW: &str = match option_env!("RELAY_ACTIVE_LOW") {
    Some(val) => val,
    None => "true",
};
