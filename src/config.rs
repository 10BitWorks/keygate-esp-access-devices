//! Build-time configuration and credentials.
//!
//! Values are injected at compile time via environment variables.

/// Wi-Fi Network SSID (mandatory)
pub const WIFI_SSID: &str = env!("WIFI_SSID");

/// Wi-Fi Password (mandatory)
pub const WIFI_PASS: &str = env!("WIFI_PASS");

/// Unique Device Identifier (optional, default: "keygate1")
pub const DEVICE_ID: &str = match option_env!("DEVICE_ID") {
    Some(val) => val,
    None => "keygate1",
};

/// MQTT Username (optional, defaults to DEVICE_ID so client ID and username are identical)
pub const MQTT_USER: &str = match option_env!("MQTT_USER") {
    Some(val) => val,
    None => DEVICE_ID,
};

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

/// Relay Trigger Logic Polarity (optional, default: "true")
pub const RELAY_ACTIVE_LOW: &str = match option_env!("RELAY_ACTIVE_LOW") {
    Some(val) => val,
    None => "true",
};

/// How long the door strike stays released on a grant — LOCAL door policy.
///
/// The verifier's contract is accept/deny only; how this node drives its own
/// relay is nobody else's business. 3 s is the minimum a person needs to
/// hear the chirp, reach the handle, and pull the door open.
pub const RELAY_HOLD_MS: u32 = 3000;

/// SUN provisioning URL template (T4).
///
/// The three empty placeholders (`uid=`, `c=`, `cmac=`) are where the NTAG 424
/// SDM mirrors land; `provision::provision_tag` computes the mirror file
/// offsets from this template. MUST start with `https://` (NDEF URI prefix
/// code 0x04) and contain `uid=`, `c=` and `cmac=` in that order.
pub const PROVISION_URL_TEMPLATE: &str = "https://10bitworks.org/k?uid=&c=&cmac=";

/// Provisioning window (T7): how long an armed job stays tap-able before it
/// silently lapses (the server-side TTL lapses on its own).
pub const PROVISION_WINDOW_SECS: u64 = 90;

/// Claim wait (T7): how long a wildcard claim waits for the verifier's keyed
/// re-publish before the job fails explicitly.
pub const CLAIM_WAIT_SECS: u64 = 15;
