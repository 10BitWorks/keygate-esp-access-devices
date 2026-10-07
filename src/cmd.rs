//! Inbound command deserializer for door access commands.
//!
//! Subscribed topic: `access/<device_id>/cmd`
//! Wire format (from access-control-verifier `src/mqtt.rs`):
//! `{"grant":bool,"reason":&str,"pulse_ms":u32}`

use serde::Deserialize;

/// Inbound door command payload published by the verifier.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CmdMessage<'a> {
    pub grant: bool,
    pub pulse_ms: u32,
    pub reason: &'a str,
}

/// Parse a raw JSON string into a `CmdMessage`.
///
/// Operates in `no_std` without heap allocation by borrowing string slices
/// directly from the input JSON buffer.
pub fn parse_cmd<'a>(json: &'a str) -> Result<CmdMessage<'a>, serde_json_core::de::Error> {
    let (msg, _bytes) = serde_json_core::from_str::<CmdMessage<'a>>(json)?;
    Ok(msg)
}

/// Parse a raw UTF-8 byte slice into a `CmdMessage`.
///
/// Convenience helper for MQTT payload buffers without requiring an intermediate
/// manual UTF-8 conversion call.
pub fn parse_cmd_slice<'a>(slice: &'a [u8]) -> Result<CmdMessage<'a>, serde_json_core::de::Error> {
    let (msg, _bytes) = serde_json_core::from_slice::<CmdMessage<'a>>(slice)?;
    Ok(msg)
}
