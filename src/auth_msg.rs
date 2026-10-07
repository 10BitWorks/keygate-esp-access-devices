//! Outbound authentication request JSON serializer for the KeyGate reader firmware.
//!
//! Feeds the MQTT publication loop (todos 14/15) by building the JSON payload published
//! on `access/<device_id>/auth`.
//!
//! Conforms strictly to the access-control-verifier schema defined in:
//! `access-control-verifier/src/api.rs`:
//! ```text
//! #[derive(Debug, Deserialize)]
//! #[serde(deny_unknown_fields)]
//! struct AuthRequest {
//!     reader: String,
//!     uid: String,
//!     counter: u64,
//!     cmac: String,
//! }
//! ```

use core::fmt::Write;
use heapless::String;
use crate::ntag424::SunParams;

/// Errors that can occur when serializing an authentication request message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// Reader identifier is empty.
    EmptyReader,
    /// Reader identifier contains invalid characters (e.g. control characters or unescapable inputs).
    InvalidReader,
    /// The formatted JSON string exceeded the capacity of the buffer.
    BufferOverflow,
}

impl core::fmt::Display for AuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AuthError::EmptyReader => write!(f, "reader ID cannot be empty"),
            AuthError::InvalidReader => write!(f, "invalid characters in reader ID"),
            AuthError::BufferOverflow => write!(f, "auth JSON exceeded buffer capacity"),
        }
    }
}

/// Helper to write a byte slice as lowercase hexadecimal characters.
fn write_hex_lower<W: Write>(w: &mut W, bytes: &[u8]) -> Result<(), core::fmt::Error> {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    for &b in bytes {
        let hi = HEX_CHARS[(b >> 4) as usize] as char;
        let lo = HEX_CHARS[(b & 0x0f) as usize] as char;
        w.write_char(hi)?;
        w.write_char(lo)?;
    }
    Ok(())
}

/// Validates and writes a JSON-escaped string slice to the formatter.
///
/// Rejects ASCII control characters (< 0x20) as invalid for a reader identifier.
/// Escapes `"` and `\`.
fn write_escaped_str<W: Write>(w: &mut W, s: &str) -> Result<(), AuthError> {
    if s.is_empty() {
        return Err(AuthError::EmptyReader);
    }
    for ch in s.chars() {
        if (ch as u32) < 0x20 {
            return Err(AuthError::InvalidReader);
        }
        match ch {
            '"' => {
                w.write_str("\\\"").map_err(|_| AuthError::BufferOverflow)?;
            }
            '\\' => {
                w.write_str("\\\\").map_err(|_| AuthError::BufferOverflow)?;
            }
            c => {
                w.write_char(c).map_err(|_| AuthError::BufferOverflow)?;
            }
        }
    }
    Ok(())
}

/// Serializes an authentication request to JSON into the provided `heapless::String<256>`.
///
/// Output format:
/// `{"reader":"<reader>","uid":"<uid>","counter":<counter>,"cmac":"<cmac>"}`
///
/// # Arguments
/// - `reader`: Device/reader ID (e.g., `"keygate1"`). Must not be empty. Escapes quotes/backslashes.
/// - `sun`: Extracted SUN parameters containing `uid` ([u8; 7]), `counter` (u32), and `cmac` ([u8; 16]).
/// - `out`: Mutable reference to `heapless::String<256>` destination buffer.
///
/// # Errors
/// Returns `AuthError::EmptyReader` if `reader` is empty.
/// Returns `AuthError::InvalidReader` if `reader` contains control characters.
/// Returns `AuthError::BufferOverflow` if the generated JSON exceeds 256 bytes.
pub fn build_auth_json(
    reader: &str,
    sun: &SunParams,
    out: &mut String<256>,
) -> Result<(), AuthError> {
    out.clear();

    out.push_str("{\"reader\":\"")
        .map_err(|_| AuthError::BufferOverflow)?;

    write_escaped_str(out, reader)?;

    out.push_str("\",\"uid\":\"")
        .map_err(|_| AuthError::BufferOverflow)?;

    write_hex_lower(out, &sun.uid)
        .map_err(|_| AuthError::BufferOverflow)?;

    out.push_str("\",\"counter\":")
        .map_err(|_| AuthError::BufferOverflow)?;

    write!(out, "{}", sun.counter)
        .map_err(|_| AuthError::BufferOverflow)?;

    out.push_str(",\"cmac\":\"")
        .map_err(|_| AuthError::BufferOverflow)?;

    write_hex_lower(out, &sun.cmac)
        .map_err(|_| AuthError::BufferOverflow)?;

    out.push_str("\"}")
        .map_err(|_| AuthError::BufferOverflow)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_auth_json_canonical() {
        let sun = SunParams {
            uid: [0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            counter: 8,
            cmac: [
                0x50, 0x5C, 0x41, 0xA3, 0x35, 0xA9, 0xB7, 0xDE, 0xF2, 0x9D, 0x59, 0x59, 0x93,
                0x6F, 0xE7, 0xFE,
            ],
        };
        let mut buf = String::<256>::new();
        build_auth_json("keygate1", &sun, &mut buf).expect("serialization failed");

        let expected = "{\"reader\":\"keygate1\",\"uid\":\"04112233445566\",\"counter\":8,\"cmac\":\"505c41a335a9b7def29d5959936fe7fe\"}";
        assert_eq!(buf.as_str(), expected);
    }

    #[test]
    fn test_empty_reader_rejected() {
        let sun = SunParams {
            uid: [0x04; 7],
            counter: 1,
            cmac: [0xAA; 16],
        };
        let mut buf = String::<256>::new();
        let res = build_auth_json("", &sun, &mut buf);
        assert_eq!(res, Err(AuthError::EmptyReader));
    }

    #[test]
    fn test_control_char_reader_rejected() {
        let sun = SunParams {
            uid: [0x04; 7],
            counter: 1,
            cmac: [0xAA; 16],
        };
        let mut buf = String::<256>::new();
        let res = build_auth_json("reader\n1", &sun, &mut buf);
        assert_eq!(res, Err(AuthError::InvalidReader));
    }

    #[test]
    fn test_escaped_reader() {
        let sun = SunParams {
            uid: [0x04; 7],
            counter: 1,
            cmac: [0xAA; 16],
        };
        let mut buf = String::<256>::new();
        build_auth_json("key\"gate\\1", &sun, &mut buf).expect("escaped serialization failed");
        assert!(buf.contains("\"reader\":\"key\\\"gate\\\\1\""));
    }

    #[test]
    fn test_buffer_overflow_typed_error() {
        let sun = SunParams {
            uid: [0x04; 7],
            counter: u32::MAX,
            cmac: [0xAA; 16],
        };
        // 250 characters long reader string will overflow 256 byte buffer
        let long_reader = "a".repeat(250);
        let mut buf = String::<256>::new();
        let res = build_auth_json(&long_reader, &sun, &mut buf);
        assert_eq!(res, Err(AuthError::BufferOverflow));
    }
}
