//! Application envelope reconstructed from public descriptions and radio-bench
//! observation.
//!
//! The public `portnum` concept selects an application carried by a packet.
//! Black-box captures show that field 1 carries that number and field 2 carries
//! the application's bytes. Extra numbered fields are accepted but remain
//! uninterpreted until a bench experiment gives them a useful meaning.

use crate::protobuf::{Reader, Value, write_tag, write_varint};

/// Port observed carrying a UTF-8 text message.
pub const TEXT_PORT: u32 = 1;

const PORT_FIELD: u32 = 1;
const PAYLOAD_FIELD: u32 = 2;

/// The application selector and its payload bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplicationEnvelope<'a> {
    pub port: u32,
    pub payload: &'a [u8],
}

impl<'a> ApplicationEnvelope<'a> {
    pub fn new(port: u32, payload: &'a [u8]) -> Self {
        Self { port, payload }
    }

    /// Decode the two observed fields while tolerating additional, still
    /// unnamed protobuf fields.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, ApplicationError> {
        let mut reader = Reader::new(bytes);
        let mut port = None;
        let mut payload = None;

        for field in reader.by_ref() {
            match (field.number, field.value) {
                (PORT_FIELD, Value::Varint(value)) => {
                    if port.is_some() {
                        return Err(ApplicationError::DuplicateField(PORT_FIELD));
                    }
                    port = Some(
                        u32::try_from(value)
                            .map_err(|_| ApplicationError::PortOutOfRange(value))?,
                    );
                }
                (PORT_FIELD, _) => return Err(ApplicationError::WrongWireType(PORT_FIELD)),
                (PAYLOAD_FIELD, Value::Len(value)) => {
                    if payload.is_some() {
                        return Err(ApplicationError::DuplicateField(PAYLOAD_FIELD));
                    }
                    payload = Some(value);
                }
                (PAYLOAD_FIELD, _) => {
                    return Err(ApplicationError::WrongWireType(PAYLOAD_FIELD));
                }
                _ => {}
            }
        }

        if !reader.is_complete() {
            return Err(ApplicationError::MalformedMessage);
        }

        Ok(Self {
            port: port.ok_or(ApplicationError::MissingField(PORT_FIELD))?,
            payload: payload.ok_or(ApplicationError::MissingField(PAYLOAD_FIELD))?,
        })
    }

    /// Encode the independently reconstructed field pair. Still-unnamed fields
    /// seen in some captures are deliberately omitted.
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.payload.len() + 8);
        write_tag(PORT_FIELD, 0, &mut out);
        write_varint(u64::from(self.port), &mut out);
        write_tag(PAYLOAD_FIELD, 2, &mut out);
        write_varint(self.payload.len() as u64, &mut out);
        out.extend_from_slice(self.payload);
        out
    }

    /// Interpret the payload as text only for the port directly observed to
    /// carry UTF-8 text.
    pub fn text(self) -> Result<&'a str, ApplicationError> {
        if self.port != TEXT_PORT {
            return Err(ApplicationError::NotTextPort(self.port));
        }
        std::str::from_utf8(self.payload).map_err(|_| ApplicationError::InvalidUtf8)
    }
}

/// Build the application bytes for a text message.
pub fn encode_text(text: &str) -> Vec<u8> {
    ApplicationEnvelope::new(TEXT_PORT, text.as_bytes()).encode()
}

/// Decode a text message from application bytes.
pub fn decode_text(bytes: &[u8]) -> Result<&str, ApplicationError> {
    ApplicationEnvelope::decode(bytes)?.text()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationError {
    MalformedMessage,
    MissingField(u32),
    DuplicateField(u32),
    WrongWireType(u32),
    PortOutOfRange(u64),
    NotTextPort(u32),
    InvalidUtf8,
}

impl std::fmt::Display for ApplicationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedMessage => write!(f, "malformed application message"),
            Self::MissingField(field) => write!(f, "missing application field {field}"),
            Self::DuplicateField(field) => write!(f, "duplicate application field {field}"),
            Self::WrongWireType(field) => {
                write!(f, "wrong wire type for application field {field}")
            }
            Self::PortOutOfRange(value) => write!(f, "application port is out of range: {value}"),
            Self::NotTextPort(port) => write!(f, "application port {port} is not text"),
            Self::InvalidUtf8 => write!(f, "text payload is not valid UTF-8"),
        }
    }
}

impl std::error::Error for ApplicationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_direct_phy_text_capture() {
        let bytes = b"\x08\x01\x12\x1btulle direct phy probe 0722\x48\x00";
        let envelope = ApplicationEnvelope::decode(bytes).unwrap();
        assert_eq!(envelope.port, TEXT_PORT);
        assert_eq!(envelope.text().unwrap(), "tulle direct phy probe 0722");
    }

    #[test]
    fn encodes_only_the_reconstructed_fields() {
        assert_eq!(encode_text("bench probe"), b"\x08\x01\x12\x0bbench probe");
    }

    #[test]
    fn application_envelope_round_trips() {
        let encoded = ApplicationEnvelope::new(67, &[1, 2, 3]).encode();
        assert_eq!(
            ApplicationEnvelope::decode(&encoded).unwrap(),
            ApplicationEnvelope::new(67, &[1, 2, 3])
        );
    }

    #[test]
    fn text_requires_the_observed_port_and_utf8() {
        assert_eq!(
            ApplicationEnvelope::new(67, b"not text").text(),
            Err(ApplicationError::NotTextPort(67))
        );
        assert_eq!(
            ApplicationEnvelope::new(TEXT_PORT, &[0xff]).text(),
            Err(ApplicationError::InvalidUtf8)
        );
    }

    #[test]
    fn malformed_or_ambiguous_envelopes_are_rejected() {
        assert_eq!(
            ApplicationEnvelope::decode(b"\x08\x01"),
            Err(ApplicationError::MissingField(PAYLOAD_FIELD))
        );
        assert_eq!(
            ApplicationEnvelope::decode(b"\x08\x01\x08\x02\x12\x00"),
            Err(ApplicationError::DuplicateField(PORT_FIELD))
        );
        assert_eq!(
            ApplicationEnvelope::decode(b"\x08\x01\x12\x08short"),
            Err(ApplicationError::MalformedMessage)
        );
    }
}
