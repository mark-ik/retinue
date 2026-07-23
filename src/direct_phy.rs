//! Host codec for Tulle's direct-PHY USB protocol.
//!
//! The firmware carries complete, protocol-owned radio packets. It does not
//! interpret Reticulum, MeshCore, or Meshtastic-compatible bytes.

use crate::link::Received;
use tulle_phy_profile::{CONFIG_COMMAND_LEN, PhyProfile, ProfileError, encode_config_command};

pub const MAX_FRAME_LEN: usize = 255;
pub use tulle_phy_profile::{CMD_CONFIG, CMD_TX, EVENT_CONFIG, EVENT_RX, EVENT_TX};

/// One event emitted by direct-PHY firmware.
#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    Received(Received),
    Transmitted { result: u8, frame_len: usize },
    Configured { result: u8 },
}

/// Encode a complete runtime radio-profile command.
pub fn encode_configure(profile: PhyProfile) -> Result<[u8; CONFIG_COMMAND_LEN], ProfileError> {
    encode_config_command(profile)
}

/// Encode one complete radio frame for transmission.
pub fn encode_transmit(frame: &[u8]) -> Result<Vec<u8>, EncodeError> {
    if frame.len() > MAX_FRAME_LEN {
        return Err(EncodeError::TooLong {
            actual: frame.len(),
        });
    }
    let mut out = Vec::with_capacity(frame.len() + 3);
    out.push(CMD_TX);
    out.extend_from_slice(&(frame.len() as u16).to_le_bytes());
    out.extend_from_slice(frame);
    Ok(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    TooLong { actual: usize },
}

impl core::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLong { actual } => {
                write!(
                    f,
                    "direct-PHY frame exceeds {MAX_FRAME_LEN} bytes: {actual}"
                )
            }
        }
    }
}

impl core::error::Error for EncodeError {}

/// Streaming decoder for firmware events.
///
/// Firmware status lines are unframed ASCII. The decoder discards them while
/// looking for the high-bit binary event markers, and handles USB packet splits
/// at every byte.
#[derive(Default)]
pub struct Decoder {
    buffer: Vec<u8>,
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, bytes: &[u8], out: &mut Vec<Event>) {
        self.buffer.extend_from_slice(bytes);
        loop {
            let Some(start) = self
                .buffer
                .iter()
                .position(|byte| matches!(*byte, EVENT_RX | EVENT_TX | EVENT_CONFIG))
            else {
                self.buffer.clear();
                return;
            };
            if start > 0 {
                self.buffer.drain(..start);
            }

            match self.buffer[0] {
                EVENT_RX => {
                    if self.buffer.len() < 7 {
                        return;
                    }
                    let frame_len =
                        usize::from(u16::from_le_bytes([self.buffer[1], self.buffer[2]]));
                    if frame_len > MAX_FRAME_LEN {
                        self.buffer.drain(..1);
                        continue;
                    }
                    let event_len = 7 + frame_len;
                    if self.buffer.len() < event_len {
                        return;
                    }
                    let rssi_dbm = i16::from_le_bytes([self.buffer[3], self.buffer[4]]);
                    let snr_db = i16::from_le_bytes([self.buffer[5], self.buffer[6]]) as f32;
                    out.push(Event::Received(Received {
                        frame: self.buffer[7..event_len].to_vec(),
                        rssi_dbm,
                        snr_db,
                    }));
                    self.buffer.drain(..event_len);
                }
                EVENT_TX => {
                    if self.buffer.len() < 4 {
                        return;
                    }
                    out.push(Event::Transmitted {
                        result: self.buffer[1],
                        frame_len: usize::from(u16::from_le_bytes([
                            self.buffer[2],
                            self.buffer[3],
                        ])),
                    });
                    self.buffer.drain(..4);
                }
                EVENT_CONFIG => {
                    if self.buffer.len() < 2 {
                        return;
                    }
                    out.push(Event::Configured {
                        result: self.buffer[1],
                    });
                    self.buffer.drain(..2);
                }
                _ => unreachable!("event marker selected above"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transmit_command_has_little_endian_length() {
        assert_eq!(encode_transmit(b"radio").unwrap(), b"\x01\x05\x00radio");
    }

    #[test]
    fn decoder_skips_status_and_reassembles_usb_chunks() {
        let mut wire = b"tulle/heltec-v4 phy online\r\n".to_vec();
        wire.extend_from_slice(&[EVENT_RX, 3, 0, 0xd8, 0xff, 9, 0, 1, 2, 3]);
        wire.extend_from_slice(&[EVENT_TX, 0, 3, 0]);
        wire.extend_from_slice(&[EVENT_CONFIG, 0]);

        let mut decoder = Decoder::new();
        let mut events = Vec::new();
        for chunk in wire.chunks(2) {
            decoder.push(chunk, &mut events);
        }
        assert_eq!(
            events,
            [
                Event::Received(Received {
                    frame: vec![1, 2, 3],
                    rssi_dbm: -40,
                    snr_db: 9.0,
                }),
                Event::Transmitted {
                    result: 0,
                    frame_len: 3,
                },
                Event::Configured { result: 0 },
            ]
        );
    }

    #[test]
    fn decoder_resynchronizes_after_an_impossible_length() {
        let mut decoder = Decoder::new();
        let mut events = Vec::new();
        decoder.push(&[EVENT_RX, 0xff, 0xff, EVENT_TX, 0, 4, 0], &mut events);
        assert_eq!(
            events,
            [Event::Transmitted {
                result: 0,
                frame_len: 4,
            }]
        );
    }
}
