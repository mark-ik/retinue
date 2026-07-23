//! Small protocol-facing composition of transport and application layers.

use crate::application::{self, ApplicationEnvelope, ApplicationError, TEXT_PORT};
use crate::transport::{ChannelKey, Header, Packet, TransportError};

/// One configured encrypted channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Channel {
    pub hash: u8,
    pub key: ChannelKey,
}

/// A text message received from one radio packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedText {
    pub header: Header,
    pub text: String,
}

impl Channel {
    /// Construct, encrypt, and encode one text radio packet.
    ///
    /// The caller owns source identity and packet-id allocation. Use
    /// [`crate::packet_id::PacketIdState`] when the pair must survive restarts.
    /// `channel_hash` is taken from this channel so the header and cipher
    /// configuration cannot drift apart.
    pub fn seal_text(&self, mut header: Header, text: &str) -> Result<Vec<u8>, NodeError> {
        header.channel_hash = self.hash;
        let mut packet = Packet {
            header,
            payload: application::encode_text(text),
        };
        packet.apply_channel_cipher(&self.key);
        packet.encode().map_err(NodeError::Transport)
    }

    /// Decode a text packet for this channel.
    ///
    /// `Ok(None)` means the channel hash or application port does not match.
    /// Channel packets carry no authenticated integrity check, so a malformed
    /// decrypted envelope remains an error rather than proof of a hostile peer.
    pub fn open_text(&self, frame: &[u8]) -> Result<Option<ReceivedText>, NodeError> {
        let mut packet = Packet::decode(frame).map_err(NodeError::Transport)?;
        if packet.header.channel_hash != self.hash {
            return Ok(None);
        }
        packet.apply_channel_cipher(&self.key);
        let envelope =
            ApplicationEnvelope::decode(&packet.payload).map_err(NodeError::Application)?;
        if envelope.port != TEXT_PORT {
            return Ok(None);
        }
        let text = envelope.text().map_err(NodeError::Application)?.to_owned();
        Ok(Some(ReceivedText {
            header: packet.header,
            text,
        }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeError {
    Transport(TransportError),
    Application(ApplicationError),
}

impl core::fmt::Display for NodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(error) => write!(f, "transport: {error}"),
            Self::Application(error) => write!(f, "application: {error}"),
        }
    }
}

impl std::error::Error for NodeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::BROADCAST_DESTINATION;

    const PUBLIC_LONGFAST: Channel = Channel {
        hash: 8,
        key: ChannelKey::Aes128([
            0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59, 0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e,
            0x69, 0x01,
        ]),
    };

    fn header() -> Header {
        Header {
            destination: BROADCAST_DESTINATION,
            source: 0xf66a_fb28,
            packet_id: 0xb726_0722,
            hop_limit: 3,
            want_ack: false,
            via_mqtt: false,
            hop_start: 3,
            channel_hash: 0,
            next_hop: 0,
            relay_node: 0x28,
        }
    }

    #[test]
    fn channel_seals_the_live_direct_phy_fixture() {
        let frame = PUBLIC_LONGFAST
            .seal_text(header(), "sennet semantic api 0722")
            .unwrap();
        assert_eq!(
            frame,
            [
                0xff, 0xff, 0xff, 0xff, 0x28, 0xfb, 0x6a, 0xf6, 0x22, 0x07, 0x26, 0xb7, 0x63, 0x08,
                0x00, 0x28, 0x4b, 0x7d, 0x51, 0xa4, 0xc9, 0xc7, 0x21, 0x3e, 0xa4, 0x48, 0xe7, 0x5c,
                0x57, 0x82, 0x1c, 0x0e, 0x59, 0xda, 0xb7, 0x32, 0x02, 0xad, 0x10, 0x7f, 0x40, 0x78,
                0x55, 0xd7,
            ]
        );
        let opened = PUBLIC_LONGFAST.open_text(&frame).unwrap().unwrap();
        let mut expected_header = header();
        expected_header.channel_hash = PUBLIC_LONGFAST.hash;
        assert_eq!(opened.header, expected_header);
        assert_eq!(opened.text, "sennet semantic api 0722");
    }

    #[test]
    fn other_channels_are_ignored_before_decryption() {
        let mut frame = PUBLIC_LONGFAST.seal_text(header(), "hello").unwrap();
        frame[13] = 9;
        assert_eq!(PUBLIC_LONGFAST.open_text(&frame).unwrap(), None);
    }
}
