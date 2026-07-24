//! Caller-persisted source and packet-ID allocation.
//!
//! A transport nonce is identified by `(source, packet_id)`. Reusing that pair
//! with the same channel key reuses the AES-CTR keystream, so allocation state
//! must survive process and device restarts. This module performs no random
//! generation and no filesystem I/O: the caller chooses a stable source,
//! persists [`PacketIdState::encode`] after each reservation, and transmits only
//! after that persistence succeeds.

/// Bytes in the stable packet-ID state record.
pub const PACKET_ID_STATE_LEN: usize = 16;
const MAGIC: [u8; 4] = *b"SNID";
const VERSION: u8 = 1;

/// One nonce identity reserved for a transport packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PacketIdentity {
    pub source: u32,
    pub packet_id: u32,
}

/// The next unused packet ID for one stable source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketIdState {
    source: u32,
    next_packet_id: u32,
}

impl PacketIdState {
    /// Start or restore an allocator. The caller owns selection and persistence
    /// of both values.
    pub const fn new(source: u32, next_packet_id: u32) -> Self {
        Self {
            source,
            next_packet_id,
        }
    }

    pub const fn source(self) -> u32 {
        self.source
    }

    pub const fn next_packet_id(self) -> u32 {
        self.next_packet_id
    }

    /// Reserve the current ID and advance the state without wrapping.
    ///
    /// Persist the newly advanced state before transmitting a packet with the
    /// returned identity. `u32::MAX` is retained as the exhausted sentinel and
    /// is never emitted.
    pub fn reserve(&mut self) -> Result<PacketIdentity, PacketIdError> {
        let packet_id = self.next_packet_id;
        let Some(next_packet_id) = packet_id.checked_add(1) else {
            return Err(PacketIdError::Exhausted);
        };
        self.next_packet_id = next_packet_id;
        Ok(PacketIdentity {
            source: self.source,
            packet_id,
        })
    }

    /// Serialize the complete caller-owned state to a fixed, versioned record.
    pub const fn encode(self) -> [u8; PACKET_ID_STATE_LEN] {
        let mut bytes = [0; PACKET_ID_STATE_LEN];
        bytes[0] = MAGIC[0];
        bytes[1] = MAGIC[1];
        bytes[2] = MAGIC[2];
        bytes[3] = MAGIC[3];
        bytes[4] = VERSION;
        let source = self.source.to_le_bytes();
        bytes[8] = source[0];
        bytes[9] = source[1];
        bytes[10] = source[2];
        bytes[11] = source[3];
        let next = self.next_packet_id.to_le_bytes();
        bytes[12] = next[0];
        bytes[13] = next[1];
        bytes[14] = next[2];
        bytes[15] = next[3];
        bytes
    }

    /// Restore a state record produced by [`Self::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, PacketIdError> {
        if bytes.len() != PACKET_ID_STATE_LEN {
            return Err(PacketIdError::Length(bytes.len()));
        }
        if bytes[..4] != MAGIC {
            return Err(PacketIdError::Magic);
        }
        if bytes[4] != VERSION {
            return Err(PacketIdError::Version(bytes[4]));
        }
        if bytes[5..8] != [0, 0, 0] {
            return Err(PacketIdError::Reserved);
        }
        Ok(Self {
            source: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            next_packet_id: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketIdError {
    Length(usize),
    Magic,
    Version(u8),
    Reserved,
    Exhausted,
}

impl core::fmt::Display for PacketIdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Length(actual) => {
                write!(
                    f,
                    "packet-ID state needs {PACKET_ID_STATE_LEN} bytes, got {actual}"
                )
            }
            Self::Magic => write!(f, "packet-ID state magic does not match"),
            Self::Version(version) => write!(f, "unsupported packet-ID state version {version}"),
            Self::Reserved => write!(f, "packet-ID state reserved bytes are not zero"),
            Self::Exhausted => write!(f, "packet-ID space is exhausted for this source"),
        }
    }
}

impl std::error::Error for PacketIdError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trip_persists_source_and_next_id() {
        let state = PacketIdState::new(0xf66a_fb28, 0xb726_0722);
        let encoded = state.encode();
        assert_eq!(&encoded[..5], b"SNID\x01");
        assert_eq!(PacketIdState::decode(&encoded), Ok(state));
    }

    #[test]
    fn restored_state_does_not_reuse_reserved_ids() {
        let mut state = PacketIdState::new(0x0102_0304, 41);
        assert_eq!(state.reserve().unwrap().packet_id, 41);

        let mut restored = PacketIdState::decode(&state.encode()).unwrap();
        assert_eq!(restored.reserve().unwrap().packet_id, 42);
        assert_eq!(restored.next_packet_id(), 43);
    }

    #[test]
    fn allocation_exhausts_instead_of_wrapping() {
        let mut state = PacketIdState::new(7, u32::MAX - 1);
        assert_eq!(state.reserve().unwrap().packet_id, u32::MAX - 1);
        assert_eq!(state.reserve(), Err(PacketIdError::Exhausted));
        assert_eq!(state.next_packet_id(), u32::MAX);
    }

    #[test]
    fn corrupt_or_unknown_records_are_rejected() {
        let mut encoded = PacketIdState::new(1, 2).encode();
        encoded[4] = 2;
        assert_eq!(
            PacketIdState::decode(&encoded),
            Err(PacketIdError::Version(2))
        );
        assert_eq!(
            PacketIdState::decode(&encoded[..15]),
            Err(PacketIdError::Length(15))
        );
    }
}
