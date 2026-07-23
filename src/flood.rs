//! Sans-I/O managed-flood relay decisions.

use std::collections::{HashSet, VecDeque};
use std::time::Duration;

use crate::transport::{Packet, TransportError};

/// Caller-selected window in which a relay transmission may be scheduled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayDelayWindow {
    pub earliest: Duration,
    pub latest: Duration,
}

impl RelayDelayWindow {
    pub fn new(earliest: Duration, latest: Duration) -> Result<Self, FloodConfigError> {
        if earliest > latest {
            return Err(FloodConfigError::DelayWindow);
        }
        Ok(Self { earliest, latest })
    }
}

/// Settings owned by one managed-flood relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagedFloodConfig {
    /// Only packets for this encrypted channel are considered.
    pub channel_hash: u8,
    /// Low byte written to the cleartext relay-node field.
    pub relay_node: u8,
    /// Number of `(source, packet_id)` identities retained for deduplication.
    pub seen_capacity: usize,
    /// Scheduling range returned with each relay decision.
    pub delay: RelayDelayWindow,
}

/// A bounded, channel-filtered managed-flood decision engine.
///
/// It owns no clock, RNG, radio, or sleeper. The caller chooses a concrete
/// transmission time inside the returned delay window.
pub struct ManagedFlood {
    config: ManagedFloodConfig,
    seen: HashSet<(u32, u32)>,
    order: VecDeque<(u32, u32)>,
}

impl ManagedFlood {
    pub fn new(config: ManagedFloodConfig) -> Result<Self, FloodConfigError> {
        if config.seen_capacity == 0 {
            return Err(FloodConfigError::SeenCapacity);
        }
        if config.delay.earliest > config.delay.latest {
            return Err(FloodConfigError::DelayWindow);
        }
        Ok(Self {
            config,
            seen: HashSet::with_capacity(config.seen_capacity),
            order: VecDeque::with_capacity(config.seen_capacity),
        })
    }

    pub const fn config(&self) -> ManagedFloodConfig {
        self.config
    }

    /// Inspect one complete radio frame and return the caller's relay action.
    pub fn consider(&mut self, frame: &[u8]) -> Result<FloodDecision, TransportError> {
        let mut packet = Packet::decode(frame)?;
        if packet.header.channel_hash != self.config.channel_hash {
            return Ok(FloodDecision::Ignore(FloodIgnore::Channel));
        }

        let identity = (packet.header.source, packet.header.packet_id);
        if self.seen.contains(&identity) {
            return Ok(FloodDecision::Ignore(FloodIgnore::Duplicate));
        }
        self.remember(identity);

        let Some(forwarded) = packet.header.forwarded_by(self.config.relay_node) else {
            return Ok(FloodDecision::Ignore(FloodIgnore::HopLimit));
        };
        packet.header = forwarded;
        Ok(FloodDecision::Relay {
            frame: packet.encode()?,
            delay: self.config.delay,
        })
    }

    fn remember(&mut self, identity: (u32, u32)) {
        if self.order.len() == self.config.seen_capacity
            && let Some(oldest) = self.order.pop_front()
        {
            self.seen.remove(&oldest);
        }
        self.order.push_back(identity);
        self.seen.insert(identity);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FloodDecision {
    Ignore(FloodIgnore),
    Relay {
        frame: Vec<u8>,
        delay: RelayDelayWindow,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FloodIgnore {
    Channel,
    Duplicate,
    HopLimit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FloodConfigError {
    SeenCapacity,
    DelayWindow,
}

impl core::fmt::Display for FloodConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SeenCapacity => write!(f, "managed-flood seen capacity must be non-zero"),
            Self::DelayWindow => write!(f, "managed-flood delay window is reversed"),
        }
    }
}

impl std::error::Error for FloodConfigError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{BROADCAST_DESTINATION, Header};

    fn frame(packet_id: u32, hop_limit: u8, channel_hash: u8) -> Vec<u8> {
        Packet {
            header: Header {
                destination: BROADCAST_DESTINATION,
                source: 0x0102_0304,
                packet_id,
                hop_limit,
                want_ack: false,
                via_mqtt: false,
                hop_start: 3,
                channel_hash,
                next_hop: 0,
                relay_node: 4,
            },
            payload: vec![1, 2, 3],
        }
        .encode()
        .unwrap()
    }

    fn relay(capacity: usize) -> ManagedFlood {
        ManagedFlood::new(ManagedFloodConfig {
            channel_hash: 8,
            relay_node: 0xaa,
            seen_capacity: capacity,
            delay: RelayDelayWindow::new(Duration::from_millis(20), Duration::from_millis(120))
                .unwrap(),
        })
        .unwrap()
    }

    #[test]
    fn filters_channels_before_mutating_the_seen_table() {
        let mut relay = relay(2);
        assert_eq!(
            relay.consider(&frame(1, 3, 9)).unwrap(),
            FloodDecision::Ignore(FloodIgnore::Channel)
        );
        assert!(matches!(
            relay.consider(&frame(1, 3, 8)).unwrap(),
            FloodDecision::Relay { .. }
        ));
    }

    #[test]
    fn duplicate_identity_is_source_and_packet_id() {
        let mut relay = relay(3);
        assert!(matches!(
            relay.consider(&frame(7, 3, 8)).unwrap(),
            FloodDecision::Relay { .. }
        ));
        assert_eq!(
            relay.consider(&frame(7, 3, 8)).unwrap(),
            FloodDecision::Ignore(FloodIgnore::Duplicate)
        );

        let mut other_source = Packet::decode(&frame(7, 3, 8)).unwrap();
        other_source.header.source += 1;
        assert!(matches!(
            relay.consider(&other_source.encode().unwrap()).unwrap(),
            FloodDecision::Relay { .. }
        ));
    }

    #[test]
    fn bounded_seen_table_evicts_oldest_identity() {
        let mut relay = relay(1);
        assert!(matches!(
            relay.consider(&frame(1, 3, 8)).unwrap(),
            FloodDecision::Relay { .. }
        ));
        assert!(matches!(
            relay.consider(&frame(2, 3, 8)).unwrap(),
            FloodDecision::Relay { .. }
        ));
        assert!(matches!(
            relay.consider(&frame(1, 3, 8)).unwrap(),
            FloodDecision::Relay { .. }
        ));
    }

    #[test]
    fn zero_hop_is_remembered_but_not_relayed() {
        let mut relay = relay(2);
        assert_eq!(
            relay.consider(&frame(9, 0, 8)).unwrap(),
            FloodDecision::Ignore(FloodIgnore::HopLimit)
        );
        assert_eq!(
            relay.consider(&frame(9, 0, 8)).unwrap(),
            FloodDecision::Ignore(FloodIgnore::Duplicate)
        );
    }
}
