//! The `Modem` trait: the seam every radio backend plugs into, beneath retinue and the mesh
//! crates.
//!
//! It is sans-io and sync (poll-based), mirroring retinue's own interface discipline where the
//! framing layer is a pure state machine and only the pump task touches sockets and the clock.
//! A modem never blocks, sleeps, or `await`s: a pump enqueues frames and drains events, and
//! owns timing, scheduling, and the duty-cycle gate ([`crate::airtime`]). The trait is
//! object-safe, so a set of heterogeneous radios (an RNode over serial, a direct SX126x over
//! SPI, a deterministic simulator) can be held as `Box<dyn Modem>`.
//!
//! A LoRa PHY frame maxes out well below retinue's 500-byte packet MTU (a one-byte length
//! field caps it near 255, and an RNode or link cap may be lower), so a single retinue packet
//! will not always fit one transmission. [`Modem::max_frame_len`] is where the pump learns the
//! cap so it can fragment or advertise a reduced MTU to the endpoint.

use core::time::Duration;

use crate::lora::LoRaParams;

/// One event a modem surfaces when polled.
#[derive(Debug, Clone)]
pub enum ModemEvent {
    /// A frame was demodulated, with its link-quality metrics.
    Received {
        frame: Vec<u8>,
        rssi_dbm: i16,
        snr_db: f32,
    },
    /// The in-flight transmission finished; `airtime` is what it actually occupied.
    TxDone { airtime: Duration },
    /// Carrier or preamble detected: half-duplex, so the caller must hold off transmitting.
    ChannelBusy,
    /// The channel returned to idle.
    ChannelClear,
}

/// A modem error.
#[derive(Debug)]
pub enum ModemError {
    /// Half-duplex conflict or a full transmit queue: retry once the channel clears.
    Busy,
    /// The frame exceeds the PHY (or negotiated) limit. The pump must fragment below `max`.
    TooLong { max: usize },
    /// A parameter set the hardware cannot honor (an invalid SF/BW combination, an
    /// out-of-band frequency).
    Unsupported,
    /// An underlying serial/SPI transport fault. Boxed to keep the trait object-safe.
    Transport(Box<dyn core::error::Error + Send + Sync>),
}

impl core::fmt::Display for ModemError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ModemError::Busy => write!(f, "modem busy"),
            ModemError::TooLong { max } => write!(f, "frame exceeds max length {max}"),
            ModemError::Unsupported => write!(f, "unsupported parameters"),
            ModemError::Transport(e) => write!(f, "transport error: {e}"),
        }
    }
}

impl core::error::Error for ModemError {}

/// A LoRa modem: sans-io, sync, object-safe. The caller drives it — enqueue a frame, poll for
/// events — and owns the clock, so airtime and duty-cycle enforcement live in the pump.
pub trait Modem {
    /// The PHY parameters currently in force: for airtime accounting, duty-cycle keying, and
    /// channel identity. `LoRaParams` is `Copy`, so this returns by value.
    fn params(&self) -> LoRaParams;

    /// Retune or change modulation (a channel hop, an ADR step). Applies to subsequent
    /// transmissions and to reception.
    fn set_params(&mut self, params: LoRaParams) -> Result<(), ModemError>;

    /// The largest PHY frame this modem accepts. The pump fragments retinue packets to fit.
    fn max_frame_len(&self) -> usize;

    /// Queue one frame for transmission. Non-blocking: returns the airtime it will occupy (=
    /// `params().time_on_air(frame.len())`), so the pump can debit a regional duty-cycle
    /// budget and schedule before committing the air. `Err(Busy)` if half-duplex or the queue
    /// is full; `Err(TooLong)` past [`max_frame_len`](Modem::max_frame_len).
    fn enqueue(&mut self, frame: &[u8]) -> Result<Duration, ModemError>;

    /// Drain one pending event, or `None` if none is ready. The pump calls this after a
    /// hardware interrupt, on a timer, or in a loop; the modem never blocks. This is the
    /// mirror of retinue's inbound `InterfaceSink`.
    fn poll(&mut self) -> Option<ModemEvent>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lora::CodingRate;
    use std::collections::VecDeque;

    /// A loopback modem: frames enqueued come straight back out as `Received`, and it reports
    /// `TxDone` with the computed airtime. Exists to prove the trait is object-safe and drives
    /// like a real radio would through a pump.
    struct Loopback {
        params: LoRaParams,
        events: VecDeque<ModemEvent>,
    }

    impl Loopback {
        fn new() -> Self {
            Loopback {
                params: LoRaParams {
                    spreading_factor: 7,
                    bandwidth_hz: 125_000,
                    coding_rate: CodingRate::Cr45,
                    frequency_hz: 915_000_000,
                    tx_power_dbm: 7,
                    preamble_syms: 8,
                    explicit_header: true,
                    crc: true,
                },
                events: VecDeque::new(),
            }
        }
    }

    impl Modem for Loopback {
        fn params(&self) -> LoRaParams {
            self.params
        }
        fn set_params(&mut self, params: LoRaParams) -> Result<(), ModemError> {
            self.params = params;
            Ok(())
        }
        fn max_frame_len(&self) -> usize {
            255
        }
        fn enqueue(&mut self, frame: &[u8]) -> Result<Duration, ModemError> {
            if frame.len() > self.max_frame_len() {
                return Err(ModemError::TooLong {
                    max: self.max_frame_len(),
                });
            }
            let airtime = self.params.time_on_air(frame.len());
            self.events.push_back(ModemEvent::TxDone { airtime });
            self.events.push_back(ModemEvent::Received {
                frame: frame.to_vec(),
                rssi_dbm: -80,
                snr_db: 9.0,
            });
            Ok(airtime)
        }
        fn poll(&mut self) -> Option<ModemEvent> {
            self.events.pop_front()
        }
    }

    #[test]
    fn drives_as_a_trait_object() {
        let mut modem: Box<dyn Modem> = Box::new(Loopback::new());
        let airtime = modem.enqueue(b"hello over the air").unwrap();
        assert_eq!(airtime, modem.params().time_on_air(18));

        // TxDone then the loopback frame come back on poll.
        assert!(matches!(modem.poll(), Some(ModemEvent::TxDone { .. })));
        match modem.poll() {
            Some(ModemEvent::Received { frame, .. }) => {
                assert_eq!(frame, b"hello over the air");
            }
            other => panic!("expected a received frame, got {other:?}"),
        }
        assert!(modem.poll().is_none());
    }

    #[test]
    fn rejects_an_oversize_frame() {
        let mut modem = Loopback::new();
        let big = vec![0u8; 256];
        assert!(matches!(
            modem.enqueue(&big),
            Err(ModemError::TooLong { max: 255 })
        ));
    }
}
