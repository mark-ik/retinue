//! A duty-cycle-respecting radio link: a [`Modem`] behind the shared airtime gate.
//!
//! The [`Modem`] trait puts frames on the air and the [`AirtimeBudget`](crate::airtime) tracks
//! how much air a channel may use; this joins them. Every transmission is priced by its
//! time-on-air and charged against the budget, so a caller cannot exceed the regional duty
//! cycle no matter how fast it feeds frames — the finding from the first reliable link over
//! real RF, where an unpaced pump backed the radio's queue up and starved the half-duplex
//! receive windows. The link is sans-io: the caller supplies the clock and drives it, so it
//! runs on a virtual clock in tests exactly as it will over a serial pump.

use core::time::Duration;

use crate::airtime::AirtimeBudget;
use crate::modem::{Modem, ModemError, ModemEvent};

/// A frame received off the air, with its link-quality metrics.
#[derive(Debug, Clone, PartialEq)]
pub struct Received {
    pub frame: Vec<u8>,
    pub rssi_dbm: i16,
    pub snr_db: f32,
}

/// What happened to a send request.
#[derive(Debug)]
pub enum SendOutcome {
    /// The frame was queued; it will occupy `airtime` of air and was charged to the budget.
    Sent { airtime: Duration },
    /// The duty-cycle budget is full; the earliest time this frame would fit is `retry_at_ms`.
    /// `None` means it can never fit (its airtime exceeds the whole window allowance).
    DutyCycleBlocked { retry_at_ms: Option<u64> },
    /// The modem refused the frame (half-duplex busy, too long, hardware fault).
    Failed(ModemError),
}

/// A [`Modem`] gated by an [`AirtimeBudget`].
pub struct RadioLink<M> {
    modem: M,
    budget: AirtimeBudget,
}

impl<M: Modem> RadioLink<M> {
    pub fn new(modem: M, budget: AirtimeBudget) -> Self {
        RadioLink { modem, budget }
    }

    /// Borrow the modem (for its serial I/O — `on_serial`, `take_outbound` — and parameters).
    pub fn modem(&self) -> &M {
        &self.modem
    }

    pub fn modem_mut(&mut self) -> &mut M {
        &mut self.modem
    }

    /// Attempt to transmit `frame` at `now_ms`, gated by the duty-cycle budget.
    ///
    /// If the budget allows it, the frame is queued on the modem and its time-on-air charged to
    /// the budget. Otherwise the send is refused with the earliest time it could be retried, so
    /// a pump can schedule rather than busy-wait. This is the one place air is committed, so it
    /// is the one place the duty cycle is enforced.
    pub fn send(&mut self, frame: &[u8], now_ms: u64) -> SendOutcome {
        let airtime_ms = self.modem.params().time_on_air_ms(frame.len());
        if !self.budget.may_transmit(now_ms, airtime_ms) {
            return SendOutcome::DutyCycleBlocked {
                retry_at_ms: self.budget.next_slot(now_ms, airtime_ms),
            };
        }
        match self.modem.enqueue(frame) {
            Ok(airtime) => {
                self.budget.record(now_ms, airtime_ms);
                SendOutcome::Sent { airtime }
            }
            Err(e) => SendOutcome::Failed(e),
        }
    }

    /// Drain the next received frame, if the modem has one. Non-receive events (transmit
    /// completion, channel activity) are consumed and skipped.
    pub fn recv(&mut self) -> Option<Received> {
        while let Some(event) = self.modem.poll() {
            if let ModemEvent::Received {
                frame,
                rssi_dbm,
                snr_db,
            } = event
            {
                return Some(Received {
                    frame,
                    rssi_dbm,
                    snr_db,
                });
            }
        }
        None
    }

    /// Airtime spent in the current window at `now_ms`, in milliseconds (diagnostics).
    pub fn airtime_spent_ms(&mut self, now_ms: u64) -> u64 {
        self.budget.spent_ms(now_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lora::{CodingRate, LoRaParams};
    use std::collections::VecDeque;

    /// A modem that echoes each enqueued frame back as a Received and reports its airtime.
    struct Echo {
        params: LoRaParams,
        events: VecDeque<ModemEvent>,
    }

    impl Echo {
        fn new() -> Self {
            Echo {
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

    impl Modem for Echo {
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
            let airtime = self.params.time_on_air(frame.len());
            self.events.push_back(ModemEvent::Received {
                frame: frame.to_vec(),
                rssi_dbm: -50,
                snr_db: 10.0,
            });
            Ok(airtime)
        }
        fn poll(&mut self) -> Option<ModemEvent> {
            self.events.pop_front()
        }
    }

    /// A 1-second window at 10% = 100 ms of allowed airtime.
    fn tight_link() -> RadioLink<Echo> {
        RadioLink::new(Echo::new(), AirtimeBudget::new(1000, 100))
    }

    #[test]
    fn a_send_within_budget_goes_out_and_is_received() {
        let mut link = tight_link();
        match link.send(b"hello", 0) {
            SendOutcome::Sent { .. } => {}
            other => panic!("expected Sent, got {other:?}"),
        }
        let got = link.recv().expect("the echo frame");
        assert_eq!(got.frame, b"hello");
        assert_eq!(got.rssi_dbm, -50);
    }

    #[test]
    fn the_duty_cycle_gate_blocks_and_reports_a_retry_time() {
        let mut link = tight_link();
        // A 12-byte SF7 frame is ~41 ms of air; two fit in the 100 ms window (82 ms), the third
        // does not (123 ms), and the gate reports when it would.
        let payload = vec![0xAB; 12];
        assert!(matches!(link.send(&payload, 0), SendOutcome::Sent { .. }));
        assert!(matches!(link.send(&payload, 0), SendOutcome::Sent { .. }));
        match link.send(&payload, 0) {
            SendOutcome::DutyCycleBlocked {
                retry_at_ms: Some(t),
            } => {
                assert!(t > 0, "a future retry time");
                // At the reported time, the send fits.
                assert!(matches!(link.send(&payload, t), SendOutcome::Sent { .. }));
            }
            other => panic!("expected DutyCycleBlocked, got {other:?}"),
        }
    }

    #[test]
    fn budget_recovers_after_the_window_passes() {
        let mut link = tight_link();
        let payload = vec![0u8; 30]; // ~72 ms, only one fits per 100 ms window
        assert!(matches!(link.send(&payload, 0), SendOutcome::Sent { .. }));
        assert!(matches!(
            link.send(&payload, 10),
            SendOutcome::DutyCycleBlocked { .. }
        ));
        // A full window later, the air is free again.
        assert!(matches!(
            link.send(&payload, 1200),
            SendOutcome::Sent { .. }
        ));
    }

    #[test]
    fn a_frame_larger_than_the_whole_allowance_can_never_fit() {
        // Slow params make even a small frame exceed a tiny allowance.
        let mut modem = Echo::new();
        modem.params.spreading_factor = 12; // very long airtime
        let mut link = RadioLink::new(modem, AirtimeBudget::new(1000, 1)); // 10 ms allowance
        match link.send(b"anything", 0) {
            SendOutcome::DutyCycleBlocked { retry_at_ms: None } => {}
            other => panic!("expected never-fits, got {other:?}"),
        }
    }
}
