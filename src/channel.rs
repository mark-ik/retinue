//! A reliable, in-order message layer over a link — the machinery beneath RNS
//! `Channel`/`Buffer`.
//!
//! Raw link data packets are best-effort by spec: over TCP they never drop, so an
//! `AsyncRead`/`AsyncWrite` link is reliable *by accident of the medium*. Over LoRa
//! or serial they drop, reorder, and delay, and a stream that returns `Ok` for bytes
//! that never arrive is lying to its caller. This module is the layer that makes the
//! stream honest on any medium: sequence numbers, cumulative acknowledgement, a send
//! window, retransmission on timeout, and receiver-side reordering.
//!
//! It is **sans-io**: [`Channel`] holds no sockets and no clock. The caller drives it
//! — [`poll_transmit`](Channel::poll_transmit) with the current time yields the
//! frames to put on the wire (new data within the window, retransmits past their
//! timeout, and pending acks), and [`handle`](Channel::handle) feeds received frames
//! back in. That makes it testable against a deterministic loss model on a virtual
//! clock, which is the only way the retransmit and reorder paths actually execute
//! (see `retinue::lossy`).
//!
//! The wire here (`[type][seq]` framing over u32 sequence numbers) is retinue's own,
//! chosen to make the machinery testable now. Pinning it to the RNS `Channel` wire —
//! its 16-bit windowed sequence and message envelope — is a capture-gated follow-on,
//! the same discipline as every other retinue wire format.

use std::collections::{BTreeMap, VecDeque};

/// Maximum unacknowledged messages in flight. A small window is enough to keep a
/// slow link busy without overrunning a slow receiver; RNS grows this dynamically
/// (deferred — the fixed window is correct, just not yet adaptive).
pub const DEFAULT_WINDOW: u32 = 8;

/// Ticks without an ack before an outstanding message is retransmitted. "Tick" is
/// whatever unit the caller passes to [`Channel::poll_transmit`] (milliseconds over
/// a real clock; a counter in tests).
pub const DEFAULT_RETX_TIMEOUT: u64 = 4;

/// One channel frame on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// A sequenced payload.
    Data {
        /// Monotonic sequence number.
        seq: u32,
        /// Application bytes.
        payload: Vec<u8>,
    },
    /// A cumulative acknowledgement: the sender may release every sequence `< next`.
    Ack {
        /// The next sequence the receiver still needs (everything below is held).
        next: u32,
    },
}

impl Frame {
    /// Encode to bytes: `[0x00][seq u32 BE][payload]` for data, `[0x01][next u32 BE]`
    /// for an ack.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Frame::Data { seq, payload } => {
                let mut out = Vec::with_capacity(5 + payload.len());
                out.push(0x00);
                out.extend_from_slice(&seq.to_be_bytes());
                out.extend_from_slice(payload);
                out
            }
            Frame::Ack { next } => {
                let mut out = Vec::with_capacity(5);
                out.push(0x01);
                out.extend_from_slice(&next.to_be_bytes());
                out
            }
        }
    }

    /// Decode a frame, or `None` if the bytes are malformed.
    pub fn decode(bytes: &[u8]) -> Option<Frame> {
        let (&kind, rest) = bytes.split_first()?;
        let seq_bytes: [u8; 4] = rest.get(..4)?.try_into().ok()?;
        let seq = u32::from_be_bytes(seq_bytes);
        match kind {
            0x00 => Some(Frame::Data {
                seq,
                payload: rest[4..].to_vec(),
            }),
            0x01 => Some(Frame::Ack { next: seq }),
            _ => None,
        }
    }
}

/// One un-acknowledged outbound message.
struct Outstanding {
    seq: u32,
    payload: Vec<u8>,
    last_tx: u64,
}

/// A reliable, in-order message channel. See the module docs.
pub struct Channel {
    // ── send side ──
    /// Application messages not yet assigned a sequence (waiting for window room).
    outgoing: VecDeque<Vec<u8>>,
    /// In-flight, unacknowledged: sequences `[send_base, send_next)`.
    outstanding: VecDeque<Outstanding>,
    send_base: u32,
    send_next: u32,
    window: u32,
    retx_timeout: u64,

    // ── receive side ──
    /// Next sequence we can deliver in order.
    recv_next: u32,
    /// Received-but-not-yet-deliverable, held until the gap before them fills.
    reorder: BTreeMap<u32, Vec<u8>>,
    /// Delivered, in order, ready for the application to read.
    inbox: VecDeque<Vec<u8>>,
    /// A data frame arrived since the last transmit, so an ack is owed.
    ack_owed: bool,
}

impl Default for Channel {
    fn default() -> Self {
        Self::new()
    }
}

impl Channel {
    /// A channel with the default window and retransmit timeout.
    pub fn new() -> Self {
        Self::with_params(DEFAULT_WINDOW, DEFAULT_RETX_TIMEOUT)
    }

    /// A channel with an explicit window and retransmit timeout (for tests and, later,
    /// dynamic window sizing).
    pub fn with_params(window: u32, retx_timeout: u64) -> Self {
        Self {
            outgoing: VecDeque::new(),
            outstanding: VecDeque::new(),
            send_base: 0,
            send_next: 0,
            window: window.max(1),
            retx_timeout,
            recv_next: 0,
            reorder: BTreeMap::new(),
            inbox: VecDeque::new(),
            ack_owed: false,
        }
    }

    /// Queue an application message for reliable, in-order delivery. It is assigned a
    /// sequence and put on the wire by [`poll_transmit`](Self::poll_transmit) as the
    /// window allows.
    pub fn send(&mut self, payload: Vec<u8>) {
        self.outgoing.push_back(payload);
    }

    /// The frames to transmit at time `now`: newly sendable data within the window,
    /// retransmissions of outstanding data past the retransmit timeout, and a pending
    /// acknowledgement if one is owed.
    pub fn poll_transmit(&mut self, now: u64) -> Vec<Frame> {
        let mut frames = Vec::new();

        // Fill the window with fresh data.
        while self.outstanding.len() < self.window as usize {
            let Some(payload) = self.outgoing.pop_front() else {
                break;
            };
            let seq = self.send_next;
            self.send_next += 1;
            self.outstanding.push_back(Outstanding {
                seq,
                payload: payload.clone(),
                last_tx: now,
            });
            frames.push(Frame::Data { seq, payload });
        }

        // Retransmit anything unacked for too long.
        for o in &mut self.outstanding {
            if now.saturating_sub(o.last_tx) >= self.retx_timeout {
                o.last_tx = now;
                frames.push(Frame::Data {
                    seq: o.seq,
                    payload: o.payload.clone(),
                });
            }
        }

        // One cumulative ack carries acknowledgement of everything received so far.
        if self.ack_owed {
            self.ack_owed = false;
            frames.push(Frame::Ack {
                next: self.recv_next,
            });
        }

        frames
    }

    /// Process a received frame.
    pub fn handle(&mut self, frame: Frame) {
        match frame {
            Frame::Ack { next } => {
                // Cumulative: release every outstanding sequence below `next`.
                let next = next.min(self.send_next);
                if next > self.send_base {
                    self.send_base = next;
                    while self.outstanding.front().is_some_and(|o| o.seq < next) {
                        self.outstanding.pop_front();
                    }
                }
            }
            Frame::Data { seq, payload } => {
                // Every data frame owes an ack, even a duplicate — the sender may be
                // retransmitting because our earlier ack was itself lost.
                self.ack_owed = true;
                match seq.cmp(&self.recv_next) {
                    std::cmp::Ordering::Equal => {
                        self.inbox.push_back(payload);
                        self.recv_next += 1;
                        // Pull any now-contiguous buffered frames into order.
                        while let Some(next) = self.reorder.remove(&self.recv_next) {
                            self.inbox.push_back(next);
                            self.recv_next += 1;
                        }
                    }
                    std::cmp::Ordering::Greater => {
                        // Future frame: hold it until the gap fills.
                        self.reorder.entry(seq).or_insert(payload);
                    }
                    std::cmp::Ordering::Less => {
                        // Already delivered: drop the payload, keep the ack.
                    }
                }
            }
        }
    }

    /// The next in-order application message, if one is ready.
    pub fn recv(&mut self) -> Option<Vec<u8>> {
        self.inbox.pop_front()
    }

    /// Whether everything queued to send has been sent and acknowledged.
    pub fn send_idle(&self) -> bool {
        self.outgoing.is_empty() && self.outstanding.is_empty()
    }

    /// Count of in-flight, unacknowledged messages.
    pub fn in_flight(&self) -> usize {
        self.outstanding.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{Channel, Frame};
    use crate::lossy::LossModel;

    #[test]
    fn frame_round_trips() {
        let data = Frame::Data {
            seq: 0x0A0B_0C0D,
            payload: b"hello".to_vec(),
        };
        assert_eq!(Frame::decode(&data.encode()), Some(data));
        let ack = Frame::Ack { next: 42 };
        assert_eq!(Frame::decode(&ack.encode()), Some(ack));
        assert_eq!(Frame::decode(&[0x00]), None);
    }

    #[test]
    fn lossless_in_order_delivery() {
        // No loss, no reorder: everything arrives once, in order.
        let mut tx = Channel::new();
        let mut rx = Channel::new();
        for i in 0u8..20 {
            tx.send(vec![i]);
        }
        let mut got = Vec::new();
        for now in 0..1000 {
            for f in tx.poll_transmit(now) {
                rx.handle(f);
            }
            for f in rx.poll_transmit(now) {
                tx.handle(f);
            }
            while let Some(m) = rx.recv() {
                got.push(m[0]);
            }
            if got.len() == 20 {
                break;
            }
        }
        assert_eq!(got, (0u8..20).collect::<Vec<_>>());
    }

    /// Run a whole byte stream from `tx` to `rx` across a deterministic lossy pipe on
    /// a virtual clock, and return what `rx` reconstructs. `drop`/`delay` seeds and
    /// rates make every drop, delay, and reorder reproducible.
    fn stream_over_loss(drop_per_mille: u32, max_delay_ticks: u64, seed: u64) -> Vec<u8> {
        let payload: Vec<u8> = (0..4000u32).map(|i| (i * 31 + 7) as u8).collect();
        let mut tx = Channel::new();
        let mut rx = Channel::new();
        for chunk in payload.chunks(48) {
            tx.send(chunk.to_vec());
        }

        // A loss model per direction; delay in ticks reorders frames.
        let mut fwd = LossModel::new(seed)
            .drop_per_mille(drop_per_mille)
            .max_delay_ms(max_delay_ticks);
        let mut bwd = LossModel::new(seed ^ 0xFFFF)
            .drop_per_mille(drop_per_mille)
            .max_delay_ms(max_delay_ticks);

        // (arrival_tick, frame) in flight in each direction.
        let mut to_rx: Vec<(u64, Frame)> = Vec::new();
        let mut to_tx: Vec<(u64, Frame)> = Vec::new();
        let mut got: Vec<u8> = Vec::new();

        for now in 0..1_000_000u64 {
            for f in tx.poll_transmit(now) {
                if !fwd.should_drop() {
                    to_rx.push((now + 1 + fwd.delay_ms(), f));
                }
            }
            for f in rx.poll_transmit(now) {
                if !bwd.should_drop() {
                    to_tx.push((now + 1 + bwd.delay_ms(), f));
                }
            }
            to_rx.retain(|(t, f)| {
                if *t <= now {
                    rx.handle(f.clone());
                    false
                } else {
                    true
                }
            });
            to_tx.retain(|(t, f)| {
                if *t <= now {
                    tx.handle(f.clone());
                    false
                } else {
                    true
                }
            });
            while let Some(m) = rx.recv() {
                got.extend_from_slice(&m);
            }
            if got.len() == payload.len() && tx.send_idle() {
                break;
            }
        }
        assert_eq!(got, payload, "stream must reconstruct exactly");
        got
    }

    #[test]
    fn stream_survives_drop() {
        // 30% packet loss, no delay: retransmission recovers every chunk, in order.
        stream_over_loss(300, 0, 11);
    }

    #[test]
    fn stream_survives_drop_reorder_and_delay() {
        // 25% loss plus up to 6 ticks of jitter (which reorders): the reorder buffer
        // plus retransmission still reconstruct the stream byte-for-byte.
        stream_over_loss(250, 6, 99);
    }

    #[test]
    fn heavy_loss_still_converges() {
        // 60% loss is brutal but retransmission is unconditional, so it still lands.
        stream_over_loss(600, 3, 7);
    }
}
