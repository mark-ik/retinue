//! A reliable, in-order message layer over a link — RNS `Channel`, wire-compatible.
//!
//! Raw link data packets are best-effort by spec: over TCP they never drop, so an
//! `AsyncRead`/`AsyncWrite` link is reliable *by accident of the medium*. Over LoRa
//! or serial they drop, reorder, and delay, and a stream that returns `Ok` for bytes
//! that never arrive is lying to its caller. This is the layer that makes the stream
//! honest on any medium: sequence numbers, a send window, retransmission of unproven
//! packets, and receiver-side reordering.
//!
//! The wire is RNS 1.3.8's, captured black-box (see
//! `design_docs/2026-07-13_rns_wire_format_reference.md` §3.9, fixtures
//! `channel_wire.json` / `channel_link.json`):
//!
//! - A message is an [`Envelope`] — `[msgtype u16][sequence u16][length u16][payload]`,
//!   big-endian — carried in a link data packet with context `14` (`0x0e`).
//! - The sequence is windowed **16-bit** (mod [`SEQ_MODULUS`]).
//! - **Acknowledgement is the link packet proof, not an ack message.** Each envelope
//!   packet is proof-requesting; an unproven sequence is retransmitted. Confirmed by
//!   capture: RNS resent a seq-0 envelope 5 times while the receiver stayed silent.
//!
//! It is **sans-io**: [`Channel`] holds no sockets and no clock. The caller (a link
//! driver) drives it — [`poll_transmit`](Channel::poll_transmit) with the current
//! time yields the envelopes to put on the wire (new data within the window, plus
//! retransmits past their timeout); [`handle`](Channel::handle) feeds received
//! envelopes back in; and [`on_proof`](Channel::on_proof) releases an outstanding
//! sequence when its packet's proof arrives (the driver maps proof-by-packet-hash to
//! sequence). That is exactly what makes the retransmit and reorder paths testable
//! against a deterministic loss model on a virtual clock (see `retinue::lossy`).

use std::collections::{BTreeMap, HashMap, VecDeque};

/// The sequence space: sequences are 16-bit and wrap at this modulus (RNS
/// `SEQ_MODULUS`). Comparisons use wrapping distance with a half-modulus split to
/// tell "ahead" (a future packet to buffer) from "behind" (an old duplicate).
pub const SEQ_MODULUS: u32 = 65536;

/// Dynamic send-window constants, from RNS 1.3.8's `Channel` (captured in
/// `channel_wire.json`). The window bounds unacknowledged envelopes in flight; it grows
/// on sustained proofs and shrinks on retransmit, bounded by the RTT tier. It is a
/// *local* send-rate policy, never on the wire, so matching RNS's tiers is a tuning
/// choice, interoperable either way. `new` starts at [`WINDOW_INITIAL`].
pub const WINDOW_INITIAL: u32 = 2;
/// The window never shrinks below this (RNS `WINDOW_MIN`).
pub const WINDOW_MIN: u32 = 2;
/// The window never grows above this (RNS `WINDOW_MAX`, the fast-tier ceiling).
pub const WINDOW_MAX: u32 = 48;
/// How far the window drops on a retransmit (RNS `WINDOW_FLEXIBILITY`).
pub const WINDOW_FLEXIBILITY: u32 = 4;

const WINDOW_MAX_SLOW: u32 = 5;
const WINDOW_MAX_MEDIUM: u32 = 12;
const WINDOW_MAX_FAST: u32 = 48;
const WINDOW_MIN_LIMIT_SLOW: u32 = 2;
const WINDOW_MIN_LIMIT_MEDIUM: u32 = 5;
const WINDOW_MIN_LIMIT_FAST: u32 = 16;
// RTT tier thresholds, in the caller's tick unit. RNS's are seconds; these read a tick
// as a millisecond (RNS RTT_FAST/MEDIUM/SLOW = 0.18 / 0.75 / 1.45 s).
const RTT_FAST: u64 = 180;
const RTT_MEDIUM: u64 = 750;
const RTT_SLOW: u64 = 1450;
// Consecutive proofs (no retransmit) before the window steps up one (RNS FAST_RATE_THRESHOLD).
const FAST_RATE_THRESHOLD: u32 = 10;

/// Ticks without a proof before an outstanding envelope is retransmitted. "Tick" is
/// whatever unit the caller passes to [`Channel::poll_transmit`] (milliseconds over a
/// real clock; a counter in tests).
pub const DEFAULT_RETX_TIMEOUT: u64 = 4;

/// A retinue message-type tag for opaque stream bytes, until RNS's `Buffer` stream
/// msgtype + EOF framing are captured (the remaining half of O-18). `Buffer` uses it;
/// it is not yet RNS-`Buffer`-wire-compatible, though the `Channel` envelope carrying
/// it is.
pub const STREAM_MSGTYPE: u16 = 0xF900;

/// One channel message on the wire: `[msgtype u16][sequence u16][length u16][payload]`,
/// big-endian. This is RNS 1.3.8's `Channel.Envelope` layout exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// Registered message type (identifies the message class on the wire).
    pub msgtype: u16,
    /// Windowed 16-bit sequence number.
    pub sequence: u16,
    /// Message payload.
    pub payload: Vec<u8>,
}

impl Envelope {
    /// Encode to the RNS wire layout.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(6 + self.payload.len());
        out.extend_from_slice(&self.msgtype.to_be_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decode from the RNS wire layout, or `None` if malformed / the declared length
    /// does not match.
    pub fn decode(bytes: &[u8]) -> Option<Envelope> {
        let msgtype = u16::from_be_bytes(bytes.get(0..2)?.try_into().ok()?);
        let sequence = u16::from_be_bytes(bytes.get(2..4)?.try_into().ok()?);
        let length = u16::from_be_bytes(bytes.get(4..6)?.try_into().ok()? ) as usize;
        let payload = bytes.get(6..6 + length)?.to_vec();
        Some(Envelope { msgtype, sequence, payload })
    }
}

/// One un-acknowledged outbound envelope.
struct Outstanding {
    payload: Vec<u8>,
    last_tx: u64,
}

/// A reliable, in-order message channel. See the module docs.
pub struct Channel {
    msgtype: u16,
    window: u32,
    retx_timeout: u64,
    /// Whether the window sizes dynamically. Off for a fixed window (`with_params`).
    dynamic: bool,
    /// Consecutive proofs since the last retransmit; drives window growth.
    consecutive: u32,
    /// EWMA of the proof round-trip, in the caller's tick unit; selects the RTT tier.
    rtt: u64,

    // ── send side ──
    /// Application payloads not yet assigned a sequence (waiting for window room).
    outgoing: VecDeque<Vec<u8>>,
    /// In-flight, unacknowledged, keyed by sequence. Released by [`on_proof`].
    outstanding: HashMap<u16, Outstanding>,
    /// The next sequence to assign (wraps at `SEQ_MODULUS`).
    send_next: u16,

    // ── receive side ──
    /// The next sequence we can deliver in order.
    recv_next: u16,
    /// Received-but-not-yet-deliverable, held until the gap before them fills.
    reorder: BTreeMap<u16, Vec<u8>>,
    /// Delivered, in order, ready for the application to read.
    inbox: VecDeque<Vec<u8>>,
}

impl Default for Channel {
    fn default() -> Self {
        Self::new(STREAM_MSGTYPE)
    }
}

impl Channel {
    /// A channel for one message type with a **dynamic** window: it starts at
    /// [`WINDOW_INITIAL`] and grows toward the RTT tier's max on sustained proofs,
    /// shrinking on retransmit.
    pub fn new(msgtype: u16) -> Self {
        let mut channel = Self::with_params(msgtype, WINDOW_INITIAL, DEFAULT_RETX_TIMEOUT);
        channel.dynamic = true;
        channel
    }

    /// A channel with a **fixed** window and explicit retransmit timeout (for tests and
    /// callers that want a static send rate).
    pub fn with_params(msgtype: u16, window: u32, retx_timeout: u64) -> Self {
        Self {
            msgtype,
            window: window.max(1),
            retx_timeout,
            dynamic: false,
            consecutive: 0,
            rtt: RTT_MEDIUM,
            outgoing: VecDeque::new(),
            outstanding: HashMap::new(),
            send_next: 0,
            recv_next: 0,
            reorder: BTreeMap::new(),
            inbox: VecDeque::new(),
        }
    }

    /// The RTT tier's window ceiling, from the current RTT estimate.
    fn tier_max(&self) -> u32 {
        match self.rtt {
            r if r <= RTT_FAST => WINDOW_MAX_FAST,
            r if r <= RTT_MEDIUM => WINDOW_MAX_MEDIUM,
            r if r <= RTT_SLOW => WINDOW_MAX_SLOW,
            _ => WINDOW_MIN,
        }
    }

    /// The RTT tier's shrink floor, from the current RTT estimate.
    fn tier_min(&self) -> u32 {
        match self.rtt {
            r if r <= RTT_FAST => WINDOW_MIN_LIMIT_FAST,
            r if r <= RTT_MEDIUM => WINDOW_MIN_LIMIT_MEDIUM,
            _ => WINDOW_MIN_LIMIT_SLOW,
        }
    }

    /// The current send window.
    pub fn window(&self) -> u32 {
        self.window
    }

    /// Queue a payload for reliable, in-order delivery. Assigned a sequence and put on
    /// the wire by [`poll_transmit`](Self::poll_transmit) as the window allows.
    pub fn send(&mut self, payload: Vec<u8>) {
        self.outgoing.push_back(payload);
    }

    /// The envelopes to transmit at time `now`: newly sendable data within the window,
    /// and retransmissions of outstanding envelopes past the retransmit timeout. There
    /// is no ack envelope — acknowledgement is the link proof, delivered via
    /// [`on_proof`](Self::on_proof).
    pub fn poll_transmit(&mut self, now: u64) -> Vec<Envelope> {
        let mut out = Vec::new();

        // Fill the window with fresh data.
        while (self.outstanding.len() as u32) < self.window {
            let Some(payload) = self.outgoing.pop_front() else {
                break;
            };
            let seq = self.send_next;
            self.send_next = self.send_next.wrapping_add(1);
            out.push(Envelope { msgtype: self.msgtype, sequence: seq, payload: payload.clone() });
            self.outstanding.insert(seq, Outstanding { payload, last_tx: now });
        }

        // Retransmit anything unproven for too long.
        let mut retransmitted = false;
        for (&seq, o) in &mut self.outstanding {
            if now.saturating_sub(o.last_tx) >= self.retx_timeout {
                o.last_tx = now;
                out.push(Envelope { msgtype: self.msgtype, sequence: seq, payload: o.payload.clone() });
                retransmitted = true;
            }
        }

        // A retransmit means loss (or a stall): back the window off toward the tier floor.
        if self.dynamic && retransmitted {
            let floor = self.tier_min().max(WINDOW_MIN);
            self.window = self.window.saturating_sub(WINDOW_FLEXIBILITY).max(floor);
            self.consecutive = 0;
        }

        out
    }

    /// Release an outstanding sequence: its packet's proof arrived. Selective — RNS
    /// proves each packet individually, so this frees exactly one sequence. `now` lets
    /// the dynamic window measure RTT and grow on sustained success.
    pub fn on_proof(&mut self, sequence: u16, now: u64) {
        let Some(o) = self.outstanding.remove(&sequence) else {
            return;
        };
        if !self.dynamic {
            return;
        }
        // EWMA the round-trip since this packet's last transmit, then grow the window
        // one step per run of clean proofs, capped by the RTT tier.
        let sample = now.saturating_sub(o.last_tx);
        self.rtt = (self.rtt * 7 + sample) / 8;
        self.consecutive += 1;
        if self.consecutive >= FAST_RATE_THRESHOLD {
            self.consecutive = 0;
            let cap = self.tier_max();
            if self.window < cap {
                self.window += 1;
            }
        }
    }

    /// Process a received envelope, delivering it or buffering it for reordering.
    ///
    /// The driver proves the underlying packet at the link layer regardless (an
    /// unproven sender retransmits, and the receiver must re-prove duplicates), so this
    /// never needs to signal a proof — it only orders delivery.
    pub fn handle(&mut self, envelope: Envelope) {
        let ahead = envelope.sequence.wrapping_sub(self.recv_next);
        if ahead == 0 {
            self.inbox.push_back(envelope.payload);
            self.recv_next = self.recv_next.wrapping_add(1);
            // Pull any now-contiguous buffered envelopes into order.
            while let Some(next) = self.reorder.remove(&self.recv_next) {
                self.inbox.push_back(next);
                self.recv_next = self.recv_next.wrapping_add(1);
            }
        } else if (ahead as u32) < SEQ_MODULUS / 2 {
            // A future sequence within the forward half of the space: hold it.
            self.reorder.entry(envelope.sequence).or_insert(envelope.payload);
        }
        // Otherwise the sequence is behind `recv_next` (an already-delivered
        // duplicate); drop the payload. The driver still proves the packet.
    }

    /// The next in-order application payload, if one is ready.
    pub fn recv(&mut self) -> Option<Vec<u8>> {
        self.inbox.pop_front()
    }

    /// Whether everything queued to send has been sent and proven.
    pub fn send_idle(&self) -> bool {
        self.outgoing.is_empty() && self.outstanding.is_empty()
    }

    /// Count of in-flight, unproven envelopes.
    pub fn in_flight(&self) -> usize {
        self.outstanding.len()
    }
}

/// Default per-message chunk: sized to sit inside a link data packet (`MDU` 464, less
/// channel framing and link encryption overhead) with margin.
pub const DEFAULT_CHUNK: usize = 384;

/// A byte stream over a reliable [`Channel`]: [`write`](Self::write) chunks bytes into
/// channel messages, [`read`](Self::read) concatenates delivered messages in order.
/// The stream-shaped, reliable face of `Channel` — the piece an `AsyncRead + AsyncWrite`
/// link binds to once a driver pumps [`poll_transmit`](Self::poll_transmit) /
/// [`handle`](Self::handle) / [`on_proof`](Self::on_proof) against the wire. Sans-io
/// like `Channel`; it adds only the byte<->message boundary.
///
/// Uses [`STREAM_MSGTYPE`]; RNS's own `Buffer` stream msgtype + EOF framing are the
/// remaining half of O-18 and pin later.
pub struct Buffer {
    channel: Channel,
    max_chunk: usize,
    read_buf: VecDeque<u8>,
}

impl Default for Buffer {
    fn default() -> Self {
        Self::new()
    }
}

impl Buffer {
    /// A buffer with the default channel and chunk size.
    pub fn new() -> Self {
        Self::with_channel(Channel::new(STREAM_MSGTYPE), DEFAULT_CHUNK)
    }

    /// A buffer over an explicit channel and chunk size.
    pub fn with_channel(channel: Channel, max_chunk: usize) -> Self {
        Self { channel, max_chunk: max_chunk.max(1), read_buf: VecDeque::new() }
    }

    /// Queue bytes for reliable, in-order delivery, chunked into channel messages.
    pub fn write(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(self.max_chunk) {
            self.channel.send(chunk.to_vec());
        }
    }

    /// Copy up to `out.len()` delivered bytes into `out`, returning the count read.
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        self.fill();
        let n = out.len().min(self.read_buf.len());
        for slot in out.iter_mut().take(n) {
            *slot = self.read_buf.pop_front().expect("len checked");
        }
        n
    }

    /// Take all currently-available delivered bytes.
    pub fn read_available(&mut self) -> Vec<u8> {
        self.fill();
        self.read_buf.drain(..).collect()
    }

    fn fill(&mut self) {
        while let Some(msg) = self.channel.recv() {
            self.read_buf.extend(msg);
        }
    }

    /// Envelopes to put on the wire now — see [`Channel::poll_transmit`].
    pub fn poll_transmit(&mut self, now: u64) -> Vec<Envelope> {
        self.channel.poll_transmit(now)
    }

    /// Feed a received envelope in — see [`Channel::handle`].
    pub fn handle(&mut self, envelope: Envelope) {
        self.channel.handle(envelope);
    }

    /// Release a proven sequence — see [`Channel::on_proof`].
    pub fn on_proof(&mut self, sequence: u16, now: u64) {
        self.channel.on_proof(sequence, now);
    }

    /// The current send window — see [`Channel::window`].
    pub fn window(&self) -> u32 {
        self.channel.window()
    }

    /// Whether everything written has been sent and proven.
    pub fn send_idle(&self) -> bool {
        self.channel.send_idle()
    }
}

#[cfg(test)]
mod tests {
    use super::{Buffer, Channel, Envelope, DEFAULT_RETX_TIMEOUT, WINDOW_INITIAL};
    use crate::lossy::LossModel;

    #[test]
    fn envelope_matches_rns_capture() {
        // Gold test: retinue's envelope encoding equals RNS 1.3.8's own Envelope.pack()
        // for every captured vector. Ties the wire to the black-box capture.
        let fixture = include_str!("../tests/fixtures/channel_wire.json");
        let doc: serde_json::Value = serde_json::from_str(fixture).unwrap();
        for v in doc["envelope_vectors"].as_array().unwrap() {
            let msgtype = v["msgtype"].as_u64().unwrap() as u16;
            let sequence = v["sequence"].as_u64().unwrap() as u16;
            let payload = hex_bytes(v["payload_hex"].as_str().unwrap());
            let expected = v["packed_hex"].as_str().unwrap();
            let env = Envelope { msgtype, sequence, payload };
            assert_eq!(hex_str(&env.encode()), expected, "encode must equal RNS pack()");
            assert_eq!(Envelope::decode(&env.encode()), Some(env), "round-trip");
        }
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
    fn hex_str(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn lossless_in_order_delivery() {
        let mut tx = Channel::new(0xABCD);
        let mut rx = Channel::new(0xABCD);
        for i in 0u8..20 {
            tx.send(vec![i]);
        }
        let mut got = Vec::new();
        for now in 0..1000 {
            for e in tx.poll_transmit(now) {
                let seq = e.sequence;
                rx.handle(e);
                tx.on_proof(seq, now); // lossless: every packet is immediately proven
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

    /// Run a byte stream through two Buffers across a deterministic lossy pipe on a
    /// virtual clock, proving each delivered envelope back (subject to loss) — the
    /// proof-based model. Returns nothing; asserts exact reconstruction.
    fn stream_over_loss(drop_per_mille: u32, max_delay_ticks: u64, seed: u64) {
        let payload: Vec<u8> = (0..4000u32).map(|i| (i.wrapping_mul(31).wrapping_add(7)) as u8).collect();
        let mut tx = Buffer::new();
        let mut rx = Buffer::new();
        tx.write(&payload);

        let mut fwd = LossModel::new(seed).drop_per_mille(drop_per_mille).max_delay_ms(max_delay_ticks);
        let mut bwd = LossModel::new(seed ^ 0xFFFF).drop_per_mille(drop_per_mille).max_delay_ms(max_delay_ticks);

        // In flight: (arrival_tick, item). Forward carries envelopes; back carries the
        // sequence of a proof (the link auto-proves every received packet).
        let mut to_rx: Vec<(u64, Envelope)> = Vec::new();
        let mut to_tx: Vec<(u64, u16)> = Vec::new();
        let mut got: Vec<u8> = Vec::new();

        for now in 0..1_000_000u64 {
            for e in tx.poll_transmit(now) {
                if !fwd.should_drop() {
                    to_rx.push((now + 1 + fwd.delay_ms(), e));
                }
            }
            // Deliver due envelopes; prove each one back (dup or not).
            let mut still = Vec::new();
            for (t, e) in std::mem::take(&mut to_rx) {
                if t <= now {
                    let seq = e.sequence;
                    rx.handle(e);
                    if !bwd.should_drop() {
                        to_tx.push((now + 1 + bwd.delay_ms(), seq));
                    }
                } else {
                    still.push((t, e));
                }
            }
            to_rx = still;
            to_tx.retain(|(t, seq)| {
                if *t <= now {
                    tx.on_proof(*seq, now);
                    false
                } else {
                    true
                }
            });
            got.extend(rx.read_available());
            if got.len() == payload.len() && tx.send_idle() {
                break;
            }
        }
        assert_eq!(got, payload, "stream must reconstruct exactly over loss");
    }

    #[test]
    fn stream_survives_drop() {
        stream_over_loss(300, 0, 11);
    }

    #[test]
    fn stream_survives_drop_reorder_and_delay() {
        stream_over_loss(250, 6, 99);
    }

    #[test]
    fn heavy_loss_still_converges() {
        stream_over_loss(600, 3, 7);
    }

    #[test]
    fn sequence_wraps_past_the_16bit_modulus() {
        // Push more than 65536 messages so the sequence wraps, and confirm order holds
        // across the wrap. Small window keeps it quick.
        let mut tx = Channel::with_params(0x0001, 4, 2);
        let mut rx = Channel::with_params(0x0001, 4, 2);
        let total = 70_000u32; // > SEQ_MODULUS
        let mut sent = 0u32;
        let mut got = 0u32;
        for now in 0..5_000_000u64 {
            while sent < total && tx.in_flight() < 4 {
                tx.send(vec![(sent % 251) as u8]);
                sent += 1;
            }
            for e in tx.poll_transmit(now) {
                let seq = e.sequence;
                rx.handle(e);
                tx.on_proof(seq, now);
            }
            while let Some(m) = rx.recv() {
                assert_eq!(m, vec![(got % 251) as u8], "in order across the wrap");
                got += 1;
            }
            if got == total {
                break;
            }
        }
        assert_eq!(got, total, "all delivered across the sequence wrap");
    }

    #[test]
    fn window_grows_on_sustained_clean_proofs() {
        // A dynamic channel starts at WINDOW_INITIAL. Prove a long run of packets
        // cleanly and promptly (one-tick round trip), and the window climbs step by
        // step into the fast RTT tier — the growth half of RNS's dynamic sizing.
        let mut c = Channel::new(0x0001);
        assert_eq!(c.window(), WINDOW_INITIAL, "starts at the initial window");
        for i in 0..2000u16 {
            c.send(vec![i as u8]);
        }
        let mut now = 0u64;
        let mut proven = 0u32;
        // Each poll sends `window` fresh envelopes; we prove them all one tick later.
        // The outer bound is a safety net — growth reaches the ceiling in ~40 polls.
        for _ in 0..100_000 {
            if proven >= 2000 {
                break;
            }
            let envs = c.poll_transmit(now);
            now += 1;
            for e in envs {
                c.on_proof(e.sequence, now);
                proven += 1;
            }
        }
        assert_eq!(proven, 2000, "proved every packet");
        assert!(c.window() > WINDOW_INITIAL, "window grew (got {})", c.window());
        assert!(c.window() >= 16, "climbed into the fast tier (got {})", c.window());
    }

    #[test]
    fn window_shrinks_on_retransmit() {
        // Grow the window with clean proofs, then let fresh packets go unproven past the
        // retransmit timeout: the retransmit backs the window off toward the tier floor
        // — the shrink half of the dynamic sizing.
        let mut c = Channel::new(0x0001);
        for i in 0..2000u16 {
            c.send(vec![i as u8]);
        }
        let mut now = 0u64;
        let mut proven = 0u32;
        for _ in 0..100_000 {
            if proven >= 2000 {
                break;
            }
            let envs = c.poll_transmit(now);
            now += 1;
            for e in envs {
                c.on_proof(e.sequence, now);
                proven += 1;
            }
        }
        let grown = c.window();
        assert!(grown > 20, "window grew well above the floor first (got {})", grown);

        // New data goes out, and nobody proves it. Past the timeout it retransmits.
        for i in 0..8u16 {
            c.send(vec![i as u8]);
        }
        let fresh = c.poll_transmit(now);
        assert!(!fresh.is_empty(), "fresh data went out");
        now += DEFAULT_RETX_TIMEOUT + 1;
        let resent = c.poll_transmit(now);
        assert!(!resent.is_empty(), "unproven data retransmitted");
        assert!(
            c.window() < grown,
            "window shrank on retransmit ({grown} -> {})",
            c.window()
        );
    }
}
