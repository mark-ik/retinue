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

/// The adaptive retransmit timeout is this multiple of the measured EWMA RTT, so the timeout
/// tracks the medium instead of a fixed tick count: a fast pipe retransmits in a few ticks, a
/// LoRa link whose round trip is seconds waits proportionally rather than storming the channel
/// with retransmits before the first proof can return. Only the dynamic channel adapts;
/// [`Channel::with_params`] keeps the fixed timeout it is given.
const RETX_RTT_FACTOR: u64 = 2;
/// The adaptive timeout never drops below this, preserving fast-medium behaviour.
const RETX_MIN: u64 = 4;
/// ...nor rises above this, so one wild RTT sample cannot stall the channel indefinitely.
const RETX_MAX: u64 = 8000;

/// The retransmit timeout implied by an RTT estimate: `RETX_RTT_FACTOR * rtt`, clamped.
fn retx_from_rtt(rtt: u64) -> u64 {
    (rtt * RETX_RTT_FACTOR).clamp(RETX_MIN, RETX_MAX)
}

/// The most out-of-order future envelopes the receiver will hold at once. A well-behaved
/// sender keeps at most a window's worth in flight (`WINDOW_MAX` = 48), so this is generous
/// headroom; its purpose is to bound the reorder buffer against a peer that streams only
/// future sequences and never fills the gap. See [`Channel::handle`].
pub const REORDER_MAX: usize = 256;

/// RNS `Buffer`'s stream-frame message type: a stream chunk rides a [`Channel`]
/// envelope under this msgtype (RNS `StreamDataMessage.MSGTYPE`). Captured black-box
/// (`buffer_wire.json`).
pub const STREAM_MSGTYPE: u16 = 0xFF00;

/// The largest stream id. The id is the low 14 bits of the [`StreamFrame`] header (RNS
/// `StreamDataMessage.STREAM_ID_MAX`); the top two bits are the eof / compressed flags.
pub const STREAM_ID_MAX: u16 = 0x3FFF;

/// The most stream data bytes in one [`StreamFrame`] (RNS `StreamDataMessage.MAX_DATA_LEN`):
/// the link MDU less the 6-byte envelope header and the 2-byte stream header (`OVERHEAD` 8).
pub const MAX_DATA_LEN: usize = 423;

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
        let length = u16::from_be_bytes(bytes.get(4..6)?.try_into().ok()?) as usize;
        let payload = bytes.get(6..6 + length)?.to_vec();
        Some(Envelope {
            msgtype,
            sequence,
            payload,
        })
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
        // Start the timeout from the initial RTT estimate (a medium-latency guess), then let
        // on_proof adapt it to the measured round trip.
        let mut channel = Self::with_params(msgtype, WINDOW_INITIAL, retx_from_rtt(RTT_MEDIUM));
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
            out.push(Envelope {
                msgtype: self.msgtype,
                sequence: seq,
                payload: payload.clone(),
            });
            self.outstanding.insert(
                seq,
                Outstanding {
                    payload,
                    last_tx: now,
                },
            );
        }

        // Retransmit anything unproven for too long.
        let mut retransmitted = false;
        for (&seq, o) in &mut self.outstanding {
            if now.saturating_sub(o.last_tx) >= self.retx_timeout {
                o.last_tx = now;
                out.push(Envelope {
                    msgtype: self.msgtype,
                    sequence: seq,
                    payload: o.payload.clone(),
                });
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
        // Track the retransmit timeout to the measured RTT (finding 1 from the first reliable
        // link over real RF: a fixed timeout storms a slow medium with premature retransmits).
        self.retx_timeout = retx_from_rtt(self.rtt);
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
    /// Returns whether the driver should prove (acknowledge) the underlying packet. It
    /// proves in-order and buffered frames, and re-proves duplicates (an unproven sender
    /// retransmits). It withholds the proof only when the reorder buffer is full and this is
    /// a new gap-filler: dropping a *proved* frame would lose it forever, so instead we leave
    /// it unproven and let the sender retransmit once the gap ahead of it clears. This bounds
    /// the reorder buffer against a peer that streams only future sequences.
    #[must_use]
    pub fn handle(&mut self, envelope: Envelope) -> bool {
        let ahead = envelope.sequence.wrapping_sub(self.recv_next);
        if ahead == 0 {
            self.inbox.push_back(envelope.payload);
            self.recv_next = self.recv_next.wrapping_add(1);
            // Pull any now-contiguous buffered envelopes into order.
            while let Some(next) = self.reorder.remove(&self.recv_next) {
                self.inbox.push_back(next);
                self.recv_next = self.recv_next.wrapping_add(1);
            }
            true
        } else if (ahead as u32) < SEQ_MODULUS / 2 {
            // A future sequence within the forward half of the space: hold it, unless the
            // reorder buffer is full of other gap-fillers and this is a new one.
            if self.reorder.len() >= REORDER_MAX && !self.reorder.contains_key(&envelope.sequence) {
                return false;
            }
            self.reorder
                .entry(envelope.sequence)
                .or_insert(envelope.payload);
            true
        } else {
            // Behind `recv_next`: an already-delivered duplicate. Drop the payload but prove
            // it — the sender retransmitted because our earlier proof did not arrive.
            true
        }
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

/// One RNS `Buffer` stream frame: the payload of the [`Channel`] envelope carrying a
/// stream chunk. Layout `[u16 BE header][data]`, header = `eof<<15 | compressed<<14 |
/// stream_id` (`stream_id` in the low 14 bits, [`STREAM_ID_MAX`]). The data length is
/// implied by the enclosing envelope's length field, so the frame carries none. This is
/// RNS 1.3.8's `StreamDataMessage.pack()` layout exactly (captured in `buffer_wire.json`).
///
/// `compressed` marks a bz2 transform applied to `data` *before* framing, not a layout
/// change — `pack()` stores `data` verbatim either way. retinue never sets it on send;
/// decoding a compressed frame from RNS needs a bz2 pass that is not yet wired.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamFrame {
    /// Stream id (14-bit): which multiplexed stream this chunk belongs to.
    pub stream_id: u16,
    /// End-of-stream marker: the last frame of this stream.
    pub eof: bool,
    /// Whether `data` is bz2-compressed (see the type docs).
    pub compressed: bool,
    /// The stream bytes (uncompressed unless `compressed`).
    pub data: Vec<u8>,
}

impl StreamFrame {
    const EOF_BIT: u16 = 0x8000;
    const COMPRESSED_BIT: u16 = 0x4000;

    /// Encode to the RNS stream-frame layout.
    pub fn encode(&self) -> Vec<u8> {
        let mut header = self.stream_id & STREAM_ID_MAX;
        if self.eof {
            header |= Self::EOF_BIT;
        }
        if self.compressed {
            header |= Self::COMPRESSED_BIT;
        }
        let mut out = Vec::with_capacity(2 + self.data.len());
        out.extend_from_slice(&header.to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    /// Decode from the RNS stream-frame layout, or `None` if shorter than the header.
    pub fn decode(bytes: &[u8]) -> Option<StreamFrame> {
        let header = u16::from_be_bytes(bytes.get(0..2)?.try_into().ok()?);
        Some(StreamFrame {
            stream_id: header & STREAM_ID_MAX,
            eof: header & Self::EOF_BIT != 0,
            compressed: header & Self::COMPRESSED_BIT != 0,
            data: bytes.get(2..)?.to_vec(),
        })
    }
}

/// Default per-frame chunk: RNS's own `MAX_DATA_LEN` — the most stream bytes that fit in
/// one link data packet after the envelope and stream headers.
pub const DEFAULT_CHUNK: usize = MAX_DATA_LEN;

/// A byte stream over a reliable [`Channel`], RNS `Buffer`-wire-compatible. Each write
/// chunk is a [`StreamFrame`] (stream id + eof + data) carried in a [`Channel`] envelope
/// under [`STREAM_MSGTYPE`]; [`read`](Self::read) concatenates delivered frames' data in
/// order. The stream-shaped, reliable face of `Channel` — the piece an
/// `AsyncRead + AsyncWrite` link binds to once a driver pumps
/// [`poll_transmit`](Self::poll_transmit) / [`handle`](Self::handle) /
/// [`on_proof`](Self::on_proof) against the wire. Sans-io like `Channel`.
///
/// The stream is multiplexable: a buffer sends on `send_stream_id` and reads only frames
/// tagged with `recv_stream_id`, so one `Channel` carries several streams (RNS's
/// bidirectional buffer is two ids over one channel). [`finish`](Self::finish) marks the
/// send stream done with an eof frame; [`recv_finished`](Self::recv_finished) reports the
/// peer's eof.
///
/// Compression is not wired: retinue never sets the compressed flag on send, and a
/// compressed frame received from RNS is left undecoded rather than appended as garbage —
/// [`had_unsupported_frame`](Self::had_unsupported_frame) surfaces that it happened. Full
/// interop-receive of RNS-compressed streams needs a bz2 pass, deferred.
pub struct Buffer {
    channel: Channel,
    max_chunk: usize,
    send_stream_id: u16,
    recv_stream_id: u16,
    read_buf: VecDeque<u8>,
    recv_eof: bool,
    saw_unsupported: bool,
}

impl Default for Buffer {
    fn default() -> Self {
        Self::new()
    }
}

impl Buffer {
    /// A buffer with the default channel and chunk size, stream id 0 both ways.
    pub fn new() -> Self {
        Self::with_channel(Channel::new(STREAM_MSGTYPE), DEFAULT_CHUNK)
    }

    /// A buffer over an explicit channel and chunk size, stream id 0 both ways.
    pub fn with_channel(channel: Channel, max_chunk: usize) -> Self {
        Self::with_streams(channel, max_chunk, 0, 0)
    }

    /// A buffer with explicit send / receive stream ids (each clamped to
    /// [`STREAM_ID_MAX`]) — one channel multiplexing distinct streams.
    pub fn with_streams(
        channel: Channel,
        max_chunk: usize,
        send_stream_id: u16,
        recv_stream_id: u16,
    ) -> Self {
        Self {
            channel,
            max_chunk: max_chunk.clamp(1, MAX_DATA_LEN),
            send_stream_id: send_stream_id & STREAM_ID_MAX,
            recv_stream_id: recv_stream_id & STREAM_ID_MAX,
            read_buf: VecDeque::new(),
            recv_eof: false,
            saw_unsupported: false,
        }
    }

    /// Queue bytes for reliable, in-order delivery, chunked into [`StreamFrame`]s.
    pub fn write(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(self.max_chunk) {
            self.send_frame(chunk.to_vec(), false);
        }
    }

    /// Mark the send stream finished: queue an empty eof frame. RNS also accepts eof
    /// riding a final data frame; a standalone eof is the simpler equivalent.
    pub fn finish(&mut self) {
        self.send_frame(Vec::new(), true);
    }

    fn send_frame(&mut self, data: Vec<u8>, eof: bool) {
        let frame = StreamFrame {
            stream_id: self.send_stream_id,
            eof,
            compressed: false,
            data,
        };
        self.channel.send(frame.encode());
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
            let Some(frame) = StreamFrame::decode(&msg) else {
                continue; // malformed frame; the channel already ordered/deduped it
            };
            if frame.stream_id != self.recv_stream_id {
                continue; // a different multiplexed stream on the same channel
            }
            if frame.compressed {
                // Undecodable without a bz2 pass (see the type docs). Don't append the
                // compressed bytes as if they were data; flag it instead of corrupting.
                self.saw_unsupported = true;
            } else {
                self.read_buf.extend(frame.data);
            }
            if frame.eof {
                self.recv_eof = true;
            }
        }
    }

    /// Whether the peer has signalled end-of-stream (an eof frame on `recv_stream_id`).
    pub fn recv_finished(&mut self) -> bool {
        self.fill();
        self.recv_eof
    }

    /// Whether a frame arrived that this buffer could not decode (today: a compressed
    /// frame from RNS). Its bytes were dropped rather than corrupting the stream.
    pub fn had_unsupported_frame(&self) -> bool {
        self.saw_unsupported
    }

    /// Envelopes to put on the wire now — see [`Channel::poll_transmit`].
    pub fn poll_transmit(&mut self, now: u64) -> Vec<Envelope> {
        self.channel.poll_transmit(now)
    }

    /// Feed a received envelope in — see [`Channel::handle`]. Returns whether the driver
    /// should prove the packet (`false` when the reorder buffer is full).
    #[must_use]
    pub fn handle(&mut self, envelope: Envelope) -> bool {
        self.channel.handle(envelope)
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
    use super::{
        Buffer, Channel, DEFAULT_RETX_TIMEOUT, Envelope, MAX_DATA_LEN, STREAM_ID_MAX,
        STREAM_MSGTYPE, StreamFrame, WINDOW_INITIAL,
    };
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
            let env = Envelope {
                msgtype,
                sequence,
                payload,
            };
            assert_eq!(
                hex_str(&env.encode()),
                expected,
                "encode must equal RNS pack()"
            );
            assert_eq!(Envelope::decode(&env.encode()), Some(env), "round-trip");
        }
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
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
                let _ = rx.handle(e);
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
        let payload: Vec<u8> = (0..4000u32)
            .map(|i| (i.wrapping_mul(31).wrapping_add(7)) as u8)
            .collect();
        let mut tx = Buffer::new();
        let mut rx = Buffer::new();
        tx.write(&payload);

        let mut fwd = LossModel::new(seed)
            .drop_per_mille(drop_per_mille)
            .max_delay_ms(max_delay_ticks);
        let mut bwd = LossModel::new(seed ^ 0xFFFF)
            .drop_per_mille(drop_per_mille)
            .max_delay_ms(max_delay_ticks);

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
                    let _ = rx.handle(e);
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

    /// Count how many envelopes `channel` puts on the wire to deliver `messages` messages over
    /// a lossless pipe whose one-way delay is `rtt/2` ticks (so a data->proof round trip is
    /// `rtt` ticks). Each sequence's proof returns once, `rtt` ticks after its first send;
    /// retransmits issued before then are the waste this measures.
    fn transmissions_over_rtt(mut channel: Channel, rtt: u64, messages: usize) -> usize {
        use std::collections::{BTreeMap, HashSet};
        for m in 0..messages {
            channel.send(vec![m as u8]);
        }
        let mut proof_at: BTreeMap<u64, Vec<u16>> = BTreeMap::new();
        let mut scheduled: HashSet<u16> = HashSet::new();
        let mut total = 0usize;
        for now in 0..2_000_000u64 {
            if let Some(seqs) = proof_at.remove(&now) {
                for s in seqs {
                    channel.on_proof(s, now);
                }
            }
            for env in channel.poll_transmit(now) {
                total += 1;
                if scheduled.insert(env.sequence) {
                    proof_at.entry(now + rtt).or_default().push(env.sequence);
                }
            }
            if channel.send_idle() {
                break;
            }
        }
        assert!(channel.send_idle(), "the transfer completed");
        total
    }

    /// The adaptive retransmit timeout must not storm a slow medium. Over a 1000-tick round
    /// trip, the dynamic channel keys its timeout off the measured RTT and sends close to one
    /// transmission per message; a fixed 4-tick timeout retransmits each packet hundreds of
    /// times before its proof can return. This is the fix for the RF finding, measured.
    #[test]
    fn adaptive_timeout_does_not_storm_a_high_rtt_link() {
        let messages = 16;
        let rtt = 1000;

        let adaptive = transmissions_over_rtt(Channel::new(STREAM_MSGTYPE), rtt, messages);
        let fixed_tiny = transmissions_over_rtt(
            Channel::with_params(STREAM_MSGTYPE, 8, DEFAULT_RETX_TIMEOUT),
            rtt,
            messages,
        );

        // The adaptive channel sends roughly one frame per message (a small startup burst is
        // allowed while its RTT estimate settles).
        assert!(
            adaptive < messages * 3,
            "adaptive sent {adaptive} for {messages} messages (should be near {messages})"
        );
        // The fixed tiny timeout storms: an order of magnitude more, and far worse than adaptive.
        assert!(
            fixed_tiny > messages * 10,
            "fixed-4 sent {fixed_tiny}, expected a retransmit storm"
        );
        assert!(
            fixed_tiny > adaptive * 5,
            "adaptive {adaptive} should be dramatically leaner than fixed {fixed_tiny}"
        );
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
                let _ = rx.handle(e);
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
        assert!(
            c.window() > WINDOW_INITIAL,
            "window grew (got {})",
            c.window()
        );
        assert!(
            c.window() >= 16,
            "climbed into the fast tier (got {})",
            c.window()
        );
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
        assert!(
            grown > 20,
            "window grew well above the floor first (got {})",
            grown
        );

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

    #[test]
    fn stream_frame_matches_rns_capture() {
        // Gold test: retinue's StreamFrame encoding equals RNS 1.3.8's own
        // StreamDataMessage.pack() for every captured vector, and our constants match.
        let fixture = include_str!("../tests/fixtures/buffer_wire.json");
        let doc: serde_json::Value = serde_json::from_str(fixture).unwrap();
        let c = &doc["constants"];
        assert_eq!(c["MSGTYPE"].as_u64().unwrap() as u16, STREAM_MSGTYPE);
        assert_eq!(c["STREAM_ID_MAX"].as_u64().unwrap() as u16, STREAM_ID_MAX);
        assert_eq!(c["MAX_DATA_LEN"].as_u64().unwrap() as usize, MAX_DATA_LEN);
        for v in doc["frame_vectors"].as_array().unwrap() {
            let frame = StreamFrame {
                stream_id: v["stream_id"].as_u64().unwrap() as u16,
                eof: v["eof"].as_bool().unwrap(),
                compressed: v["compressed"].as_bool().unwrap(),
                data: hex_bytes(v["data_hex"].as_str().unwrap()),
            };
            let expected = v["packed_hex"].as_str().unwrap();
            assert_eq!(
                hex_str(&frame.encode()),
                expected,
                "encode must equal RNS pack()"
            );
            assert_eq!(
                StreamFrame::decode(&frame.encode()),
                Some(frame),
                "round-trip"
            );
        }
    }

    #[test]
    fn buffer_demuxes_by_stream_id_and_signals_eof() {
        // One channel carries two streams (RNS multiplexes above the sequence). A reader
        // bound to stream 5 delivers only stream 5's bytes in order, ignores stream 9,
        // and reports eof from stream 5 — not from stream 9's earlier eof.
        let mut r5 = Buffer::with_streams(Channel::new(STREAM_MSGTYPE), 8, 0, 5);
        let feed = |r: &mut Buffer, seq: u16, f: StreamFrame| {
            let _ = r.handle(Envelope {
                msgtype: STREAM_MSGTYPE,
                sequence: seq,
                payload: f.encode(),
            });
        };
        feed(
            &mut r5,
            0,
            StreamFrame {
                stream_id: 5,
                eof: false,
                compressed: false,
                data: vec![1, 2, 3],
            },
        );
        feed(
            &mut r5,
            1,
            StreamFrame {
                stream_id: 9,
                eof: false,
                compressed: false,
                data: vec![0xAA],
            },
        );
        feed(
            &mut r5,
            2,
            StreamFrame {
                stream_id: 5,
                eof: false,
                compressed: false,
                data: vec![4, 5],
            },
        );
        feed(
            &mut r5,
            3,
            StreamFrame {
                stream_id: 9,
                eof: true,
                compressed: false,
                data: vec![],
            },
        );
        assert!(!r5.recv_finished(), "stream 9's eof must not end stream 5");
        feed(
            &mut r5,
            4,
            StreamFrame {
                stream_id: 5,
                eof: true,
                compressed: false,
                data: vec![6],
            },
        );
        assert_eq!(
            r5.read_available(),
            vec![1, 2, 3, 4, 5, 6],
            "only stream 5, in order"
        );
        assert!(r5.recv_finished(), "stream 5's eof");
    }

    #[test]
    fn compressed_frame_is_flagged_not_corrupting() {
        // retinue can't decode a bz2-compressed frame yet. It must drop those bytes and
        // surface it, never splice compressed bytes into the stream as if they were data.
        let mut r = Buffer::with_streams(Channel::new(STREAM_MSGTYPE), 8, 0, 0);
        let feed = |r: &mut Buffer, seq: u16, f: StreamFrame| {
            let _ = r.handle(Envelope {
                msgtype: STREAM_MSGTYPE,
                sequence: seq,
                payload: f.encode(),
            });
        };
        feed(
            &mut r,
            0,
            StreamFrame {
                stream_id: 0,
                eof: false,
                compressed: false,
                data: vec![1, 2],
            },
        );
        feed(
            &mut r,
            1,
            StreamFrame {
                stream_id: 0,
                eof: false,
                compressed: true,
                data: vec![9, 9, 9],
            },
        );
        feed(
            &mut r,
            2,
            StreamFrame {
                stream_id: 0,
                eof: false,
                compressed: false,
                data: vec![3],
            },
        );
        assert_eq!(
            r.read_available(),
            vec![1, 2, 3],
            "compressed bytes dropped, not appended"
        );
        assert!(
            r.had_unsupported_frame(),
            "the compressed frame was surfaced"
        );
    }

    #[test]
    fn buffer_stream_round_trips_with_finish() {
        // The everyday path: write a payload and finish() over the lossless proof model;
        // the reader reconstructs it exactly and sees eof.
        let mut tx = Buffer::with_streams(Channel::new(STREAM_MSGTYPE), MAX_DATA_LEN, 3, 3);
        let mut rx = Buffer::with_streams(Channel::new(STREAM_MSGTYPE), MAX_DATA_LEN, 3, 3);
        let payload: Vec<u8> = (0..2000u32).map(|i| (i * 7 + 1) as u8).collect();
        tx.write(&payload);
        tx.finish();
        let mut got = Vec::new();
        for now in 0..100_000u64 {
            let envs = tx.poll_transmit(now);
            if envs.is_empty() && tx.send_idle() {
                break;
            }
            for e in envs {
                let seq = e.sequence;
                let _ = rx.handle(e);
                tx.on_proof(seq, now);
            }
            got.extend(rx.read_available());
        }
        got.extend(rx.read_available());
        assert_eq!(got, payload, "stream reconstructs exactly");
        assert!(rx.recv_finished(), "reader saw the writer's eof");
    }
}
