//! HDLC framing, as used by Reticulum's TCP interfaces.
//!
//! A stream is a sequence of frames delimited by the flag byte. Inside a frame, the flag
//! and the escape byte are themselves escaped by emitting the escape byte followed by the
//! original XORed with a mask:
//!
//! ```text
//! flag   0x7E   delimits frames
//! escape 0x7D
//! mask   0x20   0x7E -> 7D 5E     0x7D -> 7D 5D
//! ```
//!
//! Verified against RNS 1.3.8 by capture, not assumed. The flag escape shows up
//! unprompted, because the fixture destination hash happens to contain a `0x7E`:
//!
//! ```text
//! packet: a8 72 5a 7e 21 2d ...
//! wire:   a8 72 5a 7d 5e 21 2d ...
//! ```
//!
//! The escape-byte rule was pinned by asking RNS directly: announcing `app_data` of
//! `7e 7d 7e 7d 00 ff` puts `7d5e 7d5d 7d5e 7d5d 00 ff` on the wire. Both special bytes are
//! escaped. See `oracle/capture_tcp.py` and `tests/fixtures/tcp_stream.bin`.
//!
//! This module is sans-io: [`frame`] is a pure function, and [`Deframer`] is a state
//! machine fed arbitrary byte chunks, because TCP does not respect frame boundaries.

/// Delimits frames.
pub const FLAG: u8 = 0x7E;

/// Introduces an escaped byte.
pub const ESC: u8 = 0x7D;

/// An escaped byte is XORed with this.
pub const ESC_MASK: u8 = 0x20;

/// Largest deframed frame the [`Deframer`] will assemble before discarding it. A valid
/// Reticulum packet is at most the wire MTU (the decoder rejects anything larger), so this
/// caps how much a peer can make us buffer by withholding the closing flag.
const MAX_FRAME: usize = crate::packet::MTU;

/// Wrap a packet in a frame, escaping as needed.
pub fn frame(packet: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(packet.len() + 2);
    out.push(FLAG);
    for &b in packet {
        if b == FLAG || b == ESC {
            out.push(ESC);
            out.push(b ^ ESC_MASK);
        } else {
            out.push(b);
        }
    }
    out.push(FLAG);
    out
}

/// Reassembles frames from a byte stream.
///
/// TCP hands us arbitrary chunks, so a frame can be split across any number of reads and a
/// read can contain several frames. Feed everything to [`push`](Deframer::push) and take
/// whatever frames fall out.
///
/// Empty frames (two adjacent flags, which RNS does emit between packets) are discarded
/// rather than surfaced.
#[derive(Debug, Default)]
pub struct Deframer {
    buf: Vec<u8>,
    in_frame: bool,
    escaped: bool,
}

impl Deframer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed a chunk of stream, and get back every complete frame it finished.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        for &b in chunk {
            if b == FLAG {
                // A flag both closes any open frame and opens the next one, so a run of
                // flags is harmless.
                if self.in_frame && !self.buf.is_empty() {
                    frames.push(core::mem::take(&mut self.buf));
                }
                self.buf.clear();
                self.in_frame = true;
                self.escaped = false;
                continue;
            }
            if !self.in_frame {
                // Junk before the first flag. Ignore it rather than guessing.
                continue;
            }
            if self.escaped {
                self.buf.push(b ^ ESC_MASK);
                self.escaped = false;
            } else if b == ESC {
                self.escaped = true;
            } else {
                self.buf.push(b);
            }
            // A valid Reticulum packet is at most the wire MTU, so a frame growing past it is
            // malformed — or a peer withholding the closing flag to make us buffer without
            // bound. Discard it and resynchronise at the next flag.
            if self.buf.len() > MAX_FRAME {
                self.buf.clear();
                self.in_frame = false;
            }
        }
        frames
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_without_special_bytes() {
        let packet = b"no special bytes here";
        let framed = frame(packet);
        assert_eq!(framed[0], FLAG);
        assert_eq!(*framed.last().unwrap(), FLAG);

        let mut d = Deframer::new();
        assert_eq!(d.push(&framed), vec![packet.to_vec()]);
    }

    #[test]
    fn both_special_bytes_are_escaped() {
        let framed = frame(&[0x7E, 0x7D, 0x00]);
        assert_eq!(framed, vec![FLAG, 0x7D, 0x5E, 0x7D, 0x5D, 0x00, FLAG]);

        let mut d = Deframer::new();
        assert_eq!(d.push(&framed), vec![vec![0x7E, 0x7D, 0x00]]);
    }

    /// TCP splits wherever it likes, including in the middle of an escape sequence.
    #[test]
    fn a_frame_split_across_chunks_reassembles() {
        let packet = [0x01, 0x7E, 0x02, 0x7D, 0x03];
        let framed = frame(&packet);

        let mut d = Deframer::new();
        let mut got = Vec::new();
        // One byte at a time: the worst case, and it must still work.
        for &b in &framed {
            got.extend(d.push(&[b]));
        }
        assert_eq!(got, vec![packet.to_vec()]);
    }

    #[test]
    fn adjacent_flags_do_not_produce_empty_frames() {
        let mut d = Deframer::new();
        let frames = d.push(&[FLAG, FLAG, 0x01, 0x02, FLAG, FLAG]);
        assert_eq!(frames, vec![vec![0x01, 0x02]]);
    }

    #[test]
    fn junk_before_the_first_flag_is_ignored() {
        let mut d = Deframer::new();
        let mut stream = vec![0xAA, 0xBB];
        stream.extend(frame(b"ok"));
        assert_eq!(d.push(&stream), vec![b"ok".to_vec()]);
    }

    /// A peer that opens a frame and streams bytes without ever sending the closing flag must
    /// not make us buffer without bound. The over-length frame is discarded, and a normal
    /// frame after the next flag still parses — the deframer resynchronises.
    #[test]
    fn an_unbounded_frame_is_discarded_and_resynchronises() {
        let mut d = Deframer::new();
        // Open a frame, then feed well past MAX_FRAME with no closing flag.
        d.push(&[FLAG]);
        let flood = vec![0x00u8; MAX_FRAME * 4];
        assert!(d.push(&flood).is_empty(), "no frame completes");
        // The internal buffer stayed bounded rather than holding all the flood.
        assert!(d.buf.len() <= MAX_FRAME, "buffer is capped at MAX_FRAME");
        // A genuine frame after the next flag is delivered intact.
        assert_eq!(d.push(&frame(b"after")), vec![b"after".to_vec()]);
    }
}
