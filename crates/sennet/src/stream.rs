//! The serial/TCP Stream API framing.
//!
//! A publicly documented byte layout used to carry protobuf packets over a serial or TCP
//! byte stream: a two-byte magic, a big-endian 16-bit length, then that many payload bytes.
//!
//! ```text
//! [0x94] [0xc3] [len_hi] [len_lo] [payload: len bytes]
//! ```
//!
//! This module is derived only from the public description of that frame format and from
//! Google's public protobuf wire standard; no third-party source was consulted. It is the
//! transport analog of [`tulle::kiss`](https://github.com/mark-ik/tulle) for the mesh this
//! crate interoperates with.

/// First magic byte of a stream frame.
pub const START1: u8 = 0x94;
/// Second magic byte of a stream frame.
pub const START2: u8 = 0xc3;
/// Largest payload a single frame carries in the documented format.
pub const MAX_PAYLOAD: usize = 512;

/// Wrap `payload` in a stream frame: magic, big-endian length, bytes.
///
/// # Panics
/// If `payload` exceeds [`MAX_PAYLOAD`].
pub fn encode(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= MAX_PAYLOAD, "payload exceeds MAX_PAYLOAD");
    let mut out = Vec::with_capacity(4 + payload.len());
    out.push(START1);
    out.push(START2);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// A streaming deframer: fed raw bytes, it yields complete payloads.
///
/// It resynchronizes on the two-byte magic (a stream also carries plain-text debug lines that
/// are not frames), and rejects a declared length beyond [`MAX_PAYLOAD`] by dropping the magic
/// and resuming the search, so a corrupt or non-frame stream cannot mislead it or grow memory.
pub struct Deframer {
    buf: Vec<u8>,
}

impl Deframer {
    pub fn new() -> Self {
        Deframer { buf: Vec::new() }
    }

    /// Consume `bytes`, appending any completed payloads to `out`.
    pub fn push(&mut self, bytes: &[u8], out: &mut Vec<Vec<u8>>) {
        self.buf.extend_from_slice(bytes);
        loop {
            // Find the frame start; discard anything before it (debug text, noise).
            let Some(start) = find_magic(&self.buf) else {
                // Keep only a trailing partial magic (a lone START1 at the very end).
                if self.buf.last() == Some(&START1) {
                    let last = self.buf.len() - 1;
                    self.buf.drain(..last);
                } else {
                    self.buf.clear();
                }
                return;
            };
            if start > 0 {
                self.buf.drain(..start);
            }
            // Need magic + length before we can know the frame size.
            if self.buf.len() < 4 {
                return;
            }
            let len = u16::from_be_bytes([self.buf[2], self.buf[3]]) as usize;
            if len > MAX_PAYLOAD {
                // Not a real frame: drop this magic and resync past it.
                self.buf.drain(..2);
                continue;
            }
            if self.buf.len() < 4 + len {
                return; // frame not fully arrived yet
            }
            out.push(self.buf[4..4 + len].to_vec());
            self.buf.drain(..4 + len);
        }
    }
}

impl Default for Deframer {
    fn default() -> Self {
        Self::new()
    }
}

/// Index of the first `START1 START2` pair in `buf`, if any.
fn find_magic(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == [START1, START2])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deframe_all(d: &mut Deframer, bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        d.push(bytes, &mut out);
        out
    }

    #[test]
    fn round_trips_one_frame() {
        let payload = b"\x08\x01\x12\x03abc";
        let wire = encode(payload);
        assert_eq!(&wire[..2], &[START1, START2]);
        assert_eq!(&wire[2..4], &(payload.len() as u16).to_be_bytes());
        let mut d = Deframer::new();
        assert_eq!(deframe_all(&mut d, &wire), vec![payload.to_vec()]);
    }

    #[test]
    fn skips_leading_debug_text_before_a_frame() {
        let mut wire = b"INFO some log line\r\n".to_vec();
        wire.extend_from_slice(&encode(b"payload here"));
        let mut d = Deframer::new();
        assert_eq!(deframe_all(&mut d, &wire), vec![b"payload here".to_vec()]);
    }

    #[test]
    fn reassembles_across_chunked_reads() {
        let wire = encode(&vec![0xAB; 300]);
        let mut d = Deframer::new();
        let mut out = Vec::new();
        for chunk in wire.chunks(17) {
            d.push(chunk, &mut out);
        }
        assert_eq!(out, vec![vec![0xAB; 300]]);
    }

    #[test]
    fn back_to_back_frames() {
        let mut wire = encode(b"one");
        wire.extend_from_slice(&encode(b"two"));
        let mut d = Deframer::new();
        assert_eq!(
            deframe_all(&mut d, &wire),
            vec![b"one".to_vec(), b"two".to_vec()]
        );
    }

    #[test]
    fn a_false_magic_with_huge_length_is_resynced_past() {
        // 0x94 0xc3 followed by a length > MAX_PAYLOAD is not a real frame.
        let mut wire = vec![START1, START2, 0xFF, 0xFF, 0x00];
        wire.extend_from_slice(&encode(b"real"));
        let mut d = Deframer::new();
        assert_eq!(deframe_all(&mut d, &wire), vec![b"real".to_vec()]);
    }

    #[test]
    fn a_split_magic_at_the_buffer_end_is_held() {
        let mut d = Deframer::new();
        // A lone START1 arrives; nothing yet.
        assert!(deframe_all(&mut d, &[0x00, START1]).is_empty());
        // The rest of the frame arrives next.
        let mut out = Vec::new();
        d.push(&[START2, 0x00, 0x02, b'h', b'i'], &mut out);
        assert_eq!(out, vec![b"hi".to_vec()]);
    }
}
