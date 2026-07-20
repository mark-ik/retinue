//! KISS framing (the public amateur-radio spec RNode framing builds on).
//!
//! `FEND` (0xC0) delimits frames; a literal 0xC0 inside a frame is escaped as
//! `FESC TFEND` and a literal `FESC` (0xDB) as `FESC TFESC`. Everything about
//! frame *contents* (RNode's command byte and opcode set) lives above this
//! module and is pinned by hardware capture, not assumed.

pub const FEND: u8 = 0xC0;
pub const FESC: u8 = 0xDB;
pub const TFEND: u8 = 0xDC;
pub const TFESC: u8 = 0xDD;

/// Encode one frame: leading + trailing FEND, contents escaped.
pub fn encode(frame: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(frame.len() + 2);
    out.push(FEND);
    for &b in frame {
        match b {
            FEND => out.extend_from_slice(&[FESC, TFEND]),
            FESC => out.extend_from_slice(&[FESC, TFESC]),
            _ => out.push(b),
        }
    }
    out.push(FEND);
    out
}

/// Streaming deframer with a bounded frame size.
///
/// Feed raw serial bytes in; complete frames come out. Frames that exceed
/// `max_frame` are discarded and the deframer resyncs at the next FEND, so a
/// corrupt stream cannot balloon memory. Invalid escape sequences discard the
/// frame for the same reason.
pub struct Deframer {
    buf: Vec<u8>,
    max_frame: usize,
    in_escape: bool,
    overflowed: bool,
}

impl Deframer {
    pub fn new(max_frame: usize) -> Self {
        Deframer {
            buf: Vec::new(),
            max_frame,
            in_escape: false,
            overflowed: false,
        }
    }

    /// Consume raw bytes, appending any completed frames to `out`.
    pub fn push(&mut self, bytes: &[u8], out: &mut Vec<Vec<u8>>) {
        for &b in bytes {
            if b == FEND {
                if !self.overflowed && !self.in_escape && !self.buf.is_empty() {
                    out.push(std::mem::take(&mut self.buf));
                } else {
                    self.buf.clear();
                }
                self.in_escape = false;
                self.overflowed = false;
                continue;
            }
            if self.overflowed {
                continue; // discard until the next FEND
            }
            let decoded = if self.in_escape {
                self.in_escape = false;
                match b {
                    TFEND => FEND,
                    TFESC => FESC,
                    _ => {
                        // invalid escape: poison the frame, resync at FEND
                        self.overflowed = true;
                        continue;
                    }
                }
            } else if b == FESC {
                self.in_escape = true;
                continue;
            } else {
                b
            };
            if self.buf.len() >= self.max_frame {
                self.overflowed = true;
                self.buf.clear();
            } else {
                self.buf.push(decoded);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deframe_all(deframer: &mut Deframer, bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        deframer.push(bytes, &mut out);
        out
    }

    #[test]
    fn roundtrip_plain() {
        let frame = b"\x01hello radio";
        let wire = encode(frame);
        let mut d = Deframer::new(512);
        let got = deframe_all(&mut d, &wire);
        assert_eq!(got, vec![frame.to_vec()]);
    }

    #[test]
    fn roundtrip_with_escapes() {
        let frame = vec![FEND, 0x42, FESC, FEND, FESC];
        let wire = encode(&frame);
        assert!(!wire[1..wire.len() - 1].contains(&FEND));
        let mut d = Deframer::new(512);
        assert_eq!(deframe_all(&mut d, &wire), vec![frame]);
    }

    #[test]
    fn split_across_pushes() {
        let frame = vec![9u8; 40];
        let wire = encode(&frame);
        let mut d = Deframer::new(512);
        let mut out = Vec::new();
        for chunk in wire.chunks(7) {
            d.push(chunk, &mut out);
        }
        assert_eq!(out, vec![frame]);
    }

    #[test]
    fn back_to_back_frames_share_fend() {
        // ... FEND a FEND b FEND: middle FEND ends one frame and opens the next
        let mut wire = encode(b"aa");
        wire.extend_from_slice(&encode(b"bb")[1..]); // drop duplicated FEND
        let mut d = Deframer::new(512);
        assert_eq!(
            deframe_all(&mut d, &wire),
            vec![b"aa".to_vec(), b"bb".to_vec()]
        );
    }

    #[test]
    fn oversize_frame_discarded_and_resyncs() {
        let big = vec![1u8; 600];
        let ok = b"fine".to_vec();
        let mut wire = encode(&big);
        wire.extend_from_slice(&encode(&ok));
        let mut d = Deframer::new(512);
        assert_eq!(deframe_all(&mut d, &wire), vec![ok]);
    }

    #[test]
    fn invalid_escape_discards_frame() {
        let wire = [FEND, 0x01, FESC, 0x99, 0x02, FEND, 0x33, FEND];
        let mut d = Deframer::new(512);
        assert_eq!(deframe_all(&mut d, &wire), vec![vec![0x33]]);
    }

    #[test]
    fn idle_fends_produce_nothing() {
        let mut d = Deframer::new(512);
        assert!(deframe_all(&mut d, &[FEND, FEND, FEND]).is_empty());
    }
}
