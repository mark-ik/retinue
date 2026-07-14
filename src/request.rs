//! Requests and responses over a link.
//!
//! A thin protocol RNS layers on the link data channel. A request names a path and carries
//! opaque bytes; a response echoes the request's id and carries opaque bytes back. Both are
//! msgpack arrays:
//!
//! ```text
//! request  = [ time: f64, path_hash: bin(16), data: bin ]
//! response = [ request_id: bin(16), data: bin ]
//! ```
//!
//! where `path_hash = trunc16(SHA256(path))` and `request_id` is the request packet's hash
//! ([`Packet::hash`](crate::packet::Packet::hash)). Verified against RNS 1.3.8; see
//! `oracle/capture_reqresp*.py`.
//!
//! retinue treats the request and response data as opaque byte strings. RNS can carry any
//! msgpack value there; a consumer that needs structure layers its own encoding on top,
//! which keeps retinue a transport rather than an application.
//!
//! The msgpack handled here is only what these two shapes need: a fixarray, one float64,
//! and byte strings (`bin8`/`bin16`/`bin32`, and `nil` decoded as empty). Anything else is
//! a [`Error::BadRequest`].

use crate::hash::AddressHash;
use crate::{Error, Result};

/// A request: a path and its opaque data.
#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    /// `trunc16(SHA256(path))`. The plaintext path is not recoverable from it.
    pub path_hash: AddressHash,
    pub data: Vec<u8>,
    /// The sender's wall-clock time when the request was made, as RNS records it. Not
    /// load-bearing for retinue; carried for fidelity.
    pub time: f64,
}

impl Request {
    /// Build a request for `path`, hashing it.
    pub fn new(path: &[u8], data: Vec<u8>, time: f64) -> Self {
        Self {
            path_hash: AddressHash::of(path),
            data,
            time,
        }
    }

    /// msgpack `[time, path_hash, data]`.
    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0x93); // fixarray, 3
        write_f64(&mut out, self.time);
        write_bin(&mut out, self.path_hash.as_slice());
        write_bin(&mut out, &self.data);
        out
    }

    /// Parse msgpack `[time, path_hash, data]`.
    pub fn unpack(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        if r.array_header()? != 3 {
            return Err(Error::BadRequest);
        }
        let time = r.f64()?;
        let path = r.bin()?;
        let path_hash = AddressHash::from_slice(path).ok_or(Error::BadRequest)?;
        let data = r.bin()?.to_vec();
        Ok(Self {
            path_hash,
            data,
            time,
        })
    }
}

/// A response: the id of the request it answers, and its opaque data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub request_id: AddressHash,
    pub data: Vec<u8>,
}

impl Response {
    pub fn new(request_id: AddressHash, data: Vec<u8>) -> Self {
        Self { request_id, data }
    }

    /// msgpack `[request_id, data]`.
    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0x92); // fixarray, 2
        write_bin(&mut out, self.request_id.as_slice());
        write_bin(&mut out, &self.data);
        out
    }

    /// Parse msgpack `[request_id, data]`.
    pub fn unpack(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        if r.array_header()? != 2 {
            return Err(Error::BadRequest);
        }
        let id = r.bin()?;
        let request_id = AddressHash::from_slice(id).ok_or(Error::BadRequest)?;
        let data = r.bin()?.to_vec();
        Ok(Self { request_id, data })
    }
}

// --- the sliver of msgpack these two shapes need ---

fn write_f64(out: &mut Vec<u8>, v: f64) {
    out.push(0xcb);
    out.extend_from_slice(&v.to_be_bytes());
}

fn write_bin(out: &mut Vec<u8>, b: &[u8]) {
    match b.len() {
        n if n <= u8::MAX as usize => {
            out.push(0xc4);
            out.push(n as u8);
        }
        n if n <= u16::MAX as usize => {
            out.push(0xc5);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(0xc6);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
    }
    out.extend_from_slice(b);
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let s = self.b.get(self.i..self.i + n).ok_or(Error::BadRequest)?;
        self.i += n;
        Ok(s)
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn array_header(&mut self) -> Result<usize> {
        let tag = self.byte()?;
        match tag {
            0x90..=0x9f => Ok((tag & 0x0f) as usize),
            0xdc => {
                let n = self.take(2)?;
                Ok(u16::from_be_bytes([n[0], n[1]]) as usize)
            }
            _ => Err(Error::BadRequest),
        }
    }

    fn f64(&mut self) -> Result<f64> {
        match self.byte()? {
            0xcb => {
                let n = self.take(8)?;
                Ok(f64::from_be_bytes(n.try_into().expect("8 bytes")))
            }
            0xca => {
                let n = self.take(4)?;
                Ok(f32::from_be_bytes(n.try_into().expect("4 bytes")) as f64)
            }
            _ => Err(Error::BadRequest),
        }
    }

    fn bin(&mut self) -> Result<&'a [u8]> {
        let tag = self.byte()?;
        let len = match tag {
            0xc0 => return Ok(&[]), // nil, treated as empty
            0xc4 => self.byte()? as usize,
            0xc5 => {
                let n = self.take(2)?;
                u16::from_be_bytes([n[0], n[1]]) as usize
            }
            0xc6 => {
                let n = self.take(4)?;
                u32::from_be_bytes([n[0], n[1], n[2], n[3]]) as usize
            }
            // Some senders use str types for byte data; accept the str family too.
            0xa0..=0xbf => (tag & 0x1f) as usize,
            0xd9 => self.byte()? as usize,
            _ => return Err(Error::BadRequest),
        };
        self.take(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let r = Request::new(b"/echo", b"ping123".to_vec(), 1784048181.092014);
        let packed = r.pack();
        assert_eq!(Request::unpack(&packed).unwrap(), r);
    }

    #[test]
    fn response_round_trips() {
        let r = Response::new(AddressHash::from_bytes([0xAB; 16]), b"pong".to_vec());
        assert_eq!(Response::unpack(&r.pack()).unwrap(), r);
    }

    #[test]
    fn path_hash_matches_rns() {
        // From capture_reqresp.py: /echo -> cb9c1f54d8102d68b7a40c2376e1f0e8
        assert_eq!(
            AddressHash::of(b"/echo").to_string(),
            "cb9c1f54d8102d68b7a40c2376e1f0e8",
        );
    }

    #[test]
    fn large_data_uses_bin16() {
        let big = vec![7u8; 1000];
        let r = Request::new(b"/x", big.clone(), 0.0);
        let round = Request::unpack(&r.pack()).unwrap();
        assert_eq!(round.data, big);
    }
}
