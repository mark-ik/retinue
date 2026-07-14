//! Resources: segmented transfer of large payloads over a link.
//!
//! **Status: the advertisement is implemented and verified; the transfer state machine is
//! not.** A full resource transfer is a windowed protocol (see the RNS constants: `WINDOW`,
//! `SDU = 464`, `MAPHASH_LEN = 4`, hashmap updates, retries, proofs) with bz2 compression.
//! This module currently models the advertisement, which is the packet that opens every
//! transfer, so the rest can be built on a verified foundation. See the wire reference,
//! section 0.2, for the full protocol as reversed from capture.
//!
//! The advertisement is a msgpack map. Its keys are single letters; the meanings below are
//! from decoding a real RNS 1.3.8 advertisement:
//!
//! ```text
//! t  transfer size   (bytes on the wire, after compression)
//! d  data size       (uncompressed)
//! n  parts           (number of segments)
//! h  resource hash   (32)
//! o  original hash   (32, of the uncompressed data)
//! r  random hash     (4)
//! f  flags
//! m  hashmap         (MAPHASH_LEN = 4 bytes per part)
//! i, l, q            carried opaque (interleave / split / request), not yet interpreted
//! ```

use crate::{Error, Result};

/// Bytes of a part's map hash in the advertisement hashmap.
pub const MAPHASH_LEN: usize = 4;

/// A resource transfer advertisement.
///
/// Fields that retinue does not yet interpret (`i`, `l`, `q`) are preserved so an
/// advertisement round-trips exactly, which keeps hashing and signatures over it stable.
#[derive(Clone, Debug, PartialEq)]
pub struct Advertisement {
    /// `t`: size on the wire after compression.
    pub transfer_size: u64,
    /// `d`: uncompressed data size.
    pub data_size: u64,
    /// `n`: number of parts.
    pub parts: u64,
    /// `h`: the resource hash.
    pub resource_hash: Vec<u8>,
    /// `o`: the hash of the uncompressed data.
    pub original_hash: Vec<u8>,
    /// `r`: a random hash for uniqueness.
    pub random_hash: Vec<u8>,
    /// `f`: flags.
    pub flags: u64,
    /// `m`: the hashmap, `MAPHASH_LEN` bytes per part.
    pub hashmap: Vec<u8>,
    /// `i`, carried opaque.
    pub i: i64,
    /// `l`, carried opaque.
    pub l: i64,
    /// `q`, carried opaque (present-but-nil is `None`).
    pub q: Option<i64>,
}

impl Advertisement {
    /// Parse an advertisement from its msgpack map.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut r = MapReader::new(bytes);
        let n = r.map_header()?;

        let mut transfer_size = None;
        let mut data_size = None;
        let mut parts = None;
        let mut resource_hash = None;
        let mut original_hash = None;
        let mut random_hash = None;
        let mut flags = None;
        let mut hashmap = None;
        let mut i = None;
        let mut l = None;
        let mut q = None;

        for _ in 0..n {
            let key = r.str_key()?;
            match key {
                b't' => transfer_size = Some(r.uint()?),
                b'd' => data_size = Some(r.uint()?),
                b'n' => parts = Some(r.uint()?),
                b'h' => resource_hash = Some(r.bin()?.to_vec()),
                b'o' => original_hash = Some(r.bin()?.to_vec()),
                b'r' => random_hash = Some(r.bin()?.to_vec()),
                b'f' => flags = Some(r.uint()?),
                b'm' => hashmap = Some(r.bin()?.to_vec()),
                b'i' => i = Some(r.int()?),
                b'l' => l = Some(r.int()?),
                b'q' => q = r.int_or_nil()?,
                _ => r.skip_value()?,
            }
        }

        Ok(Self {
            transfer_size: transfer_size.ok_or(Error::BadRequest)?,
            data_size: data_size.ok_or(Error::BadRequest)?,
            parts: parts.ok_or(Error::BadRequest)?,
            resource_hash: resource_hash.ok_or(Error::BadRequest)?,
            original_hash: original_hash.ok_or(Error::BadRequest)?,
            random_hash: random_hash.ok_or(Error::BadRequest)?,
            flags: flags.ok_or(Error::BadRequest)?,
            hashmap: hashmap.ok_or(Error::BadRequest)?,
            i: i.ok_or(Error::BadRequest)?,
            l: l.ok_or(Error::BadRequest)?,
            q,
        })
    }

    /// Serialise to the msgpack map, in RNS's key order.
    pub fn pack(&self) -> Vec<u8> {
        let mut w = MapWriter::new(11);
        w.str_key(b't');
        w.uint(self.transfer_size);
        w.str_key(b'd');
        w.uint(self.data_size);
        w.str_key(b'n');
        w.uint(self.parts);
        w.str_key(b'h');
        w.bin(&self.resource_hash);
        w.str_key(b'r');
        w.bin(&self.random_hash);
        w.str_key(b'o');
        w.bin(&self.original_hash);
        w.str_key(b'i');
        w.int(self.i);
        w.str_key(b'l');
        w.int(self.l);
        w.str_key(b'q');
        match self.q {
            Some(v) => w.int(v),
            None => w.nil(),
        }
        w.str_key(b'f');
        w.uint(self.flags);
        w.str_key(b'm');
        w.bin(&self.hashmap);
        w.finish()
    }

    /// The number of parts named in the hashmap.
    pub fn hashmap_parts(&self) -> usize {
        self.hashmap.len() / MAPHASH_LEN
    }
}

// --- a small msgpack map codec, enough for the advertisement ---

struct MapWriter {
    out: Vec<u8>,
}

impl MapWriter {
    fn new(entries: usize) -> Self {
        let mut out = Vec::new();
        assert!(entries < 16, "advertisement fits in a fixmap");
        out.push(0x80 | entries as u8);
        Self { out }
    }
    fn str_key(&mut self, k: u8) {
        self.out.push(0xa1); // fixstr, len 1
        self.out.push(k);
    }
    fn uint(&mut self, v: u64) {
        if v < 0x80 {
            self.out.push(v as u8);
        } else if v <= u8::MAX as u64 {
            self.out.push(0xcc);
            self.out.push(v as u8);
        } else if v <= u16::MAX as u64 {
            self.out.push(0xcd);
            self.out.extend_from_slice(&(v as u16).to_be_bytes());
        } else if v <= u32::MAX as u64 {
            self.out.push(0xce);
            self.out.extend_from_slice(&(v as u32).to_be_bytes());
        } else {
            self.out.push(0xcf);
            self.out.extend_from_slice(&v.to_be_bytes());
        }
    }
    fn int(&mut self, v: i64) {
        if (0..0x80).contains(&v) {
            self.out.push(v as u8);
        } else if (-32..0).contains(&v) {
            self.out.push((v as i8) as u8); // negative fixint
        } else {
            self.out.push(0xd3);
            self.out.extend_from_slice(&v.to_be_bytes());
        }
    }
    fn nil(&mut self) {
        self.out.push(0xc0);
    }
    fn bin(&mut self, b: &[u8]) {
        match b.len() {
            n if n <= u8::MAX as usize => {
                self.out.push(0xc4);
                self.out.push(n as u8);
            }
            n if n <= u16::MAX as usize => {
                self.out.push(0xc5);
                self.out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                self.out.push(0xc6);
                self.out.extend_from_slice(&(n as u32).to_be_bytes());
            }
        }
        self.out.extend_from_slice(b);
    }
    fn finish(self) -> Vec<u8> {
        self.out
    }
}

struct MapReader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> MapReader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }
    fn byte(&mut self) -> Result<u8> {
        let v = *self.b.get(self.i).ok_or(Error::BadRequest)?;
        self.i += 1;
        Ok(v)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let s = self.b.get(self.i..self.i + n).ok_or(Error::BadRequest)?;
        self.i += n;
        Ok(s)
    }
    fn map_header(&mut self) -> Result<usize> {
        let t = self.byte()?;
        match t {
            0x80..=0x8f => Ok((t & 0x0f) as usize),
            0xde => {
                let n = self.take(2)?;
                Ok(u16::from_be_bytes([n[0], n[1]]) as usize)
            }
            _ => Err(Error::BadRequest),
        }
    }
    fn str_key(&mut self) -> Result<u8> {
        let t = self.byte()?;
        // Only single-letter keys appear here.
        if (0xa1..=0xbf).contains(&t) {
            let len = (t & 0x1f) as usize;
            let s = self.take(len)?;
            Ok(s[0])
        } else {
            Err(Error::BadRequest)
        }
    }
    fn uint(&mut self) -> Result<u64> {
        let t = self.byte()?;
        Ok(match t {
            0x00..=0x7f => t as u64,
            0xcc => self.byte()? as u64,
            0xcd => {
                let n = self.take(2)?;
                u16::from_be_bytes([n[0], n[1]]) as u64
            }
            0xce => {
                let n = self.take(4)?;
                u32::from_be_bytes([n[0], n[1], n[2], n[3]]) as u64
            }
            0xcf => {
                let n = self.take(8)?;
                u64::from_be_bytes(n.try_into().expect("8"))
            }
            _ => return Err(Error::BadRequest),
        })
    }
    fn int(&mut self) -> Result<i64> {
        let t = self.b.get(self.i).copied().ok_or(Error::BadRequest)?;
        if t >= 0xe0 {
            self.i += 1;
            Ok((t as i8) as i64) // negative fixint
        } else if t < 0x80 {
            self.i += 1;
            Ok(t as i64)
        } else {
            match self.byte()? {
                0xd3 => {
                    let n = self.take(8)?;
                    Ok(i64::from_be_bytes(n.try_into().expect("8")))
                }
                0xd2 => {
                    let n = self.take(4)?;
                    Ok(i32::from_be_bytes([n[0], n[1], n[2], n[3]]) as i64)
                }
                0xcc => Ok(self.byte()? as i64),
                _ => Err(Error::BadRequest),
            }
        }
    }
    fn int_or_nil(&mut self) -> Result<Option<i64>> {
        if self.b.get(self.i) == Some(&0xc0) {
            self.i += 1;
            Ok(None)
        } else {
            Ok(Some(self.int()?))
        }
    }
    fn bin(&mut self) -> Result<&'a [u8]> {
        let t = self.byte()?;
        let len = match t {
            0xc4 => self.byte()? as usize,
            0xc5 => {
                let n = self.take(2)?;
                u16::from_be_bytes([n[0], n[1]]) as usize
            }
            0xc6 => {
                let n = self.take(4)?;
                u32::from_be_bytes([n[0], n[1], n[2], n[3]]) as usize
            }
            _ => return Err(Error::BadRequest),
        };
        self.take(len)
    }
    fn skip_value(&mut self) -> Result<()> {
        // Only needed if RNS adds keys we do not model; skip common scalar shapes.
        let t = self.byte()?;
        match t {
            0x00..=0x7f | 0xe0..=0xff | 0xc0 => Ok(()),
            0xcc => {
                self.byte()?;
                Ok(())
            }
            0xcd => {
                self.take(2)?;
                Ok(())
            }
            0xce | 0xd2 => {
                self.take(4)?;
                Ok(())
            }
            0xcf | 0xd3 => {
                self.take(8)?;
                Ok(())
            }
            0xc4 => {
                let n = self.byte()? as usize;
                self.take(n)?;
                Ok(())
            }
            _ => Err(Error::BadRequest),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real advertisement captured in `oracle/capture_resource.py`.
    const ADV: &str = "8ba174cd02d0a164cd1000a16e02a168c42011b44f89a2dc4d73865701b5174b2\
                       0a532c53325651383a749b33c863b7fb60ea172c404fddb2d74a16fc42011b44f\
                       89a2dc4d73865701b5174b20a532c53325651383a749b33c863b7fb60ea16901a\
                       16c01a171c0a16603a16dc408202ecd18fe3e1fcb";

    fn adv_bytes() -> Vec<u8> {
        hex::decode(ADV.replace([' ', '\n'], "")).unwrap()
    }

    #[test]
    fn parses_the_captured_advertisement() {
        let a = Advertisement::parse(&adv_bytes()).unwrap();
        assert_eq!(a.transfer_size, 720);
        assert_eq!(a.data_size, 4096);
        assert_eq!(a.parts, 2);
        assert_eq!(a.flags, 3);
        assert_eq!(a.resource_hash.len(), 32);
        assert_eq!(a.original_hash.len(), 32);
        assert_eq!(a.random_hash.len(), 4);
        assert_eq!(a.random_hash, hex::decode("fddb2d74").unwrap());
        assert_eq!(a.hashmap, hex::decode("202ecd18fe3e1fcb").unwrap());
        assert_eq!(a.hashmap_parts(), 2);
        assert_eq!(a.i, 1);
        assert_eq!(a.l, 1);
        assert_eq!(a.q, None);
    }

    /// Re-packing the parsed advertisement reproduces the exact captured bytes. This is the
    /// proof the codec is faithful, key order and all.
    #[test]
    fn repacks_to_the_exact_captured_bytes() {
        let a = Advertisement::parse(&adv_bytes()).unwrap();
        assert_eq!(a.pack(), adv_bytes());
    }
}
