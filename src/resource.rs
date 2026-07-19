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

use crate::hash::full_hash;
use crate::{Error, Result};

/// Bytes of a part's map hash in the advertisement hashmap.
pub const MAPHASH_LEN: usize = 4;

/// Length of a random hash.
pub const RANDOM_HASH_LEN: usize = 4;

/// Segment data unit: the maximum size of one part's payload. `RNS.Resource.SDU`.
pub const SDU: usize = 464;

/// Advertisement flag bit: the payload is encrypted (always set, over a link).
pub const FLAG_ENCRYPTED: u64 = 0x01;
/// Advertisement flag bit: the payload is bz2-compressed.
pub const FLAG_COMPRESSED: u64 = 0x02;

/// The resource hash: `SHA256(uncompressed_data || random_hash)`. It binds the resource to
/// its content and this transfer's random hash. Verified against RNS 1.3.8.
pub fn resource_hash(data: &[u8], random_hash: &[u8]) -> [u8; 32] {
    let mut m = Vec::with_capacity(data.len() + random_hash.len());
    m.extend_from_slice(data);
    m.extend_from_slice(random_hash);
    full_hash(&m)
}

/// A part's 4-byte map hash: `SHA256(part || random_hash)[..4]`. Verified against RNS 1.3.8.
pub fn map_hash(part: &[u8], random_hash: &[u8]) -> [u8; MAPHASH_LEN] {
    let mut m = Vec::with_capacity(part.len() + random_hash.len());
    m.extend_from_slice(part);
    m.extend_from_slice(random_hash);
    let h = full_hash(&m);
    let mut out = [0u8; MAPHASH_LEN];
    out.copy_from_slice(&h[..MAPHASH_LEN]);
    out
}

/// Compress content with bz2, as RNS does when compression helps.
///
/// RNS compresses the `random_hash || data` content, and only keeps the compressed form if
/// it is smaller. Returns the bz2 bytes; the caller decides whether to use them (and sets
/// [`FLAG_COMPRESSED`] accordingly) by comparing lengths. Available under the `compression`
/// feature.
#[cfg(feature = "compression")]
pub fn compress(content: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::best());
    enc.write_all(content)
        .expect("writing to a Vec cannot fail");
    enc.finish().expect("finishing a Vec encoder cannot fail")
}

/// Decompress bz2 content. The inverse of [`compress`]; used on a received resource whose
/// advertisement set [`FLAG_COMPRESSED`]. Returns [`Error::BadPadding`] on malformed input.
#[cfg(feature = "compression")]
pub fn decompress(compressed: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut dec = bzip2::read::BzDecoder::new(compressed);
    let mut out = Vec::new();
    dec.read_to_end(&mut out).map_err(|_| Error::BadPadding)?;
    Ok(out)
}

/// The content that is compressed, sealed, and split for transfer: `random_hash || data`.
///
/// RNS prepends the random hash to the payload before compression and encryption, so the
/// transferred blob decrypts to this, not to the bare payload. The resource hash is still
/// computed over `data || random_hash` (a different order); both were verified against RNS
/// 1.3.8.
pub fn content(data: &[u8], random_hash: &[u8]) -> Vec<u8> {
    let mut c = Vec::with_capacity(random_hash.len() + data.len());
    c.extend_from_slice(random_hash);
    c.extend_from_slice(data);
    c
}

/// Recover the payload from transferred content by stripping the `random_hash` prefix.
pub fn data_from_content(content: &[u8]) -> Result<&[u8]> {
    content.get(RANDOM_HASH_LEN..).ok_or(Error::Truncated)
}

/// Parse a resource proof packet payload: `resource_hash(32) || proof(32)`, sent
/// unencrypted. Returns `(resource_hash, proof)`, or `None` if it is not 64 bytes.
///
/// A sender compares the returned proof against the value it precomputed with [`proof`]; a
/// match means the receiver reassembled the resource intact. Verified against RNS 1.3.8.
pub fn parse_proof(payload: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    if payload.len() != 64 {
        return None;
    }
    let mut h = [0u8; 32];
    let mut p = [0u8; 32];
    h.copy_from_slice(&payload[..32]);
    p.copy_from_slice(&payload[32..]);
    Some((h, p))
}

/// The proof a receiver returns: `SHA256(uncompressed_data || resource_hash)`. The sender
/// checks it against the value it precomputed. Verified against RNS 1.3.8.
pub fn proof(data: &[u8], resource_hash: &[u8; 32]) -> [u8; 32] {
    let mut m = Vec::with_capacity(data.len() + 32);
    m.extend_from_slice(data);
    m.extend_from_slice(resource_hash);
    full_hash(&m)
}

/// Split a sealed transfer token into parts of at most [`SDU`] bytes, and compute the
/// hashmap over them.
pub fn split_parts(token: &[u8], random_hash: &[u8]) -> (Vec<Vec<u8>>, Vec<u8>) {
    let mut parts = Vec::new();
    let mut hashmap = Vec::new();
    for chunk in token.chunks(SDU) {
        hashmap.extend_from_slice(&map_hash(chunk, random_hash));
        parts.push(chunk.to_vec());
    }
    (parts, hashmap)
}

/// Build an advertisement for a transfer.
///
/// `token` is the sealed (and possibly compressed) transfer blob; `data` is the original
/// uncompressed payload. `compressed` sets the compression flag. This computes the hashes,
/// splits the token into parts, and returns the advertisement plus the parts to send.
pub fn advertise(
    data: &[u8],
    token: &[u8],
    random_hash: [u8; RANDOM_HASH_LEN],
    compressed: bool,
) -> (Advertisement, Vec<Vec<u8>>) {
    let hash = resource_hash(data, &random_hash);
    let (parts, hashmap) = split_parts(token, &random_hash);
    let mut flags = FLAG_ENCRYPTED;
    if compressed {
        flags |= FLAG_COMPRESSED;
    }
    let adv = Advertisement {
        transfer_size: token.len() as u64,
        data_size: data.len() as u64,
        parts: parts.len() as u64,
        resource_hash: hash.to_vec(),
        original_hash: hash.to_vec(),
        random_hash: random_hash.to_vec(),
        flags,
        hashmap,
        i: 1,
        l: 1,
        q: None,
    };
    (adv, parts)
}

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

/// Bytes of hashmap an advertisement carries at most. `RNS.ResourceAdvertisement`'s
/// `HASHMAP_MAX_LEN` is 74 part-hashes; the rest stream via [`Hmu`].
pub const HASHMAP_MAX_PARTS: usize = 74;

/// A parsed part request (context `RESOURCE_REQ`).
///
/// Normal: `0x00 || resource_hash(32) || wanted(4*N)`. Exhausted (soliciting more hashmap):
/// `0xff || last_map_hash(4) || resource_hash(32) || wanted(4*N)`. The leading map hash on the
/// exhausted form tells the sender where the [`Hmu`] resumes. Verified against RNS 1.3.8.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The receiver's hashmap is exhausted and it wants more via an [`Hmu`].
    pub exhausted: bool,
    /// On an exhausted request, the last map hash the receiver already holds.
    pub last_map_hash: Option<[u8; MAPHASH_LEN]>,
    pub resource_hash: [u8; 32],
    /// The map hashes of the parts being requested (may be empty on a pure HMU solicit).
    pub wanted: Vec<[u8; MAPHASH_LEN]>,
}

/// Build a normal part request: `0x00 || resource_hash || wanted*`.
pub fn build_request(resource_hash: &[u8; 32], wanted: &[[u8; MAPHASH_LEN]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + wanted.len() * MAPHASH_LEN);
    out.push(0x00);
    out.extend_from_slice(resource_hash);
    for w in wanted {
        out.extend_from_slice(w);
    }
    out
}

/// Build an exhausted request soliciting more hashmap:
/// `0xff || last_map_hash || resource_hash || wanted*`.
pub fn build_exhausted_request(
    last_map_hash: &[u8; MAPHASH_LEN],
    resource_hash: &[u8; 32],
    wanted: &[[u8; MAPHASH_LEN]],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + MAPHASH_LEN + 32 + wanted.len() * MAPHASH_LEN);
    out.push(0xff);
    out.extend_from_slice(last_map_hash);
    out.extend_from_slice(resource_hash);
    for w in wanted {
        out.extend_from_slice(w);
    }
    out
}

/// Parse a part request. The sender uses this to learn which parts to send and whether to
/// emit an [`Hmu`].
pub fn parse_request(payload: &[u8]) -> Result<Request> {
    let flag = *payload.first().ok_or(Error::BadRequest)?;
    let exhausted = flag == 0xff;
    let mut off = 1;
    let last_map_hash = if exhausted {
        let m: [u8; MAPHASH_LEN] = payload
            .get(off..off + MAPHASH_LEN)
            .ok_or(Error::BadRequest)?
            .try_into()
            .expect("checked");
        off += MAPHASH_LEN;
        Some(m)
    } else {
        None
    };
    let resource_hash: [u8; 32] = payload
        .get(off..off + 32)
        .ok_or(Error::BadRequest)?
        .try_into()
        .expect("checked");
    off += 32;
    let wanted = payload[off..]
        .chunks_exact(MAPHASH_LEN)
        .map(|c| c.try_into().expect("exact"))
        .collect();
    Ok(Request {
        exhausted,
        last_map_hash,
        resource_hash,
        wanted,
    })
}

/// A parsed hashmap update (context `RESOURCE_HMU`): the next batch of part map hashes.
///
/// `resource_hash(32) || msgpack([segment, hashmap_bin(4*M)])`. Verified against RNS 1.3.8.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hmu {
    pub resource_hash: [u8; 32],
    pub segment: i64,
    pub hashes: Vec<[u8; MAPHASH_LEN]>,
}

/// Build an HMU payload.
pub fn build_hmu(resource_hash: &[u8; 32], segment: i64, hashes: &[[u8; MAPHASH_LEN]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 4 + hashes.len() * MAPHASH_LEN);
    out.extend_from_slice(resource_hash);
    out.push(0x92); // fixarray, 2
    // segment as a msgpack int (positive fixint covers the small counters RNS uses).
    if (0..0x80).contains(&segment) {
        out.push(segment as u8);
    } else {
        out.push(0xd3);
        out.extend_from_slice(&segment.to_be_bytes());
    }
    let bin: Vec<u8> = hashes.iter().flat_map(|h| h.iter().copied()).collect();
    // bin8/bin16 for the hashmap bytes.
    if bin.len() <= u8::MAX as usize {
        out.push(0xc4);
        out.push(bin.len() as u8);
    } else {
        out.push(0xc5);
        out.extend_from_slice(&(bin.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(&bin);
    out
}

/// Parse an HMU payload.
pub fn parse_hmu(payload: &[u8]) -> Result<Hmu> {
    let resource_hash: [u8; 32] = payload
        .get(..32)
        .ok_or(Error::BadRequest)?
        .try_into()
        .expect("32");
    let mut r = MapReader::new(&payload[32..]);
    if r.byte()? != 0x92 {
        return Err(Error::BadRequest);
    }
    let segment = r.int()?;
    let bin = r.bin()?;
    if bin.len() % MAPHASH_LEN != 0 {
        return Err(Error::BadRequest);
    }
    let hashes = bin
        .chunks_exact(MAPHASH_LEN)
        .map(|c| c.try_into().expect("exact"))
        .collect();
    Ok(Hmu {
        resource_hash,
        segment,
        hashes,
    })
}

/// Receiver state for one incoming resource segment.
///
/// Drives the windowed transfer: parse the advertisement's first hashmap, request parts,
/// collect them by map hash, solicit more hashmap via [`Hmu`] when the advertised hashes run
/// out, and finally reassemble, decrypt, decompress, verify, and prove. One `Incoming`
/// handles one segment (a resource up to ~1 MB is a single segment).
pub struct Incoming {
    hash: [u8; 32],
    random_hash: Vec<u8>,
    compressed: bool,
    total_parts: usize,
    /// Map hashes in transfer order. Starts with the advertisement's hashmap and grows as
    /// each [`Hmu`] arrives.
    order: Vec<[u8; MAPHASH_LEN]>,
    /// Collected parts, keyed by map hash.
    parts: std::collections::HashMap<[u8; MAPHASH_LEN], Vec<u8>>,
}

impl Incoming {
    /// Begin receiving from an advertisement. Accepts a partial hashmap (a large resource
    /// whose hashmap streams via [`Hmu`]); the missing hashes arrive later.
    pub fn new(adv: &Advertisement) -> Result<Self> {
        if adv.resource_hash.len() != 32 {
            return Err(Error::BadRequest);
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&adv.resource_hash);
        let order = adv
            .hashmap
            .chunks_exact(MAPHASH_LEN)
            .map(|c| c.try_into().expect("exact"))
            .collect();
        Ok(Self {
            hash,
            random_hash: adv.random_hash.clone(),
            compressed: adv.flags & FLAG_COMPRESSED != 0,
            total_parts: adv.parts as usize,
            order,
            parts: std::collections::HashMap::new(),
        })
    }

    /// Whether the advertisement said the payload is bz2-compressed.
    pub fn is_compressed(&self) -> bool {
        self.compressed
    }

    /// Total parts in this segment.
    pub fn total_parts(&self) -> usize {
        self.total_parts
    }

    /// How many part hashes are known so far (advertisement + ingested HMUs).
    pub fn order_len(&self) -> usize {
        self.order.len()
    }

    /// Known map hashes not yet collected. These are what to ask for next.
    pub fn missing_known(&self) -> Vec<[u8; MAPHASH_LEN]> {
        self.order
            .iter()
            .filter(|m| !self.parts.contains_key(*m))
            .copied()
            .collect()
    }

    /// Whether every known map hash has been collected (but more may remain via HMU).
    pub fn all_known_collected(&self) -> bool {
        self.order.iter().all(|m| self.parts.contains_key(m))
    }

    /// Whether the full hashmap is known (all part hashes, via advertisement + HMUs).
    pub fn have_all_hashes(&self) -> bool {
        self.order.len() >= self.total_parts
    }

    /// Whether more hashmap is needed: known hashes exhausted, parts remain.
    pub fn needs_hmu(&self) -> bool {
        self.all_known_collected() && !self.have_all_hashes()
    }

    /// A normal request for the given map hashes.
    pub fn request(&self, wanted: &[[u8; MAPHASH_LEN]]) -> Vec<u8> {
        build_request(&self.hash, wanted)
    }

    /// An exhausted request soliciting more hashmap, referencing the last known map hash.
    pub fn solicit_hmu(&self) -> Vec<u8> {
        let last = self.order.last().copied().unwrap_or([0u8; MAPHASH_LEN]);
        build_exhausted_request(&last, &self.hash, &[])
    }

    /// Ingest an HMU's hashes, appending any new ones in order. Returns how many were added.
    pub fn ingest_hmu(&mut self, hmu: &Hmu) -> usize {
        let mut added = 0;
        for h in &hmu.hashes {
            if !self.order.contains(h) {
                self.order.push(*h);
                added += 1;
            }
        }
        added
    }

    /// Take a received part (a raw token slice). Matched by its map hash; a part whose map
    /// hash is not (yet) known is ignored.
    pub fn accept_part(&mut self, part: &[u8]) -> bool {
        let m = map_hash(part, &self.random_hash);
        if self.order.contains(&m) {
            self.parts.insert(m, part.to_vec());
            true
        } else {
            false
        }
    }

    /// Whether every part of the segment has arrived.
    pub fn is_complete(&self) -> bool {
        self.have_all_hashes() && self.all_known_collected()
    }

    /// Reassemble the token in transfer order. Verifies nothing; call [`recover`](Self::recover).
    pub fn assemble_token(&self) -> Result<Vec<u8>> {
        if !self.is_complete() {
            return Err(Error::Truncated);
        }
        let mut token = Vec::new();
        for m in &self.order {
            token.extend_from_slice(self.parts.get(m).ok_or(Error::Truncated)?);
        }
        Ok(token)
    }

    /// Recover the payload from the decrypted transfer blob: decompress if the
    /// advertisement flagged it, strip the `random_hash` prefix, and verify against the
    /// resource hash. This is the whole receive tail in one call.
    ///
    /// Returns [`Error::ResourceCorrupt`] if the recovered data does not match the hash, and
    /// [`Error::Unsupported`] if the resource is compressed but the `compression` feature is
    /// off.
    pub fn recover(&self, decrypted: &[u8]) -> Result<Vec<u8>> {
        // The transferred blob is `random_hash || body`, where body is the payload,
        // bz2-compressed if the advertisement flagged it. The random-hash prefix sits
        // OUTSIDE the compression, so strip it first, then decompress.
        let body = data_from_content(decrypted)?;
        let data = if self.compressed {
            #[cfg(feature = "compression")]
            {
                decompress(body)?
            }
            #[cfg(not(feature = "compression"))]
            {
                return Err(Error::Unsupported);
            }
        } else {
            body.to_vec()
        };
        if !self.verify(&data) {
            return Err(Error::ResourceCorrupt);
        }
        Ok(data)
    }

    /// Check that decrypted (and decompressed) `data` matches the advertised resource hash.
    pub fn verify(&self, data: &[u8]) -> bool {
        resource_hash(data, &self.random_hash) == self.hash
    }

    /// The proof to return for `data`: `SHA256(data || resource_hash)`.
    pub fn proof(&self, data: &[u8]) -> [u8; 32] {
        proof(data, &self.hash)
    }

    /// The resource hash from the advertisement.
    pub fn resource_hash(&self) -> [u8; 32] {
        self.hash
    }
}

/// Sender state for one outgoing resource segment.
///
/// Splits a sealed token into parts, advertises the first [`HASHMAP_MAX_PARTS`] map hashes,
/// serves part requests, and emits an [`Hmu`] when the receiver's hashmap runs out. Pair the
/// advertisement and each served part / HMU with the link's framing in the shell.
/// Bytes of payload per segment. A resource larger than this splits into multiple segments,
/// each transferred (and proved) independently. `RNS.Resource.MAX_EFFICIENT_SIZE`.
pub const MAX_SEGMENT_SIZE: usize = 1_048_575;

pub struct Outgoing {
    hash: [u8; 32],
    /// The whole-resource identity, carried in every segment's advertisement `o` field. For
    /// a single-segment resource this equals `hash`; across a multi-segment resource it is
    /// the FIRST segment's hash, shared, so the receiver groups the segments.
    original_hash: [u8; 32],
    random_hash: [u8; RANDOM_HASH_LEN],
    transfer_size: u64,
    compressed: bool,
    /// 1-based segment index and total segment count. Single-segment resources are (1, 1).
    segment_index: i64,
    total_segments: i64,
    /// The full resource's data size, carried in every segment's advertisement `d` field.
    total_data_size: u64,
    /// All part map hashes, in transfer order.
    map_hashes: Vec<[u8; MAPHASH_LEN]>,
    /// Parts (raw token slices) keyed by map hash.
    by_hash: std::collections::HashMap<[u8; MAPHASH_LEN], Vec<u8>>,
    expected_proof: [u8; 32],
    hmu_segment: i64,
}

impl Outgoing {
    /// Prepare to send `data`, already sealed into `token` (see [`content`] and the link's
    /// `seal`). `compressed` records whether `token`'s plaintext was bz2-compressed.
    pub fn new(
        data: &[u8],
        token: &[u8],
        random_hash: [u8; RANDOM_HASH_LEN],
        compressed: bool,
    ) -> Self {
        let hash = resource_hash(data, &random_hash);
        let (parts, _hashmap) = split_parts(token, &random_hash);
        let mut map_hashes = Vec::with_capacity(parts.len());
        let mut by_hash = std::collections::HashMap::new();
        for p in parts {
            let m = map_hash(&p, &random_hash);
            map_hashes.push(m);
            by_hash.insert(m, p);
        }
        Self {
            hash,
            original_hash: hash,
            random_hash,
            transfer_size: token.len() as u64,
            compressed,
            segment_index: 1,
            total_segments: 1,
            total_data_size: data.len() as u64,
            expected_proof: proof(data, &hash),
            map_hashes,
            by_hash,
            hmu_segment: 1,
        }
    }

    /// Mark this as segment `index` of `total` in a larger resource whose full payload is
    /// `total_data_size` bytes and whose identity is `original_hash` (the FIRST segment's
    /// hash, shared across all segments so the receiver groups them). The advertisement's
    /// `i`/`l`/`d`/`o` fields carry these. Verified against RNS 1.3.8.
    pub fn with_segment(
        mut self,
        index: i64,
        total: i64,
        total_data_size: u64,
        original_hash: [u8; 32],
    ) -> Self {
        self.segment_index = index;
        self.total_segments = total;
        self.total_data_size = total_data_size;
        self.original_hash = original_hash;
        self
    }

    /// The advertisement, carrying the first [`HASHMAP_MAX_PARTS`] map hashes.
    pub fn advertisement(&self) -> Advertisement {
        let n = self.map_hashes.len().min(HASHMAP_MAX_PARTS);
        let hashmap: Vec<u8> = self.map_hashes[..n]
            .iter()
            .flat_map(|h| h.iter().copied())
            .collect();
        let mut flags = FLAG_ENCRYPTED;
        if self.compressed {
            flags |= FLAG_COMPRESSED;
        }
        Advertisement {
            transfer_size: self.transfer_size,
            data_size: self.total_data_size,
            parts: self.map_hashes.len() as u64,
            resource_hash: self.hash.to_vec(),
            original_hash: self.original_hash.to_vec(),
            random_hash: self.random_hash.to_vec(),
            flags,
            hashmap,
            i: self.segment_index,
            l: self.total_segments,
            q: None,
        }
    }

    /// The parts to send in response to a request (those whose map hashes we hold).
    pub fn serve(&self, request: &Request) -> Vec<Vec<u8>> {
        request
            .wanted
            .iter()
            .filter_map(|m| self.by_hash.get(m).cloned())
            .collect()
    }

    /// Build the next hashmap update after `last_map_hash`: the batch of map hashes that
    /// follow it in transfer order. Empty if `last_map_hash` is the final part.
    pub fn hmu_after(&mut self, last_map_hash: &[u8; MAPHASH_LEN]) -> Vec<u8> {
        let start = self
            .map_hashes
            .iter()
            .position(|m| m == last_map_hash)
            .map(|i| i + 1)
            .unwrap_or(self.map_hashes.len());
        // Send the rest of the hashmap in one HMU (fits many parts; a fuller implementation
        // would batch to the MDU). One HMU per solicit is correct if smaller than the MDU.
        let batch: Vec<[u8; MAPHASH_LEN]> = self.map_hashes[start..].to_vec();
        let seg = self.hmu_segment;
        self.hmu_segment += 1;
        build_hmu(&self.hash, seg, &batch)
    }

    /// The resource hash.
    pub fn resource_hash(&self) -> [u8; 32] {
        self.hash
    }

    /// The proof the receiver must return for a correct transfer.
    pub fn expected_proof(&self) -> [u8; 32] {
        self.expected_proof
    }

    /// Total parts.
    pub fn total_parts(&self) -> usize {
        self.map_hashes.len()
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

    #[test]
    fn request_codec_round_trips() {
        let rh = [0x11u8; 32];
        let wanted = [[1u8; 4], [2u8; 4], [3u8; 4]];
        let r = parse_request(&build_request(&rh, &wanted)).unwrap();
        assert!(!r.exhausted);
        assert_eq!(r.last_map_hash, None);
        assert_eq!(r.resource_hash, rh);
        assert_eq!(r.wanted, wanted);

        let last = [9u8; 4];
        let e = parse_request(&build_exhausted_request(&last, &rh, &wanted)).unwrap();
        assert!(e.exhausted);
        assert_eq!(e.last_map_hash, Some(last));
        assert_eq!(e.resource_hash, rh);
        assert_eq!(e.wanted, wanted);
    }

    #[test]
    fn hmu_codec_round_trips() {
        let rh = [0x22u8; 32];
        let hashes = [[0xAu8; 4], [0xBu8; 4], [0xCu8; 4]];
        let h = parse_hmu(&build_hmu(&rh, 1, &hashes)).unwrap();
        assert_eq!(h.resource_hash, rh);
        assert_eq!(h.segment, 1);
        assert_eq!(h.hashes, hashes);
    }

    /// The captured RNS HMU decodes to the known structure.
    #[test]
    fn hmu_matches_captured_rns() {
        let hmu = hex::decode(
            "34fa88d9f5bbe24374673ed08a7a1748c8cef5a281c5d82866f530026d863a08\
             9201c43456db7769dec46a395226df3ef3d0ac23c4ef932b3b5626381e0ef732\
             1238cf007f73a344c91aa2590e7ec740c3c3ea1fe51bc895",
        )
        .unwrap();
        let h = parse_hmu(&hmu).unwrap();
        assert_eq!(h.segment, 1);
        assert_eq!(h.hashes.len(), 13);
        assert_eq!(
            hex::encode(h.resource_hash),
            "34fa88d9f5bbe24374673ed08a7a1748c8cef5a281c5d82866f530026d863a08"
        );
    }

    /// A >74-part resource round-trips sender -> receiver through the windowed HMU path,
    /// entirely in-process (no RNS): advertise, request windows, solicit + ingest HMUs,
    /// serve, reassemble.
    #[test]
    fn windowed_sender_receiver_round_trip() {
        use crate::destination::DestinationName;
        use crate::identity::PrivateIdentity;
        use crate::link::{LinkMode, LinkTrailer, PendingLink, accept};

        let dest_id = PrivateIdentity::from_secret_bytes(&[0x11; 64]);
        let (pending, req) = PendingLink::open(
            DestinationName::new("retinue", ["r"]).destination_hash(dest_id.public()),
            *dest_id.public(),
            &[0x33; 64],
            LinkTrailer {
                mode: LinkMode::Aes256Cbc,
                mtu: 500,
            },
        );
        let (recv_link, proof_pkt) = accept(
            &req,
            &dest_id,
            &[0x99; 64],
            LinkTrailer {
                mode: LinkMode::Aes256Cbc,
                mtu: 500,
            },
        )
        .unwrap();
        let send_link = pending.prove(&proof_pkt).unwrap();

        // ~120 parts of data.
        let data: Vec<u8> = (0..55_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 8) as u8)
            .collect();
        let rh = [0xAB, 0xCD, 0xEF, 0x01];
        let token = send_link.seal(&content(&data, &rh), &[7u8; 16]);
        let mut out = Outgoing::new(&data, &token, rh, false);
        assert!(out.total_parts() > HASHMAP_MAX_PARTS);

        let mut inc = Incoming::new(&out.advertisement()).unwrap();
        // Drive the windowed exchange to completion.
        loop {
            if inc.is_complete() {
                break;
            }
            let want = inc.missing_known();
            if !want.is_empty() {
                let req = parse_request(&inc.request(&want)).unwrap();
                for part in out.serve(&req) {
                    inc.accept_part(&part);
                }
            } else if inc.needs_hmu() {
                let solicit = parse_request(&inc.solicit_hmu()).unwrap();
                let last = solicit.last_map_hash.unwrap();
                let hmu = parse_hmu(&out.hmu_after(&last)).unwrap();
                assert!(inc.ingest_hmu(&hmu) > 0);
            } else {
                panic!("stuck: not complete, nothing to request, no HMU needed");
            }
        }
        let recovered = inc
            .recover(&recv_link.open(&inc.assemble_token().unwrap()).unwrap())
            .unwrap();
        assert_eq!(recovered, data);
        assert_eq!(inc.proof(&recovered), out.expected_proof());
    }

    /// A multi-segment resource round-trips sender -> receiver in-process: two segments
    /// sharing one original_hash, driven windowed, recovered bodies concatenated.
    #[test]
    fn multi_segment_round_trip() {
        use crate::destination::DestinationName;
        use crate::identity::PrivateIdentity;
        use crate::link::{LinkMode, LinkTrailer, PendingLink, accept};

        let dest_id = PrivateIdentity::from_secret_bytes(&[0x11; 64]);
        let (pending, req) = PendingLink::open(
            DestinationName::new("retinue", ["r"]).destination_hash(dest_id.public()),
            *dest_id.public(),
            &[0x33; 64],
            LinkTrailer {
                mode: LinkMode::Aes256Cbc,
                mtu: 500,
            },
        );
        let (recv_link, proof_pkt) = accept(
            &req,
            &dest_id,
            &[0x99; 64],
            LinkTrailer {
                mode: LinkMode::Aes256Cbc,
                mtu: 500,
            },
        )
        .unwrap();
        let send_link = pending.prove(&proof_pkt).unwrap();

        // Two segments of ~90 parts each (small "MAX_SEGMENT_SIZE" for the test).
        const SEG: usize = 40_000;
        let data: Vec<u8> = (0..90_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 8) as u8)
            .collect();
        let seg0_rh = [1u8, 2, 3, 4];
        let original = resource_hash(&data[..SEG.min(data.len())], &seg0_rh);

        let mut assembled = Vec::new();
        let total_segs = data.chunks(SEG).count() as i64;
        for (idx, chunk) in data.chunks(SEG).enumerate() {
            let rh = [(idx as u8) + 1, 2, 3, 4];
            let token = send_link.seal(&content(chunk, &rh), &[7u8; 16]);
            let mut out = Outgoing::new(chunk, &token, rh, false).with_segment(
                idx as i64 + 1,
                total_segs,
                data.len() as u64,
                original,
            );
            // Check the advertisement carries the shared identity and total size.
            let adv = out.advertisement();
            assert_eq!(adv.original_hash, original.to_vec());
            assert_eq!(adv.data_size, data.len() as u64);

            let mut inc = Incoming::new(&adv).unwrap();
            loop {
                if inc.is_complete() {
                    break;
                }
                let want = inc.missing_known();
                if !want.is_empty() {
                    let r = parse_request(&inc.request(&want)).unwrap();
                    for part in out.serve(&r) {
                        inc.accept_part(&part);
                    }
                } else {
                    let s = parse_request(&inc.solicit_hmu()).unwrap();
                    let hmu = parse_hmu(&out.hmu_after(&s.last_map_hash.unwrap())).unwrap();
                    inc.ingest_hmu(&hmu);
                }
            }
            let body = inc
                .recover(&recv_link.open(&inc.assemble_token().unwrap()).unwrap())
                .unwrap();
            assembled.extend_from_slice(&body);
        }
        assert_eq!(assembled, data);
    }

    #[test]
    fn proof_packet_round_trips() {
        let h = [0x11; 32];
        let p = [0x22; 32];
        let mut payload = h.to_vec();
        payload.extend_from_slice(&p);
        assert_eq!(parse_proof(&payload), Some((h, p)));
        assert_eq!(parse_proof(&payload[..63]), None);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn compress_round_trips() {
        // Compressible input so bz2 actually shrinks it.
        let content: Vec<u8> = (0..8000u32).map(|i| (i / 40) as u8).collect();
        let squished = compress(&content);
        assert!(squished.len() < content.len());
        assert_eq!(decompress(&squished).unwrap(), content);
    }

    #[test]
    fn hash_map_and_proof_derivations() {
        let data = b"the quick brown fox";
        let rh = [0x11, 0x22, 0x33, 0x44];
        let h = resource_hash(data, &rh);
        // map hash is a prefix of SHA256(part || rh)
        let mh = map_hash(data, &rh);
        assert_eq!(
            &crate::hash::full_hash(&[&data[..], &rh[..]].concat())[..4],
            &mh
        );
        // proof folds the resource hash back in
        assert_eq!(
            proof(data, &h),
            crate::hash::full_hash(&[&data[..], &h[..]].concat())
        );
    }

    /// The sender and receiver halves agree end to end, through a real AES token: build an
    /// advertisement and parts, then receive them back and recover the payload. This mirrors
    /// the live RNS gate without needing RNS.
    #[test]
    fn sender_and_receiver_round_trip() {
        use crate::destination::DestinationName;
        use crate::identity::PrivateIdentity;
        use crate::link::{LinkMode, LinkTrailer, PendingLink, accept};

        // A link to seal/open with.
        let dest_id = PrivateIdentity::from_secret_bytes(&[0x11; 64]);
        let (pending, req) = PendingLink::open(
            DestinationName::new("retinue", ["r"]).destination_hash(dest_id.public()),
            *dest_id.public(),
            &[0x33; 64],
            LinkTrailer {
                mode: LinkMode::Aes256Cbc,
                mtu: 500,
            },
        );
        let (recv_link, proof_pkt) = accept(
            &req,
            &dest_id,
            &[0x99; 64],
            LinkTrailer {
                mode: LinkMode::Aes256Cbc,
                mtu: 500,
            },
        )
        .unwrap();
        let send_link = pending.prove(&proof_pkt).unwrap();

        // Sender: content = rh || data, sealed, split, advertised.
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 3 + 1) as u8).collect();
        let rh = [0xAB, 0xCD, 0xEF, 0x01];
        let token = send_link.seal(&content(&data, &rh), &[7u8; 16]);
        let (adv, parts) = advertise(&data, &token, rh, false);

        // Receiver: parse, collect parts, recover.
        let mut inc = Incoming::new(&adv).unwrap();
        for p in &parts {
            assert!(inc.accept_part(p));
        }
        assert!(inc.is_complete());
        let recovered_content = recv_link.open(&inc.assemble_token().unwrap()).unwrap();
        let recovered = data_from_content(&recovered_content).unwrap();
        assert_eq!(recovered, &data[..]);
        assert!(inc.verify(recovered));
        // Proof round-trips to the value the sender precomputed.
        assert_eq!(inc.proof(recovered), proof(&data, &inc.resource_hash()));
    }
}
