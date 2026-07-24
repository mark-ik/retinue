//! retinue — an endpoint-scoped implementation of the
//! [Reticulum](https://reticulum.network/) protocol.
//!
//! A retinue is the company that travels with a person. This crate is that for a peer: the
//! identity, announce, link, resource, and reliable-stream layers a node needs to *be* a
//! Reticulum endpoint, embedded as a library, wire-compatible with RNS 1.3.x.
//!
//! # Status
//!
//! The wire vocabulary, links, resources, request/response, the endpoint runtime, opt-in
//! transport-node routing, and reliable streaming are all implemented and checked
//! byte-for-byte against RNS 1.3.8 (run as a black-box oracle; see *Provenance*). The
//! layering:
//!
//! - **Sans-io core** — always available, no runtime or RNG: the packet codec
//!   ([`packet`]), identities ([`identity`]), announces ([`announce`]), the token
//!   ([`token`]), HDLC framing ([`iface::hdlc`]), links ([`link`]), resources
//!   ([`resource`]), and the `Channel`/`Buffer` + link-proof reliability machinery
//!   ([`channel`], [`reliable`]). Pure functions over bytes, replayable against fixtures.
//! - **The tokio shell** — behind the `tokio` feature (on by default): the TCP interface
//!   ([`iface::tcp`]) and the [`endpoint`] runtime that attaches interfaces, routes packets,
//!   and opens/accepts links as streams. Turn the feature off and the sans-io core stands
//!   alone.
//!
//! Transport-node routing is opt-in ([`endpoint::Endpoint::enable_routing`]); the default
//! posture is endpoint-scoped. Not yet done: on-air interfaces (serial/RNode/UDP), an
//! endpoint-level resource-transfer API, and route expiry/budgeting. See the README's
//! *Maturity* section and `design_docs/`.
//!
//! # Provenance
//!
//! Wire-compatibility target is RNS 1.3.8. This crate was implemented from the
//! public-domain Reticulum protocol specification and the MIT-licensed Beechat
//! `reticulum` crate. The Python reference implementation was never read: it is used
//! strictly as a black-box interoperability oracle, run and observed, and the bytes it
//! emitted are checked in as fixtures under `tests/fixtures/`. See
//! `design_docs/2026-07-13_rns_wire_format_reference.md`.

pub mod address_book;
pub mod announce;
pub mod channel;
pub mod destination;
#[cfg(feature = "tokio")]
pub mod endpoint;
pub mod hash;
pub mod identity;
pub mod iface;
pub mod link;
pub mod lossy;
pub mod packet;
pub mod path;
pub mod reliable;
pub mod request;
pub mod resource;
pub mod resource_transfer;
pub mod token;

pub use address_book::{AddressBook, Peer};
pub use announce::Announce;
pub use destination::DestinationName;
pub use hash::{AddressHash, NameHash};
pub use identity::{Identity, PrivateIdentity};
pub use packet::Packet;
pub use reliable::ReliableChannel;

/// Anything that can go wrong decoding or validating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The input ended before a required field did.
    Truncated,
    /// A packet is larger than the wire MTU. RNS drops such packets; we reject them at the
    /// decoder so a peer cannot hand us an over-sized buffer.
    Oversize,
    /// A public key is not a valid point on its curve.
    BadKey,
    /// The Ed25519 signature did not verify. For an announce this means the peer does not
    /// hold the private key for the identity it is announcing.
    BadSignature,
    /// The destination hash in the header is not the one the announced identity and name
    /// imply: a correctly signed announce for a destination that is not the one claimed.
    DestinationMismatch,
    /// The HMAC on a token did not verify.
    BadMac,
    /// PKCS7 padding was malformed after decryption.
    BadPadding,
    /// An announce decoder was handed a packet that is not an announce.
    NotAnAnnounce,
    /// A link trailer named a cipher mode we do not know.
    BadLinkMode,
    /// A proof decoder was handed a packet that is not a proof.
    NotAProof,
    /// An accept was handed a packet that is not a link request.
    NotALinkRequest,
    /// A proof was addressed to a different link than the one it is being matched against.
    LinkMismatch,
    /// A request or response could not be parsed from its msgpack.
    BadRequest,
    /// A reassembled resource did not match its advertised hash.
    ResourceCorrupt,
    /// The operation needs a feature that is not enabled (e.g. `compression`).
    Unsupported,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::Truncated => "input ended mid-field",
            Self::Oversize => "packet exceeds the wire MTU",
            Self::BadKey => "invalid public key",
            Self::BadSignature => "signature did not verify",
            Self::DestinationMismatch => "destination hash does not match the announced identity",
            Self::BadMac => "token HMAC did not verify",
            Self::BadPadding => "malformed padding",
            Self::NotAnAnnounce => "packet is not an announce",
            Self::BadLinkMode => "unknown link cipher mode",
            Self::NotAProof => "packet is not a proof",
            Self::NotALinkRequest => "packet is not a link request",
            Self::LinkMismatch => "proof is for a different link",
            Self::BadRequest => "malformed request or response",
            Self::ResourceCorrupt => "reassembled resource does not match its hash",
            Self::Unsupported => "operation needs a disabled feature",
        };
        f.write_str(s)
    }
}

impl core::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
