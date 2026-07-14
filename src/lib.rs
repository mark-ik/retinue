//! retinue — an endpoint-scoped implementation of the
//! [Reticulum](https://reticulum.network/) protocol.
//!
//! A retinue is the company that travels with a person. This crate aims to be that for a
//! peer: the identity, announce, link, and resource layers a node needs to *be* a
//! Reticulum endpoint, embedded as a library. Transport-node routing is a non-goal.
//!
//! # Status
//!
//! **R0, the wire vocabulary**: identities, hashes, destination naming, the packet codec,
//! announces, and the encrypted token. No I/O, no runtime, no RNG. Everything is a pure
//! function over bytes, which is what lets it be replayed against fixtures captured from
//! the reference implementation.
//!
//! **R1, the TCP interface**: HDLC framing ([`iface::hdlc`], also sans-io) and a tokio
//! shell over it ([`iface::tcp`]). The shell is behind the `tokio` feature, on by default;
//! turn it off and the codec still stands alone.
//!
//! Links and resources (R3, R4) will sit on top.
//!
//! # Provenance
//!
//! Wire-compatibility target is RNS 1.3.8. This crate was implemented from the
//! public-domain Reticulum protocol specification and the MIT-licensed Beechat
//! `reticulum` crate. The Python reference implementation was never read: it is used
//! strictly as a black-box interoperability oracle, run and observed, and the bytes it
//! emitted are checked in as fixtures under `tests/fixtures/`. See
//! `design_docs/2026-07-13_rns_wire_format_reference.md`.

pub mod announce;
pub mod destination;
pub mod hash;
pub mod identity;
pub mod iface;
pub mod link;
pub mod packet;
pub mod token;

pub use announce::Announce;
pub use destination::DestinationName;
pub use hash::{AddressHash, NameHash};
pub use identity::{Identity, PrivateIdentity};
pub use packet::Packet;

/// Anything that can go wrong decoding or validating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The input ended before a required field did.
    Truncated,
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
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::Truncated => "input ended mid-field",
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
        };
        f.write_str(s)
    }
}

impl core::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
