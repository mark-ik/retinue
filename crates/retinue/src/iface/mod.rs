//! Interfaces: how packets get onto a wire.
//!
//! An interface is a byte pipe plus a framing. R1 implements the TCP interface, which is
//! HDLC framing over a TCP stream, in both the client and the server direction.
//!
//! The framing ([`hdlc`]) is sans-io and always available. The TCP interface ([`tcp`])
//! needs a runtime and sits behind the `tokio` feature, which is on by default.

pub mod hdlc;

#[cfg(feature = "tokio")]
pub mod tcp;

#[cfg(feature = "tulle-radio")]
pub mod tulle;
