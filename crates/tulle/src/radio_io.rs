//! Common asynchronous packet-radio boundary for protocol crates.

use core::future::Future;
use core::time::Duration;

use crate::link::Received;
use crate::serial::{RNodeSerialLink, TransmitError};
use crate::{
    direct_phy::MAX_FRAME_LEN as DIRECT_PHY_MAX_FRAME, direct_phy_serial::DirectPhySerialLink,
};

/// A running packet radio whose transport details remain inside Tulle.
///
/// The trait is generic rather than object-safe so its futures remain allocation
/// free. Protocol pumps can use either serial personality without knowing its
/// framing.
pub trait PacketRadio {
    fn max_frame_len(&self) -> usize;

    fn send_frame(
        &self,
        frame: Vec<u8>,
    ) -> impl Future<Output = Result<Duration, TransmitError>> + Send;

    fn recv_frame(&mut self) -> impl Future<Output = Option<Received>> + Send;
}

// The explicit `impl Future + Send` mirrors the trait's own signature, which needs
// the `Send` bound spelled out for callers that spawn these futures. Rewriting the
// impls as `async fn` would hide the bound the trait exists to guarantee.
#[allow(clippy::manual_async_fn)]
impl PacketRadio for RNodeSerialLink {
    fn max_frame_len(&self) -> usize {
        crate::rnode::MAX_FRAME
    }

    fn send_frame(
        &self,
        frame: Vec<u8>,
    ) -> impl Future<Output = Result<Duration, TransmitError>> + Send {
        async move { self.send(frame).await }
    }

    fn recv_frame(&mut self) -> impl Future<Output = Option<Received>> + Send {
        async move { self.recv().await }
    }
}

#[allow(clippy::manual_async_fn)]
impl PacketRadio for DirectPhySerialLink {
    fn max_frame_len(&self) -> usize {
        DIRECT_PHY_MAX_FRAME
    }

    fn send_frame(
        &self,
        frame: Vec<u8>,
    ) -> impl Future<Output = Result<Duration, TransmitError>> + Send {
        async move { self.send(frame).await }
    }

    fn recv_frame(&mut self) -> impl Future<Output = Option<Received>> + Send {
        async move { self.recv().await }
    }
}
