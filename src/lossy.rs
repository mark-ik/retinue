//! A deterministic packet loss / delay oracle for testing reliability without radio.
//!
//! Reticulum's reliability machinery — link `Channel`/`Buffer`, resource windowing,
//! retries and cancellation, dynamic window sizing, part timeouts — earns its keep
//! only on a medium that drops, reorders, and delays. The interop oracle is Python
//! RNS over TCP loopback, which does none of that, so a green test there proves
//! nothing about the paths that matter: every retry branch is dead code that passes
//! because it never runs.
//!
//! This connects two [`Endpoint`]s through a **seeded, reproducible** loss model, so
//! those paths run at a desk, before any hardware exists. Same seed + same packet
//! sequence yields the same drops and delays, so a failure reproduces exactly.
//!
//! It plugs into the transport-agnostic [`Endpoint::attach_interface`] seam — the
//! same seam TCP and (later) serial/RNode use — and drops/delays whole packets,
//! which is the granularity link reliability and resource transfer actually care
//! about.
//!
//! ```no_run
//! # use retinue::endpoint::Endpoint;
//! # use retinue::identity::PrivateIdentity;
//! # use retinue::lossy::{self, LossModel};
//! # async fn demo() {
//! let a = Endpoint::new(PrivateIdentity::from_secret_bytes(&[1u8; 64]));
//! let b = Endpoint::new(PrivateIdentity::from_secret_bytes(&[2u8; 64]));
//! // 20% packet loss and up to 40ms jitter each way, both reproducible.
//! lossy::connect(
//!     &a,
//!     &b,
//!     LossModel::new(1).drop_per_mille(200).max_delay_ms(40),
//!     LossModel::new(2).drop_per_mille(200).max_delay_ms(40),
//! );
//! # }
//! ```

use std::time::Duration;

use crate::endpoint::{Endpoint, InterfaceSink};
use crate::packet::Packet;

/// A seeded, deterministic loss model: a probability of dropping each packet and a
/// bounded random delay applied to those that survive.
///
/// Default is lossless (a faithful pass-through), so `LossModel::new(seed)` alone
/// turns [`connect`] into an ordinary in-memory link — useful as the control.
#[derive(Clone)]
pub struct LossModel {
    state: u64,
    drop_per_mille: u32,
    max_delay_ms: u64,
}

impl LossModel {
    /// A lossless model with the given seed. Build loss onto it with the setters.
    pub fn new(seed: u64) -> Self {
        // SplitMix64 to derive the initial state: it decorrelates nearby seeds (so
        // seeds 42 and 43 give unrelated streams) and never lands on xorshift's
        // fixed point at 0.
        Self {
            state: splitmix64(seed),
            drop_per_mille: 0,
            max_delay_ms: 0,
        }
    }

    /// Drop this many packets per thousand (clamped to 1000).
    pub fn drop_per_mille(mut self, per_mille: u32) -> Self {
        self.drop_per_mille = per_mille.min(1000);
        self
    }

    /// Delay each *delivered* packet by a reproducible `0..=ms` milliseconds. Delay
    /// also reorders: a delayed packet arrives after later ones that were not.
    pub fn max_delay_ms(mut self, ms: u64) -> Self {
        self.max_delay_ms = ms;
        self
    }

    /// xorshift64 — deterministic, allocation-free, no RNG dependency (retinue's
    /// core is RNG-free; this is a test shell).
    fn next(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn drops(&mut self) -> bool {
        self.drop_per_mille != 0 && (self.next() % 1000) < u64::from(self.drop_per_mille)
    }

    fn delay(&mut self) -> Duration {
        if self.max_delay_ms == 0 {
            Duration::ZERO
        } else {
            Duration::from_millis(self.next() % (self.max_delay_ms + 1))
        }
    }
}

/// Mix an arbitrary seed into a well-distributed, non-zero xorshift state.
fn splitmix64(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    let z = z ^ (z >> 31);
    // xorshift's only fixed point is 0; splitmix maps exactly one seed there.
    if z == 0 { 0x9E37_79B9_7F4A_7C15 } else { z }
}

/// Connect two endpoints through a deterministic lossy link, one [`LossModel`] per
/// direction. Returns immediately; two pump tasks run in the background until either
/// endpoint is dropped.
pub fn connect(a: &Endpoint, b: &Endpoint, a_to_b: LossModel, b_to_a: LossModel) {
    let (a_out, a_sink) = a.attach_interface().split();
    let (b_out, b_sink) = b.attach_interface().split();
    tokio::spawn(pump(a_out, b_sink, a_to_b));
    tokio::spawn(pump(b_out, a_sink, b_to_a));
}

/// Move packets from one endpoint's outbound stream to the other's sink, applying
/// the loss model: some are dropped, survivors delivered after a bounded delay.
async fn pump(
    mut out: tokio::sync::mpsc::UnboundedReceiver<Packet>,
    sink: InterfaceSink,
    mut model: LossModel,
) {
    while let Some(pkt) = out.recv().await {
        if model.drops() {
            continue;
        }
        let delay = model.delay();
        if delay.is_zero() {
            if !sink.deliver(pkt) {
                break;
            }
        } else {
            // Deliver late on its own task, so a delayed packet does not hold up the
            // ones behind it — that is what produces reordering.
            let sink = sink.clone();
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                sink.deliver(pkt);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::{Instant, timeout};

    use super::{LossModel, connect};
    use crate::destination::DestinationName;
    use crate::endpoint::Endpoint;
    use crate::identity::PrivateIdentity;

    /// Drive A's announces until B learns A's destination, or the deadline passes.
    async fn learns(a: &Endpoint, b: &Endpoint, name: &DestinationName) -> bool {
        let dest = name.destination_hash(a.identity());
        a.register(name.clone(), b"cap");
        let deadline = Instant::now() + Duration::from_secs(6);
        while b.resolve(dest).is_none() && Instant::now() < deadline {
            a.announce(name, b"cap");
            let _ = timeout(Duration::from_millis(60), b.next_announcement()).await;
        }
        b.resolve(dest).is_some()
    }

    #[tokio::test]
    async fn zero_loss_link_is_faithful() {
        // The control: a lossless model is an ordinary in-memory link. Discovery
        // over the attach_interface seam works exactly like TCP.
        let a = Endpoint::new(PrivateIdentity::from_secret_bytes(&[1u8; 64]));
        let b = Endpoint::new(PrivateIdentity::from_secret_bytes(&[2u8; 64]));
        connect(&a, &b, LossModel::new(1), LossModel::new(2));

        let name = DestinationName::new("test", ["cap"]);
        assert!(
            learns(&a, &b, &name).await,
            "B learns A over a lossless lossy-link (seam is a faithful transport)"
        );
    }

    #[tokio::test]
    async fn announces_survive_moderate_drop() {
        // Loss is really injected, and repetition-based discovery survives it: at
        // 40% packet loss each way, a re-announced destination still gets through.
        let a = Endpoint::new(PrivateIdentity::from_secret_bytes(&[3u8; 64]));
        let b = Endpoint::new(PrivateIdentity::from_secret_bytes(&[4u8; 64]));
        connect(
            &a,
            &b,
            LossModel::new(7).drop_per_mille(400).max_delay_ms(15),
            LossModel::new(8).drop_per_mille(400).max_delay_ms(15),
        );

        let name = DestinationName::new("test", ["cap"]);
        assert!(
            learns(&a, &b, &name).await,
            "repeated announces survive 40% drop + jitter (loss is injected, retry-by-repeat works)"
        );
    }

    #[tokio::test]
    async fn drop_model_is_deterministic() {
        // Same seed + same packet count => identical drop decisions. This is what
        // makes a reliability-layer failure reproduce exactly.
        let run = |seed: u64| {
            let mut m = LossModel::new(seed).drop_per_mille(500);
            (0..64).map(|_| m.drops()).collect::<Vec<_>>()
        };
        assert_eq!(run(42), run(42), "same seed is reproducible");
        assert_ne!(run(42), run(43), "different seeds diverge");
    }
}
