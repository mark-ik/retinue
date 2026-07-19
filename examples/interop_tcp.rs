//! The retinue half of the R1 live interop gate.
//!
//! Binds a TCP interface, waits for RNS to connect to it, then:
//!   - receives and validates whatever RNS announces, and
//!   - announces its own destination, which RNS must accept.
//!
//! Driven by `oracle/interop_r1.py`, which starts this, points a real RNS
//! `TCPClientInterface` at it, and checks both directions. Run that, not this.
//!
//! Prints machine-readable lines the driver greps for. Keep them stable.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use retinue::announce::{self, Announce, RAND_HASH_LEN};
use retinue::destination::DestinationName;
use retinue::identity::PrivateIdentity;
use retinue::iface::tcp::{RecvError, TcpInterfaceListener};
use retinue::packet::PacketType;

/// retinue's own identity for the gate. Deliberately not the oracle's, so the two
/// announce distinct destinations and neither can be mistaken for the other.
const RETINUE_SEED: [u8; 64] = [0x11; 64];

/// A fresh rand_hash per run. R0 has no RNG by design (it is sans-io and reproducible), so
/// supplying this is the shell's job. Uniqueness is all that matters here: RNS treats the
/// field as opaque, but a byte-identical announce would look like a duplicate.
fn rand_hash() -> [u8; RAND_HASH_LEN] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after 1970")
        .as_nanos()
        .to_le_bytes();
    let mut out = [0u8; RAND_HASH_LEN];
    out.copy_from_slice(&nanos[..RAND_HASH_LEN]);
    out
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpInterfaceListener::bind("127.0.0.1:0".parse()?).await?;
    let port = listener.local_addr()?.port();

    // The driver reads this line to learn where to point RNS.
    println!("LISTENING {port}");

    let mut iface = listener.accept().await?;
    println!("ACCEPTED {}", iface.peer_addr()?);

    // --- our direction: announce ourselves, and see whether RNS accepts it.
    let identity = PrivateIdentity::from_secret_bytes(&RETINUE_SEED);
    let name = DestinationName::new("retinue", ["interop"]);
    let packet = announce::build(
        &identity,
        name.name_hash(),
        &rand_hash(),
        None,
        b"hello-from-retinue",
    );
    let dest = name.destination_hash(identity.public());
    iface.send(&packet).await?;
    println!("SENT_ANNOUNCE {dest}");

    // --- their direction: receive whatever RNS announces, and validate it ourselves.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            println!("TIMEOUT waiting for an announce from RNS");
            return Ok(());
        }

        match tokio::time::timeout(remaining, iface.recv()).await {
            Err(_) => {
                println!("TIMEOUT waiting for an announce from RNS");
                return Ok(());
            }
            Ok(Err(RecvError::Io(e))) => {
                println!("IO_ERROR {e}");
                return Ok(());
            }
            // A frame we could not decode is a bad packet, not a bad connection. RNS sends
            // interface chatter we do not model; skip it and keep listening.
            Ok(Err(RecvError::Wire(e))) => {
                println!("SKIPPED undecodable frame: {e}");
            }
            Ok(Ok(p)) => {
                if p.packet_type != PacketType::Announce {
                    println!("SKIPPED non-announce packet type {:?}", p.packet_type);
                    continue;
                }
                match Announce::decode(&p) {
                    Ok(a) => {
                        println!(
                            "RECV_ANNOUNCE {} ratchet={}",
                            a.destination,
                            a.ratchet.is_some()
                        );
                        println!("  identity  {}", a.identity.hash());
                        println!("  app_data  {:?}", String::from_utf8_lossy(&a.app_data));
                        println!("VALIDATED_RNS_ANNOUNCE");
                        // Give RNS a moment to process ours before we hang up.
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        return Ok(());
                    }
                    Err(e) => {
                        // This is the failure that matters: a real RNS announce we could
                        // not validate means we are not wire-compatible.
                        println!("REJECTED_RNS_ANNOUNCE {e}");
                        return Ok(());
                    }
                }
            }
        }
    }
}
