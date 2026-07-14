//! The retinue half of the R2 gate: path request + address book against a transport node.
//!
//! retinue connects to a transport-enabled RNS, announces itself on a cadence, requests a
//! path to a target it has not heard from, and resolves that target once the transport node
//! relays its announce into retinue's address book.
//!
//! Driven by `oracle/interop_r2.py`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use retinue::address_book::AddressBook;
use retinue::announce::{self, Announce, RAND_HASH_LEN};
use retinue::destination::DestinationName;
use retinue::iface::tcp::{RecvError, TcpInterface, TcpInterfaceListener};
use retinue::identity::PrivateIdentity;
use retinue::packet::{Packet, PacketType};
use retinue::path;

/// retinue's own identity, announced on a cadence.
const OUR_SEED: [u8; 64] = [0x22; 64];
/// The target's identity, known so retinue can compute its destination hash and ask for it.
const TARGET_SEED: [u8; 64] = [0x44; 64];

fn rand_hash(salt: u8) -> [u8; RAND_HASH_LEN] {
    let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().to_le_bytes();
    let mut o = [0u8; RAND_HASH_LEN];
    o.copy_from_slice(&n[..RAND_HASH_LEN]);
    o[0] ^= salt;
    o
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpInterfaceListener::bind("127.0.0.1:0".parse()?).await?;
    println!("LISTENING {}", listener.local_addr()?.port());
    let mut iface: TcpInterface = listener.accept().await?;

    let our_id = PrivateIdentity::from_secret_bytes(&OUR_SEED);
    let our_name = DestinationName::new("retinue", ["r2"]);

    // The target we want a path to, computed from its known identity.
    let target_id = *PrivateIdentity::from_secret_bytes(&TARGET_SEED).public();
    let target_dest = DestinationName::new("retinue", ["target"]).destination_hash(&target_id);
    println!("TARGET {target_dest}");

    let mut book = AddressBook::new();

    // Announce ourselves up front so the transport node learns our path.
    let ann = announce::build(&our_id, our_name.name_hash(), &rand_hash(0), None, b"r2");
    iface.send(&ann).await?;
    println!("ANNOUNCED_SELF {}", our_name.destination_hash(our_id.public()));

    // Ask the transport node for a path to the target. Sent deterministically, before we
    // could possibly have resolved it, so the request is always exercised.
    iface.send(&path::path_request(target_dest, &[0x5A; 16])).await?;
    println!("SENT_PATH_REQUEST for {target_dest}");

    // Cadence: re-announce every 2s, the whole of what "announce cadence" means in the
    // shell. Run until the target resolves AND we have re-announced at least once, so both
    // behaviours are observed even if resolution is instant.
    let mut cadence = tokio::time::interval(Duration::from_secs(2));
    cadence.tick().await; // consume the immediate first tick
    let mut re_announced = false;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if tokio::time::Instant::now() >= deadline {
            println!("TIMEOUT");
            break;
        }
        if book.knows(target_dest) && re_announced {
            break;
        }
        tokio::select! {
            _ = cadence.tick() => {
                let a = announce::build(&our_id, our_name.name_hash(), &rand_hash(1), None, b"r2");
                let _ = iface.send(&a).await;
                re_announced = true;
                println!("RE_ANNOUNCED");
            }
            recv = iface.recv() => {
                match recv {
                    Err(RecvError::Io(_)) => break,
                    Err(RecvError::Wire(_)) => continue,
                    Ok(p) if p.packet_type == PacketType::Announce => {
                        if let Ok(a) = Announce::decode(&p) {
                            let dest = a.destination;
                            let newly = !book.knows(target_dest);
                            book.ingest(&a);
                            println!("INGESTED {dest} (book size {})", book.len());
                            if newly && book.knows(target_dest) {
                                let peer = book.resolve(target_dest).unwrap();
                                println!("RESOLVED_TARGET identity={}", peer.identity.hash());
                            }
                        }
                    }
                    Ok(_) => {}
                }
            }
        }
    }

    println!("DONE resolved={}", book.knows(target_dest));
    Ok(())
}

// keep the unused-in-some-builds import honest
const _: fn(&Packet) = |_p| {};
