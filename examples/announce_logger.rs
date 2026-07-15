//! Connect to an interface, announce a destination, and log every announce received (with
//! its hop count). Used to observe how a transport node propagates announces. The label and
//! target address come from env vars RETINUE_LABEL and RETINUE_ADDR.

use std::time::Duration;

use retinue::announce::{self, RAND_HASH_LEN};
use retinue::destination::DestinationName;
use retinue::identity::PrivateIdentity;
use retinue::packet::{Packet, PacketType};

fn rh(salt: u8) -> [u8; RAND_HASH_LEN] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().to_le_bytes();
    let mut o = [0u8; RAND_HASH_LEN];
    o.copy_from_slice(&n[..RAND_HASH_LEN]);
    o[0] ^= salt;
    o
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let label = std::env::var("RETINUE_LABEL").unwrap_or_else(|_| "x".into());
    let addr: std::net::SocketAddr = std::env::var("RETINUE_ADDR")?.parse()?;

    // Deterministic identity per label so its destination is stable.
    let mut seed = [0u8; 64];
    seed[0] = label.as_bytes()[0];
    let identity = PrivateIdentity::from_secret_bytes(&seed);
    let name = DestinationName::new("retinue", [label.as_str()]);
    let our_dest = name.destination_hash(identity.public());
    println!("SELF {label} {our_dest}");

    use retinue::iface::tcp::TcpInterface;
    let mut iface = TcpInterface::connect(addr).await?;

    // Announce ourselves a few times.
    let mut salt = 0u8;
    tokio::spawn({
        // separate connection for announcing would need a second socket; instead announce
        // inline before the receive loop and periodically.
        async move {}
    });

    // Announce, then log inbound announces (and keep re-announcing).
    let announce_every = Duration::from_secs(1);
    let mut ticker = tokio::time::interval(announce_every);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    // Send the first announce immediately.
    iface.send(&announce::build(&identity, name.name_hash(), &rh(salt), None, label.as_bytes())).await?;

    loop {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::select! {
            _ = ticker.tick() => {
                salt = salt.wrapping_add(1);
                let _ = iface.send(&announce::build(&identity, name.name_hash(), &rh(salt), None, label.as_bytes())).await;
            }
            r = iface.recv() => {
                match r {
                    Ok(pkt) if pkt.packet_type == PacketType::Announce => {
                        // Log dest + hops + header type + transport id. Skip our own.
                        if pkt.destination != our_dest {
                            let _: &Packet = &pkt;
                            println!(
                                "RECV_ANNOUNCE dest={} hops={} header={:?} transport={}",
                                pkt.destination,
                                pkt.hops,
                                pkt.header_type,
                                pkt.transport.map(|t| t.to_string()).unwrap_or_else(|| "none".into()),
                            );
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
    }
    println!("DONE {label}");
    Ok(())
}
