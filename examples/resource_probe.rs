//! Dump every link packet RNS sends, decrypted, so we can reverse the resource protocol.
//!
//! retinue is the responder. After the link is up, it prints `(context, decrypted-hex)` for
//! every packet on the link, without interpreting it. Driven by `oracle/capture_resource.py`,
//! which sends retinue a small multi-part resource.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use retinue::announce::{self, RAND_HASH_LEN};
use retinue::destination::DestinationName;
use retinue::iface::tcp::{RecvError, TcpInterface, TcpInterfaceListener};
use retinue::identity::PrivateIdentity;
use retinue::link::{self, Link, LinkMode, LinkTrailer};
use retinue::packet::{Packet, PacketType};

const IDENTITY_SEED: [u8; 64] = [0x11; 64];
const EPHEMERAL_SEED: [u8; 64] = [0x77; 64];

fn rh() -> [u8; RAND_HASH_LEN] {
    let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().to_le_bytes();
    let mut o = [0u8; RAND_HASH_LEN];
    o.copy_from_slice(&n[..RAND_HASH_LEN]);
    o
}
async fn send(iface: &mut TcpInterface, p: &Packet) { iface.send(p).await.expect("send"); }

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpInterfaceListener::bind("127.0.0.1:0".parse()?).await?;
    println!("LISTENING {}", listener.local_addr()?.port());
    let mut iface = listener.accept().await?;

    let identity = PrivateIdentity::from_secret_bytes(&IDENTITY_SEED);
    let name = DestinationName::new("retinue", ["resource"]);
    let our_dest = name.destination_hash(identity.public());
    send(&mut iface, &announce::build(&identity, name.name_hash(), &rh(), None, b"res")).await;

    // Re-announce until a link arrives. A single announce races the driver's handler
    // registration (RNS's interface connects during Reticulum() init, before the Python
    // side registers its announce handler), which is exactly how the first introspection
    // run silently saw nothing.
    let mut cadence = tokio::time::interval(Duration::from_secs(2));
    cadence.tick().await;

    let mut link: Option<Link> = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let packet = tokio::select! {
            _ = cadence.tick(), if link.is_none() => {
                send(&mut iface, &announce::build(&identity, name.name_hash(), &rh(), None, b"res")).await;
                continue;
            }
            r = tokio::time::timeout(remaining, iface.recv()) => match r {
                Err(_) => break,
                Ok(Err(RecvError::Wire(_))) => continue,
                Ok(Err(RecvError::Io(_))) => break,
                Ok(Ok(p)) => p,
            },
        };
        match &link {
            None if packet.packet_type == PacketType::LinkRequest && packet.destination == our_dest => {
                let (l, proof) = link::accept(&packet, &identity, &EPHEMERAL_SEED,
                    LinkTrailer { mode: LinkMode::Aes256Cbc, mtu: 500 })?;
                println!("LINK_UP {}", l.id());
                send(&mut iface, &proof).await;
                link = Some(l);
            }
            Some(l) if packet.destination == l.id() => {
                // Decrypt whatever it is (data/resource contexts are all token-encrypted)
                // and dump context + plaintext. RTT (0xfe) and keepalive (0xfa) too.
                match l.decrypt(&packet) {
                    Ok(pt) => println!("PKT ctx=0x{:02x} len={} {}", packet.context, pt.len(), hex::encode(&pt)),
                    Err(_) => println!("PKT ctx=0x{:02x} (undecryptable, {} raw bytes) {}",
                        packet.context, packet.payload.len(), hex::encode(&packet.payload)),
                }
            }
            _ => {}
        }
    }
    println!("DONE");
    Ok(())
}
