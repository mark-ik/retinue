//! retinue receives a resource from RNS: parse the advertisement, request the parts, collect
//! them, reassemble + decrypt + verify, and send the proof. RNS then concludes COMPLETE.
//!
//! Handles single-segment uncompressed resources (the gate sends `auto_compress=False`).
//! Driven by `oracle/interop_resource_recv.py`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use retinue::announce::{self, RAND_HASH_LEN};
use retinue::destination::DestinationName;
use retinue::iface::tcp::{RecvError, TcpInterface, TcpInterfaceListener};
use retinue::identity::PrivateIdentity;
use retinue::link::{self, Link, LinkMode, LinkTrailer, CTX_RESOURCE_REQ};
use retinue::packet::{Packet, PacketType};
use retinue::resource::{Advertisement, Incoming};

const IDENTITY_SEED: [u8; 64] = [0x11; 64];
const EPHEMERAL_SEED: [u8; 64] = [0x77; 64];

fn rh() -> [u8; RAND_HASH_LEN] {
    let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().to_le_bytes();
    let mut o = [0u8; RAND_HASH_LEN];
    o.copy_from_slice(&n[..RAND_HASH_LEN]);
    o
}
fn iv(n: u8) -> [u8; 16] {
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().to_le_bytes();
    let mut v = [0u8; 16];
    v[..8].copy_from_slice(&t[..8]);
    v[15] = n;
    v
}
async fn send(i: &mut TcpInterface, p: &Packet) { i.send(p).await.expect("send"); }

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpInterfaceListener::bind("127.0.0.1:0".parse()?).await?;
    println!("LISTENING {}", listener.local_addr()?.port());
    let mut iface = listener.accept().await?;

    let identity = PrivateIdentity::from_secret_bytes(&IDENTITY_SEED);
    let name = DestinationName::new("retinue", ["resource"]);
    let our_dest = name.destination_hash(identity.public());
    send(&mut iface, &announce::build(&identity, name.name_hash(), &rh(), None, b"res")).await;

    let mut cadence = tokio::time::interval(Duration::from_secs(2));
    cadence.tick().await;

    let mut link: Option<Link> = None;
    let mut incoming: Option<Incoming> = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(40);

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
                match packet.context {
                    // Advertisement: parse, request all parts.
                    0x02 => {
                        let plain = l.decrypt(&packet)?;
                        let adv = Advertisement::parse(&plain)?;
                        println!("ADV t={} d={} n={} compressed={}",
                            adv.transfer_size, adv.data_size, adv.parts,
                            adv.flags & 0x02 != 0);
                        let inc = Incoming::new(&adv)?;
                        send(&mut iface, &l.sealed_packet(CTX_RESOURCE_REQ, &inc.request_payload(), &iv(1))).await;
                        println!("REQUESTED {} parts", adv.parts);
                        incoming = Some(inc);
                    }
                    // Part: raw token slice.
                    0x01 => {
                        if let Some(inc) = incoming.as_mut() {
                            inc.accept_part(&packet.payload);
                            if inc.is_complete() {
                                let token = inc.assemble_token()?;
                                let decrypted = l.open(&token)?;
                                // recover: decompress if flagged, strip prefix, verify.
                                match inc.recover(&decrypted) {
                                    Ok(data) => {
                                        println!("ASSEMBLED token={} data={} compressed={}",
                                            token.len(), data.len(), inc.is_compressed());
                                        let proof = inc.proof(&data);
                                        send(&mut iface, &l.resource_proof_packet(&inc.resource_hash(), &proof)).await;
                                        println!("SENT_PROOF {}", hex::encode(proof));
                                        println!("DATA {}", hex::encode(&data));
                                    }
                                    Err(e) => println!("RECOVER_FAILED {e}"),
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    println!("DONE");
    Ok(())
}
