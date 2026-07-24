//! Capture the windowed / hashmap-update behaviour of a large resource. retinue accepts a
//! link, parses the advertisement, requests the parts it has hashes for, and logs every
//! part (0x01) and RESOURCE_HMU (0x04) packet so we can read the HMU format and the
//! windowing. Driven by `oracle/capture_hmu.py`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use retinue::announce::{self, RAND_HASH_LEN};
use retinue::destination::DestinationName;
use retinue::identity::PrivateIdentity;
use retinue::iface::tcp::{RecvError, TcpInterface, TcpInterfaceListener};
use retinue::link::{self, CTX_RESOURCE_REQ, Link, LinkMode, LinkTrailer};
use retinue::packet::{Packet, PacketType};
use retinue::resource::Advertisement;

const IDENTITY_SEED: [u8; 64] = [0x11; 64];
const EPHEMERAL_SEED: [u8; 64] = [0x77; 64];

fn rh() -> [u8; RAND_HASH_LEN] {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes();
    let mut o = [0u8; RAND_HASH_LEN];
    o.copy_from_slice(&n[..RAND_HASH_LEN]);
    o
}
fn iv(n: u8) -> [u8; 16] {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes();
    let mut v = [0u8; 16];
    v[..8].copy_from_slice(&t[..8]);
    v[15] = n;
    v
}
async fn send(i: &mut TcpInterface, p: &Packet) {
    i.send(p).await.expect("send");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (listener, addr) = TcpInterfaceListener::bind("127.0.0.1:0".parse()?)
        .await
        .map(|l| (l, ()))
        .map(|(l, _)| {
            let a = l.local_addr().unwrap();
            (l, a)
        })?;
    println!("LISTENING {}", addr.port());
    let mut iface = listener.accept().await?;

    let identity = PrivateIdentity::from_secret_bytes(&IDENTITY_SEED);
    let name = DestinationName::new("retinue", ["resource"]);
    let our_dest = name.destination_hash(identity.public());
    send(
        &mut iface,
        &announce::build(&identity, name.name_hash(), &rh(), None, b"res"),
    )
    .await;
    let mut cadence = tokio::time::interval(Duration::from_secs(2));
    cadence.tick().await;

    let mut link: Option<Link> = None;
    let mut requested = false;
    let mut iv_ctr = 10u8;
    let mut parts_seen = 0u32;
    let mut solicited = false;
    let mut res_hash: Option<Vec<u8>> = None;
    let mut last_maphash: Option<Vec<u8>> = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
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
            None if packet.packet_type == PacketType::LinkRequest
                && packet.destination == our_dest =>
            {
                let (l, proof) = link::accept(
                    &packet,
                    &identity,
                    &EPHEMERAL_SEED,
                    LinkTrailer {
                        mode: LinkMode::Aes256Cbc,
                        mtu: 500,
                    },
                )?;
                println!("LINK_UP");
                send(&mut iface, &proof).await;
                link = Some(l);
            }
            Some(l) if packet.destination == l.id() => match packet.context {
                0x02 => {
                    let plain = l.decrypt(&packet)?;
                    let adv = Advertisement::parse(&plain)?;
                    res_hash = Some(adv.resource_hash.clone());
                    // The last map hash the advertisement named: where the HMU resumes.
                    let n = adv.hashmap.len();
                    last_maphash = Some(adv.hashmap[n - 4..].to_vec());
                    println!(
                        "ADV parts={} hashmap_parts={} t={} d={} f={}",
                        adv.parts,
                        adv.hashmap_parts(),
                        adv.transfer_size,
                        adv.data_size,
                        adv.flags
                    );
                    if !requested {
                        requested = true;
                        // Request the parts named in the advertisement (the first window).
                        let mut req = vec![0x00];
                        req.extend_from_slice(&adv.resource_hash);
                        req.extend_from_slice(&adv.hashmap);
                        iv_ctr += 1;
                        send(
                            &mut iface,
                            &l.sealed_packet(CTX_RESOURCE_REQ, &req, &iv(iv_ctr)),
                        )
                        .await;
                        println!("REQ {} hashes", adv.hashmap_parts());
                    }
                }
                0x01 => {
                    parts_seen += 1;
                    // After the first advertised window, solicit the rest of the hashmap
                    // with an exhausted-flag (0xff) request, to draw out a RESOURCE_HMU.
                    if parts_seen == 70 && !solicited {
                        solicited = true;
                        if let (Some(rhash), Some(last)) = (res_hash.clone(), last_maphash.clone())
                        {
                            // exhausted request: 0xff || last_map_hash(4) || resource_hash(32)
                            let mut req = vec![0xff];
                            req.extend_from_slice(&last);
                            req.extend_from_slice(&rhash);
                            iv_ctr += 1;
                            send(
                                &mut iface,
                                &l.sealed_packet(CTX_RESOURCE_REQ, &req, &iv(iv_ctr)),
                            )
                            .await;
                            println!("SOLICIT_HMU (0xff || last {} || hash)", hex::encode(&last));
                        }
                    }
                }
                0x04 => {
                    // RESOURCE_HMU: decrypt and dump so we can read its structure.
                    let plain = l
                        .decrypt(&packet)
                        .unwrap_or_else(|_| packet.payload.clone());
                    println!("HMU {} bytes: {}", plain.len(), hex::encode(&plain));
                    if let Some(rh) = &res_hash {
                        println!("  res_hash    {}", hex::encode(rh));
                        println!(
                            "  hmu[0..32]  {}",
                            hex::encode(&plain[..32.min(plain.len())])
                        );
                        println!(
                            "  hmu[32..36] {}",
                            hex::encode(&plain[32..36.min(plain.len())])
                        );
                        println!(
                            "  hmu[36..]   {} ({} bytes = {} maphashes)",
                            hex::encode(&plain[36.min(plain.len())..]),
                            plain.len().saturating_sub(36),
                            plain.len().saturating_sub(36) / 4
                        );
                    }
                }
                other => println!("CTX 0x{other:02x} {} bytes", packet.payload.len()),
            },
            _ => {}
        }
    }
    println!("DONE");
    Ok(())
}
