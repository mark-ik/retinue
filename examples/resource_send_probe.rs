//! retinue sends an (uncompressed) resource to RNS, dumping RNS's responses so we can read
//! the RESOURCE_REQ and RESOURCE_PRF formats. retinue initiates the link.
//!
//! Driven by `oracle/capture_resource_send.py`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use retinue::destination::DestinationName;
use retinue::identity::PrivateIdentity;
use retinue::iface::tcp::{RecvError, TcpInterface, TcpInterfaceListener};
use retinue::link::{CTX_RESOURCE, CTX_RESOURCE_ADV, LinkMode, LinkTrailer, PendingLink};
use retinue::packet::{Packet, PacketType};
use retinue::resource;

const DEST_SEED: [u8; 64] = [0x11; 64];
const EPHEMERAL_SEED: [u8; 64] = [0x33; 64];

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
    let listener = TcpInterfaceListener::bind("127.0.0.1:0".parse()?).await?;
    println!("LISTENING {}", listener.local_addr()?.port());
    let mut iface = listener.accept().await?;
    // RNS 1.3.9 and 1.4.0 can start their TCP reader before interface setup assigns
    // `ifac_size`. An immediate first frame then tears down an otherwise valid connection.
    // This delay belongs to the black-box oracle probe, not to Retinue's TCP interface.
    tokio::time::sleep(Duration::from_millis(250)).await;

    let peer = *PrivateIdentity::from_secret_bytes(&DEST_SEED).public();
    let dest = DestinationName::new("retinue", ["recv"]).destination_hash(&peer);
    let (pending, request) = PendingLink::open(
        dest,
        peer,
        &EPHEMERAL_SEED,
        LinkTrailer {
            mode: LinkMode::Aes256Cbc,
            mtu: 500,
        },
    );
    send(&mut iface, &request).await;

    let link = loop {
        match tokio::time::timeout(Duration::from_secs(10), iface.recv()).await {
            Err(_) => {
                println!("TIMEOUT proof");
                return Ok(());
            }
            Ok(Err(_)) => continue,
            Ok(Ok(p)) if p.packet_type == PacketType::Proof => break pending.prove(&p)?,
            Ok(Ok(_)) => continue,
        }
    };
    println!("LINK {}", link.id());
    send(&mut iface, &link.rtt_packet(0.05, &iv(1))).await;
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Build an uncompressed resource: seal the data as one token, split into parts.
    // Small enough to stay in RNS's in-RAM path (larger ones hit its disk storage).
    let data: Vec<u8> = (0..300u32)
        .map(|i| (i.wrapping_mul(7).wrapping_add(3)) as u8)
        .collect();
    let random_hash = [0xA5, 0x5A, 0x12, 0x34];
    // The transferred content is random_hash || data; seal that, not the bare payload.
    let token = link.seal(&resource::content(&data, &random_hash), &iv(2));
    let (adv, parts) = resource::advertise(&data, &token, random_hash, false);
    let expected_proof = resource::proof(&data, &{
        let mut h = [0u8; 32];
        h.copy_from_slice(&adv.resource_hash);
        h
    });
    println!(
        "ADV t={} d={} n={} parts={}",
        adv.transfer_size,
        adv.data_size,
        adv.parts,
        parts.len()
    );
    println!("EXPECTED_PROOF {}", hex::encode(expected_proof));

    // Map each part by its 4-byte map hash, so a windowed request can be answered exactly.
    let by_maphash: std::collections::HashMap<[u8; 4], Vec<u8>> = parts
        .iter()
        .map(|p| (resource::map_hash(p, &random_hash), p.clone()))
        .collect();

    // Send the advertisement (sealed, context 0x02).
    send(
        &mut iface,
        &link.sealed_packet(CTX_RESOURCE_ADV, &adv.pack(), &iv(3)),
    )
    .await;
    println!("SENT_ADV");

    // Respond to whatever RNS asks. Dump every packet so we learn REQ (0x03) and PRF (0x05).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let packet = match tokio::time::timeout(remaining, iface.recv()).await {
            Err(_) => break,
            Ok(Err(RecvError::Wire(_))) => continue,
            Ok(Err(RecvError::Io(_))) => break,
            Ok(Ok(p)) if p.destination == link.id() => p,
            Ok(Ok(_)) => continue,
        };
        let dec = link.decrypt(&packet).ok();
        match &dec {
            Some(pt) => println!(
                "RX ctx=0x{:02x} decrypted[{}] {}",
                packet.context,
                pt.len(),
                hex::encode(pt)
            ),
            None => println!(
                "RX ctx=0x{:02x} raw[{}] {}",
                packet.context,
                packet.payload.len(),
                hex::encode(&packet.payload)
            ),
        }
        match packet.context {
            // Part request: flag(1) || resource_hash(32) || requested map_hash(4)*
            0x03 => {
                if let Some(pt) = &dec {
                    let hashes = &pt[1 + 32..];
                    let mut sent = 0;
                    for mh in hashes.chunks(4) {
                        let key: [u8; 4] = mh.try_into().unwrap();
                        if let Some(part) = by_maphash.get(&key) {
                            send(&mut iface, &link.framed_packet(CTX_RESOURCE, part.clone())).await;
                            sent += 1;
                        }
                    }
                    println!("REQ for {} parts, sent {}", hashes.len() / 4, sent);
                }
            }
            0x05 => {
                // The proof is sent unencrypted: resource_hash(32) || proof(32).
                match resource::parse_proof(&packet.payload) {
                    Some((_h, proof)) if proof == expected_proof => println!("PROOF_VERIFIED"),
                    Some(_) => println!("PROOF_MISMATCH"),
                    None => println!("PROOF_MALFORMED"),
                }
            }
            _ => {}
        }
    }
    println!("DONE");
    Ok(())
}
