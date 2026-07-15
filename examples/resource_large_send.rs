//! retinue sends a >74-part resource advertising only the first 74 hashes, and logs every
//! request RNS makes, so we can read how RNS solicits the rest of the hashmap (RESOURCE_HMU)
//! and how the exhausted flag works. Driven by `oracle/capture_large_send.py`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use retinue::destination::DestinationName;
use retinue::iface::tcp::{TcpInterface, TcpInterfaceListener};
use retinue::identity::PrivateIdentity;
use retinue::link::{LinkMode, LinkTrailer, PendingLink, CTX_RESOURCE, CTX_RESOURCE_ADV};
use retinue::packet::{Packet, PacketType};
use retinue::resource::{self, Advertisement, MAPHASH_LEN};

const DEST_SEED: [u8; 64] = [0x11; 64];
const EPHEMERAL_SEED: [u8; 64] = [0x33; 64];
const ADV_HASHES: usize = 74; // RNS HASHMAP_MAX_LEN

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

    let peer = *PrivateIdentity::from_secret_bytes(&DEST_SEED).public();
    let dest = DestinationName::new("retinue", ["recv"]).destination_hash(&peer);
    let (pending, request) = PendingLink::open(
        dest, peer, &EPHEMERAL_SEED, LinkTrailer { mode: LinkMode::Aes256Cbc, mtu: 500 },
    );
    send(&mut iface, &request).await;
    let link = loop {
        match tokio::time::timeout(Duration::from_secs(10), iface.recv()).await {
            Err(_) => { println!("TIMEOUT"); return Ok(()); }
            Ok(Err(_)) => continue,
            Ok(Ok(p)) if p.packet_type == PacketType::Proof => break pending.prove(&p)?,
            Ok(Ok(_)) => continue,
        }
    };
    send(&mut iface, &link.rtt_packet(0.05, &iv(1))).await;
    tokio::time::sleep(Duration::from_millis(400)).await;

    // A 40 KB uncompressed resource: 87 parts.
    let data: Vec<u8> = (0..40000u32).map(|i| (i.wrapping_mul(131).wrapping_add(7)) as u8).collect();
    let random_hash = [0xA5, 0x5A, 0x12, 0x34];
    let token = link.seal(&resource::content(&data, &random_hash), &iv(2));
    let (full_adv, parts) = resource::advertise(&data, &token, random_hash, false);
    println!("PARTS {} (advertising first {})", parts.len(), ADV_HASHES);
    // Print map hashes around the advertised/un-advertised boundary, and the resource hash,
    // so we can identify what an exhausted-flag request references.
    for i in [72usize, 73, 74, 75, 86] {
        if let Some(p) = parts.get(i) {
            println!("MAPHASH[{i}] {}", hex::encode(resource::map_hash(p, &random_hash)));
        }
    }
    println!("RESHASH {}", hex::encode(&full_adv.resource_hash));
    println!("RESHASH16 {}", hex::encode(&full_adv.resource_hash[..4]));

    let by_maphash: std::collections::HashMap<[u8; 4], Vec<u8>> = parts
        .iter()
        .map(|p| (resource::map_hash(p, &random_hash), p.clone()))
        .collect();

    // Advertise with a truncated hashmap (first 74 hashes), parts count = full.
    let mut adv = full_adv.clone();
    adv.hashmap.truncate(ADV_HASHES * MAPHASH_LEN);
    let _ = Advertisement::parse(&adv.pack()); // sanity
    send(&mut iface, &link.sealed_packet(CTX_RESOURCE_ADV, &adv.pack(), &iv(3))).await;
    println!("SENT_ADV parts={} hashmap_parts={}", adv.parts, adv.hashmap_parts());

    let mut ivc = 10u8;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let packet = match tokio::time::timeout(remaining, iface.recv()).await {
            Err(_) => break,
            Ok(Err(_)) => continue,
            Ok(Ok(p)) if p.destination == link.id() => p,
            Ok(Ok(_)) => continue,
        };
        if packet.context == 0x03 {
            let pt = link.decrypt(&packet)?;
            let flag = pt[0];
            let hashes = &pt[1 + 32..];
            if flag == 0xff {
                println!("REQ0xFF full={}", hex::encode(&pt));
            }
            println!("REQ flag=0x{:02x} hashes={} tail={}", flag, hashes.len() / 4,
                hex::encode(&pt[1 + 32..(1 + 32 + 16).min(pt.len())]));
            // Serve any requested parts we recognise.
            let mut sent = 0;
            for mh in hashes.chunks(4) {
                if let Ok(k) = <[u8; 4]>::try_from(mh)
                    && let Some(part) = by_maphash.get(&k)
                {
                    ivc = ivc.wrapping_add(1);
                    send(&mut iface, &link.framed_packet(CTX_RESOURCE, part.clone())).await;
                    sent += 1;
                }
            }
            println!("  served {sent}");
        } else {
            println!("CTX 0x{:02x} {} bytes", packet.context, packet.payload.len());
        }
    }
    println!("DONE");
    Ok(())
}
