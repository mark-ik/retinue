//! retinue sends a >74-part resource to RNS using the windowed Outgoing sender: advertise
//! the first 74 hashes, serve part requests, and emit RESOURCE_HMU when RNS's hashmap runs
//! out. Verifies RNS's returned proof. Driven by `oracle/interop_send_large.py`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use retinue::destination::DestinationName;
use retinue::identity::PrivateIdentity;
use retinue::iface::tcp::{RecvError, TcpInterface, TcpInterfaceListener};
use retinue::link::{
    CTX_RESOURCE, CTX_RESOURCE_ADV, CTX_RESOURCE_HMU, LinkMode, LinkTrailer, PendingLink,
};
use retinue::packet::{Packet, PacketType};
use retinue::resource::{self, Outgoing};

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
                println!("TIMEOUT");
                return Ok(());
            }
            Ok(Err(_)) => continue,
            Ok(Ok(p)) if p.packet_type == PacketType::Proof => break pending.prove(&p)?,
            Ok(Ok(_)) => continue,
        }
    };
    send(&mut iface, &link.rtt_packet(0.05, &iv(1))).await;
    tokio::time::sleep(Duration::from_millis(400)).await;

    // A 120 KB uncompressed resource: 259 parts, so HMU is exercised.
    let data: Vec<u8> = (0..120_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 8) as u8)
        .collect();
    let random_hash = [0xA5, 0x5A, 0x12, 0x34];
    let token = link.seal(&resource::content(&data, &random_hash), &iv(2));
    let mut out = Outgoing::new(&data, &token, random_hash, false);
    let expected = out.expected_proof();
    println!("SENDING {} parts", out.total_parts());

    send(
        &mut iface,
        &link.sealed_packet(CTX_RESOURCE_ADV, &out.advertisement().pack(), &iv(3)),
    )
    .await;
    println!("SENT_ADV");

    let mut ivc = 10u8;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let packet = match tokio::time::timeout(remaining, iface.recv()).await {
            Err(_) => break,
            Ok(Err(RecvError::Wire(_))) => continue,
            Ok(Err(RecvError::Io(_))) => break,
            Ok(Ok(p)) if p.destination == link.id() => p,
            Ok(Ok(_)) => continue,
        };
        match packet.context {
            0x03 => {
                let req = resource::parse_request(&link.decrypt(&packet)?)?;
                // Serve the requested parts.
                for part in out.serve(&req) {
                    send(&mut iface, &link.framed_packet(CTX_RESOURCE, part)).await;
                }
                // If exhausted, emit the next hashmap batch.
                if req.exhausted
                    && let Some(last) = req.last_map_hash
                {
                    ivc = ivc.wrapping_add(1);
                    let hmu = out.hmu_after(&last);
                    send(
                        &mut iface,
                        &link.sealed_packet(CTX_RESOURCE_HMU, &hmu, &iv(ivc)),
                    )
                    .await;
                    println!("SENT_HMU");
                }
            }
            0x05 => {
                match resource::parse_proof(&packet.payload) {
                    Some((_h, proof)) if proof == expected => println!("PROOF_VERIFIED"),
                    _ => println!("PROOF_BAD"),
                }
                break;
            }
            _ => {}
        }
    }
    println!("DONE");
    Ok(())
}
