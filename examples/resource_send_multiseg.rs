//! retinue sends a multi-megabyte resource to RNS as several segments (each ~1 MB), with
//! per-segment windowed transfer + HMU + proof. Verifies each segment's returned proof.
//! Driven by `oracle/interop_send_multiseg.py`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use retinue::destination::DestinationName;
use retinue::identity::PrivateIdentity;
use retinue::iface::tcp::{RecvError, TcpInterface, TcpInterfaceListener};
use retinue::link::{
    CTX_RESOURCE, CTX_RESOURCE_ADV, CTX_RESOURCE_HMU, Link, LinkMode, LinkTrailer, PendingLink,
};
use retinue::packet::{Packet, PacketType};
use retinue::resource::{self, MAX_SEGMENT_SIZE, Outgoing};

const DEST_SEED: [u8; 64] = [0x11; 64];
const EPHEMERAL_SEED: [u8; 64] = [0x33; 64];
const TOTAL: usize = 2_500_000;

fn iv(n: u64) -> [u8; 16] {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes();
    let mut v = [0u8; 16];
    v[..8].copy_from_slice(&t[..8]);
    v[8..16].copy_from_slice(&n.to_le_bytes());
    v
}
async fn send(i: &mut TcpInterface, p: &Packet) {
    i.send(p).await.expect("send");
}

/// Drive one segment to completion: advertise, serve requests + HMU, verify the proof.
async fn send_segment(
    iface: &mut TcpInterface,
    link: &Link,
    mut out: Outgoing,
    ivc: &mut u64,
) -> Result<bool, Box<dyn std::error::Error>> {
    let expected = out.expected_proof();
    *ivc += 1;
    send(
        iface,
        &link.sealed_packet(CTX_RESOURCE_ADV, &out.advertisement().pack(), &iv(*ivc)),
    )
    .await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
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
                for part in out.serve(&req) {
                    send(iface, &link.framed_packet(CTX_RESOURCE, part)).await;
                }
                if req.exhausted
                    && let Some(last) = req.last_map_hash
                {
                    *ivc += 1;
                    let hmu = out.hmu_after(&last);
                    send(
                        iface,
                        &link.sealed_packet(CTX_RESOURCE_HMU, &hmu, &iv(*ivc)),
                    )
                    .await;
                }
            }
            0x05 => {
                return Ok(
                    matches!(resource::parse_proof(&packet.payload), Some((_h, p)) if p == expected),
                );
            }
            _ => {}
        }
    }
    Ok(false)
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

    let data: Vec<u8> = (0..TOTAL as u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 8) as u8)
        .collect();
    let segments = data.chunks(MAX_SEGMENT_SIZE).count();
    println!("SENDING {} bytes in {} segments", data.len(), segments);

    let mut ivc = 100u64;
    let mut all_ok = true;
    // The whole-resource identity is the FIRST segment's hash, shared across all segments so
    // RNS groups them into one resource. Compute it up front.
    let seg0_rh = [1u8, 0x5A, 0x12, 0x34];
    let original_hash =
        resource::resource_hash(&data[..data.len().min(MAX_SEGMENT_SIZE)], &seg0_rh);

    for (idx, chunk) in data.chunks(MAX_SEGMENT_SIZE).enumerate() {
        // Fresh random hash per segment (segment 0 must match the identity computed above).
        let rh = [(idx as u8).wrapping_add(1), 0x5A, 0x12, 0x34];
        ivc += 1;
        let token = link.seal(&resource::content(chunk, &rh), &iv(ivc));
        let out = Outgoing::new(chunk, &token, rh, false).with_segment(
            idx as i64 + 1,
            segments as i64,
            data.len() as u64,
            original_hash,
        );
        let ok = send_segment(&mut iface, &link, out, &mut ivc).await?;
        println!("SEGMENT {}/{} proof_ok={}", idx + 1, segments, ok);
        all_ok &= ok;
    }
    println!("ALL_SEGMENTS_SENT ok={all_ok}");
    println!("DONE");
    Ok(())
}
