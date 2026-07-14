//! Probe the response format: retinue sends a real request to an RNS handler and dumps the
//! decrypted response. Inline msgpack here is throwaway; the real codec lands once both
//! directions are known. Driven by `oracle/capture_reqresp_response.py`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use retinue::destination::DestinationName;
use retinue::hash::AddressHash;
use retinue::iface::tcp::{TcpInterface, TcpInterfaceListener};
use retinue::identity::PrivateIdentity;
use retinue::link::{Inbound, LinkMode, LinkTrailer, PendingLink};
use retinue::packet::{Packet, PacketType};

const DEST_SEED: [u8; 64] = [0x11; 64];
const EPHEMERAL_SEED: [u8; 64] = [0x33; 64];

fn iv(n: u8) -> [u8; 16] {
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().to_le_bytes();
    let mut v = [0u8; 16];
    v[..8].copy_from_slice(&t[..8]);
    v[15] = n;
    v
}

/// Pack `[time_f64, path_hash(16), data]` the way RNS does: fixarray(3), float64, and
/// bin8-tagged byte strings.
fn pack_request(path: &[u8], data: &[u8]) -> Vec<u8> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
    let path_hash = AddressHash::of(path);
    let mut out = vec![0x93, 0xcb];
    out.extend_from_slice(&now.to_be_bytes());
    out.push(0xc4);
    out.push(16);
    out.extend_from_slice(path_hash.as_slice());
    out.push(0xc4);
    out.push(data.len() as u8);
    out.extend_from_slice(data);
    out
}

async fn send(iface: &mut TcpInterface, p: &Packet) {
    iface.send(p).await.expect("send");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpInterfaceListener::bind("127.0.0.1:0".parse()?).await?;
    println!("LISTENING {}", listener.local_addr()?.port());
    let mut iface = listener.accept().await?;

    let peer = *PrivateIdentity::from_secret_bytes(&DEST_SEED).public();
    let dest = DestinationName::new("retinue", ["reqresp"]).destination_hash(&peer);
    let (pending, request) = PendingLink::open(
        dest, peer, &EPHEMERAL_SEED, LinkTrailer { mode: LinkMode::Aes256Cbc, mtu: 500 },
    );
    send(&mut iface, &request).await;

    // Establish.
    let link = loop {
        match tokio::time::timeout(Duration::from_secs(10), iface.recv()).await {
            Err(_) => { println!("TIMEOUT"); return Ok(()); }
            Ok(Err(_)) => continue,
            Ok(Ok(p)) if p.packet_type == PacketType::Proof => break pending.prove(&p)?,
            Ok(Ok(_)) => continue,
        }
    };
    println!("LINK_ESTABLISHED {}", link.id());
    send(&mut iface, &link.rtt_packet(0.05, &iv(1))).await;
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Send the request.
    let packed = pack_request(b"/echo", b"ping123");
    let req_pkt = link.request_packet(&packed, &iv(2));
    println!("REQUEST_SENT {}", hex::encode(&packed));
    println!("REQUEST_PACKET_RAW {}", hex::encode(req_pkt.encode()));
    send(&mut iface, &req_pkt).await;

    // Await the response.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, iface.recv()).await {
            Err(_) => break,
            Ok(Err(_)) => continue,
            Ok(Ok(p)) => match link.receive(&p) {
                Some(Inbound::Response(data)) => {
                    println!("RESPONSE_PLAINTEXT {}", hex::encode(&data));
                    break;
                }
                Some(Inbound::Data(d)) => println!("DATA {}", hex::encode(&d)),
                _ => {}
            },
        }
    }
    println!("DONE");
    Ok(())
}
