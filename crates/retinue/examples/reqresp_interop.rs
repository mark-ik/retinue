//! The retinue half of the R3 request/response gate.
//!
//! retinue initiates a link to an RNS destination, sends a request to its `/echo` handler,
//! and checks the response ties back by request id. Then, over the same connection, it acts
//! as a responder for a request RNS sends the other way.
//!
//! Driven by `oracle/interop_reqresp.py`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use retinue::announce::{self, RAND_HASH_LEN};
use retinue::destination::DestinationName;
use retinue::identity::PrivateIdentity;
use retinue::iface::tcp::{RecvError, TcpInterface, TcpInterfaceListener};
use retinue::link::{self, Inbound, LinkMode, LinkTrailer, PendingLink};
use retinue::packet::{Packet, PacketType};
use retinue::request::{Request, Response};

/// The RNS destination retinue calls into (fixed seed, known to both).
const DEST_SEED: [u8; 64] = [0x11; 64];
const EPHEMERAL_SEED: [u8; 64] = [0x33; 64];
/// retinue's own responder identity, for the reverse direction.
const OUR_SEED: [u8; 64] = [0x55; 64];
const OUR_EPHEMERAL: [u8; 64] = [0x77; 64];

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
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
async fn send(iface: &mut TcpInterface, p: &Packet) {
    iface.send(p).await.expect("send");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpInterfaceListener::bind("127.0.0.1:0".parse()?).await?;
    println!("LISTENING {}", listener.local_addr()?.port());
    let mut iface = listener.accept().await?;
    tokio::time::sleep(Duration::from_millis(250)).await;

    // Announce our responder destination so RNS can call us back.
    let our_id = PrivateIdentity::from_secret_bytes(&OUR_SEED);
    let our_name = DestinationName::new("retinue", ["svc"]);
    let our_dest = our_name.destination_hash(our_id.public());
    send(
        &mut iface,
        &announce::build(&our_id, our_name.name_hash(), &rh(), None, b"svc"),
    )
    .await;

    // --- Direction 1: retinue -> RNS request.
    let peer = *PrivateIdentity::from_secret_bytes(&DEST_SEED).public();
    let dest = DestinationName::new("retinue", ["reqresp"]).destination_hash(&peer);
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

    let out_link = loop {
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
    send(&mut iface, &out_link.rtt_packet(0.05, &iv(1))).await;
    tokio::time::sleep(Duration::from_millis(400)).await;

    let req = Request::new(b"/echo", b"ping-from-retinue".to_vec(), now());
    let req_pkt = out_link.request_packet(&req.pack(), &iv(2));
    let request_id = req_pkt.hash(); // what the response must reference
    send(&mut iface, &req_pkt).await;
    println!("SENT_REQUEST id={request_id}");

    // Meanwhile, act as responder for RNS's inbound link + request.
    let mut resp_link: Option<retinue::link::Link> = None;
    let mut direction1_done = false;
    let mut direction2_done = false;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline && !(direction1_done && direction2_done) {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let packet = match tokio::time::timeout(remaining, iface.recv()).await {
            Err(_) => break,
            Ok(Err(RecvError::Wire(_))) => continue,
            Ok(Err(RecvError::Io(_))) => break,
            Ok(Ok(p)) => p,
        };

        // Direction 1: our outbound link carries the response.
        if let Some(Inbound::Response(bytes)) = out_link.receive(&packet) {
            match Response::unpack(&bytes) {
                Ok(resp) => {
                    let matched = resp.request_id == request_id;
                    println!(
                        "RECV_RESPONSE data={} id_match={}",
                        String::from_utf8_lossy(&resp.data),
                        matched,
                    );
                    direction1_done = true;
                }
                Err(e) => println!("RESPONSE_PARSE_FAILED {e}"),
            }
            continue;
        }

        // Direction 2: RNS opens a link to our /svc destination and sends a request.
        match &resp_link {
            None if packet.packet_type == PacketType::LinkRequest
                && packet.destination == our_dest =>
            {
                let (l, proof) = link::accept(
                    &packet,
                    &our_id,
                    &OUR_EPHEMERAL,
                    LinkTrailer {
                        mode: LinkMode::Aes256Cbc,
                        mtu: 500,
                    },
                )?;
                send(&mut iface, &proof).await;
                resp_link = Some(l);
            }
            Some(l) => {
                if let Some(Inbound::Request(bytes)) = l.receive(&packet) {
                    let incoming = Request::unpack(&bytes)?;
                    // request_id is the hash of the received request packet.
                    let id = packet.hash();
                    let mut data = b"retinue-echo:".to_vec();
                    data.extend_from_slice(&incoming.data);
                    let response = Response::new(id, data);
                    send(&mut iface, &l.response_packet(&response.pack(), &iv(3))).await;
                    println!("ANSWERED_REQUEST");
                    direction2_done = true;
                }
            }
            None => {}
        }
    }

    println!("DONE d1={direction1_done} d2={direction2_done}");
    Ok(())
}
