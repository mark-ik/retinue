//! Probe the request/response wire format over a link.
//!
//! retinue is the responder. It announces, accepts an inbound link, then dumps the
//! DECRYPTED plaintext of any request (context 0x09) or response (0x0a) it sees, as hex, so
//! we can read RNS's msgpack packing off the wire rather than guessing it.
//!
//! Driven by `oracle/capture_reqresp.py`, which links to retinue and sends a request.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use retinue::announce::{self, RAND_HASH_LEN};
use retinue::destination::DestinationName;
use retinue::iface::tcp::{RecvError, TcpInterface, TcpInterfaceListener};
use retinue::identity::PrivateIdentity;
use retinue::link::{self, Inbound, Link, LinkMode, LinkTrailer};
use retinue::packet::{Packet, PacketType};

const IDENTITY_SEED: [u8; 64] = [0x11; 64];
const EPHEMERAL_SEED: [u8; 64] = [0x77; 64];

fn rand_hash() -> [u8; RAND_HASH_LEN] {
    let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().to_le_bytes();
    let mut o = [0u8; RAND_HASH_LEN];
    o.copy_from_slice(&n[..RAND_HASH_LEN]);
    o
}

fn iv(n: u8) -> [u8; 16] {
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().to_le_bytes();
    let mut iv = [0u8; 16];
    iv[..8].copy_from_slice(&t[..8]);
    iv[15] = n;
    iv
}

async fn send(iface: &mut TcpInterface, p: &Packet) {
    iface.send(p).await.expect("send");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpInterfaceListener::bind("127.0.0.1:0".parse()?).await?;
    println!("LISTENING {}", listener.local_addr()?.port());
    let mut iface = listener.accept().await?;

    let identity = PrivateIdentity::from_secret_bytes(&IDENTITY_SEED);
    let name = DestinationName::new("retinue", ["reqresp"]);
    let our_dest = name.destination_hash(identity.public());
    send(&mut iface, &announce::build(&identity, name.name_hash(), &rand_hash(), None, b"rr")).await;
    println!("SENT_ANNOUNCE {our_dest}");

    let mut link: Option<Link> = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let packet = match tokio::time::timeout(remaining, iface.recv()).await {
            Err(_) => break,
            Ok(Err(RecvError::Wire(_))) => continue,
            Ok(Err(RecvError::Io(_))) => break,
            Ok(Ok(p)) => p,
        };
        match &link {
            None if packet.packet_type == PacketType::LinkRequest && packet.destination == our_dest => {
                let (l, proof) = link::accept(
                    &packet, &identity, &EPHEMERAL_SEED,
                    LinkTrailer { mode: LinkMode::Aes256Cbc, mtu: 500 },
                )?;
                println!("LINK_ACCEPTED id={}", l.id());
                send(&mut iface, &proof).await;
                link = Some(l);
            }
            Some(l) => match l.receive(&packet) {
                Some(Inbound::Request(data)) => {
                    println!("REQUEST_PLAINTEXT {}", hex::encode(&data));
                    // Echo a response back so we can observe RNS accept it (and the driver
                    // learns the packet flows). We do not yet know the exact response
                    // packing, so reply with the raw request bytes; the driver reports
                    // whether RNS's response_callback fires.
                    send(&mut iface, &l.response_packet(&data, &iv(1))).await;
                    println!("SENT_RESPONSE_ECHO");
                }
                Some(Inbound::Response(data)) => println!("RESPONSE_PLAINTEXT {}", hex::encode(&data)),
                Some(Inbound::Close) => { println!("RECV_CLOSE"); break; }
                _ => {}
            },
            None => {}
        }
    }
    println!("DONE");
    Ok(())
}
