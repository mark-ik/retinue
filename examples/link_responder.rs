//! The retinue half of the R3 responder gate.
//!
//! retinue is the link *responder* here. It announces a destination, waits for RNS to send
//! a link request, proves it, then:
//!   - decrypts application bytes RNS sends on the link and echoes them back encrypted,
//!   - answers a keepalive,
//!   - recognises the link close.
//!
//! Driven by `oracle/interop_link_responder.py`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use retinue::announce::{self, RAND_HASH_LEN};
use retinue::destination::DestinationName;
use retinue::identity::PrivateIdentity;
use retinue::iface::tcp::{RecvError, TcpInterface, TcpInterfaceListener};
use retinue::link::{self, Inbound, Link, LinkMode, LinkTrailer};
use retinue::packet::{Packet, PacketType};

/// retinue's long-term destination identity for this gate.
const IDENTITY_SEED: [u8; 64] = [0x11; 64];
/// retinue's ephemeral seed for the proof, fixed for reproducibility.
const EPHEMERAL_SEED: [u8; 64] = [0x77; 64];

fn rand_hash() -> [u8; RAND_HASH_LEN] {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes();
    let mut out = [0u8; RAND_HASH_LEN];
    out.copy_from_slice(&n[..RAND_HASH_LEN]);
    out
}

fn iv(nonce: u8) -> [u8; 16] {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes();
    let mut iv = [0u8; 16];
    iv[..8].copy_from_slice(&t[..8]);
    iv[15] = nonce;
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
    println!("ACCEPTED");

    let identity = PrivateIdentity::from_secret_bytes(&IDENTITY_SEED);
    let name = DestinationName::new("retinue", ["responder"]);
    let our_dest = name.destination_hash(identity.public());

    // Announce so RNS learns us and can link to us.
    let ann = announce::build(
        &identity,
        name.name_hash(),
        &rand_hash(),
        None,
        b"responder",
    );
    send(&mut iface, &ann).await;
    println!("SENT_ANNOUNCE {our_dest}");

    // Wait for the inbound link request, then prove it.
    let mut link: Option<Link> = None;
    let mut echoes = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(40);

    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let packet = match tokio::time::timeout(remaining, iface.recv()).await {
            Err(_) => break,
            Ok(Err(RecvError::Io(e))) => {
                println!("IO_ERROR {e}");
                break;
            }
            Ok(Err(RecvError::Wire(_))) => continue,
            Ok(Ok(p)) => p,
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
                println!(
                    "LINK_ACCEPTED id={} mode={:?} mtu={}",
                    l.id(),
                    l.mode(),
                    l.mtu()
                );
                send(&mut iface, &proof).await;
                println!("SENT_PROOF");
                link = Some(l);
            }
            Some(l) => match l.receive(&packet) {
                Some(Inbound::Data(data)) => {
                    println!("RECV_DATA {}", String::from_utf8_lossy(&data));
                    // Echo it back encrypted.
                    let mut reply = b"echo:".to_vec();
                    reply.extend_from_slice(&data);
                    send(&mut iface, &l.data_packet(&reply, &iv(echoes))).await;
                    echoes += 1;
                    println!("SENT_ECHO");
                }
                Some(Inbound::KeepAliveRequest) => {
                    println!("RECV_KEEPALIVE_REQUEST");
                    send(&mut iface, &l.keepalive_packet(link::KEEPALIVE_RESPONSE)).await;
                    println!("SENT_KEEPALIVE_RESPONSE");
                }
                Some(Inbound::Rtt) => println!("RECV_RTT"),
                Some(Inbound::Close) => {
                    println!("RECV_CLOSE");
                    break;
                }
                Some(Inbound::KeepAliveResponse) => println!("RECV_KEEPALIVE_RESPONSE"),
                Some(Inbound::Request(_) | Inbound::Response(_) | Inbound::Unknown) | None => {}
            },
            None => {}
        }
    }

    println!("DONE");
    Ok(())
}
