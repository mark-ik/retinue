//! The retinue half of the R3 live link gate.
//!
//! retinue is the initiator. It connects to RNS, opens a link to a known destination,
//! completes the handshake (request, proof, RTT), then:
//!   - sends an encrypted application message, which RNS must decrypt, and
//!   - decrypts RNS's encrypted reply,
//!   - waits out an idle period and confirms the link still carries data.
//!
//! Driven by `oracle/interop_link.py`. Prints machine-readable lines it greps for.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use retinue::destination::DestinationName;
use retinue::identity::PrivateIdentity;
use retinue::iface::tcp::{RecvError, TcpInterfaceListener};
use retinue::link::{Link, LinkMode, LinkTrailer, PendingLink};
use retinue::packet::{Packet, PacketType};

/// The RNS destination's identity, from the shared fixed seed. In production this arrives
/// in an announce; here it is known so the example is self-contained.
const DEST_SEED: [u8; 64] = {
    let mut s = [0u8; 64];
    let half = [
        0xf0, 0xec, 0xbb, 0xa4, 0x9e, 0x78, 0x3d, 0xee, 0x14, 0xff, 0xc6, 0xc9, 0xf1, 0xe1, 0x25,
        0x1e, 0xfa, 0x7d, 0x76, 0x29, 0xe0, 0xfa, 0x32, 0x41, 0x3c, 0x5c, 0x59, 0xec, 0x2e, 0x0f,
        0x6d, 0x6c,
    ];
    let mut i = 0;
    while i < 32 {
        s[i] = half[i];
        s[i + 32] = half[i];
        i += 1;
    }
    s
};

/// retinue's ephemeral link seed, fixed for reproducibility. Production generates this per
/// attempt.
const EPHEMERAL_SEED: [u8; 64] = {
    let mut s = [0u8; 64];
    let mut i = 0;
    while i < 32 {
        s[i] = 0x33;
        s[i + 32] = 0x44;
        i += 1;
    }
    s
};

/// A byte of variety for IVs, so successive packets do not reuse one. Not cryptographic
/// randomness; the example is a functional gate, not a security demonstration.
fn iv_from(nonce: u8) -> [u8; 16] {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_nanos()
        .to_le_bytes();
    let mut iv = [0u8; 16];
    iv[..8].copy_from_slice(&t[..8]);
    iv[15] = nonce;
    iv
}

async fn send(iface: &mut retinue::iface::tcp::TcpInterface, p: &Packet) {
    iface.send(p).await.expect("send");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpInterfaceListener::bind("127.0.0.1:0".parse()?).await?;
    println!("LISTENING {}", listener.local_addr()?.port());
    let mut iface = listener.accept().await?;
    tokio::time::sleep(Duration::from_millis(250)).await;
    println!("ACCEPTED");

    let peer = *PrivateIdentity::from_secret_bytes(&DEST_SEED).public();
    let destination = DestinationName::new("retinue", ["test"]).destination_hash(&peer);

    // 1. Open the link and send the request.
    let (pending, request) = PendingLink::open(
        destination,
        peer,
        &EPHEMERAL_SEED,
        LinkTrailer {
            mode: LinkMode::Aes256Cbc,
            mtu: 500,
        },
    );
    println!("LINK_REQUEST id={}", pending.link_id());
    send(&mut iface, &request).await;

    // 2. Wait for the proof, and establish.
    let link: Link = loop {
        match tokio::time::timeout(Duration::from_secs(10), iface.recv()).await {
            Err(_) => {
                println!("TIMEOUT waiting for proof");
                return Ok(());
            }
            Ok(Err(RecvError::Wire(_))) => continue, // interface chatter
            Ok(Err(RecvError::Io(e))) => {
                println!("IO_ERROR {e}");
                return Ok(());
            }
            Ok(Ok(p)) if p.packet_type == PacketType::Proof => match pending.prove(&p) {
                Ok(link) => {
                    println!(
                        "LINK_ESTABLISHED id={} mode={:?} mtu={}",
                        link.id(),
                        link.mode(),
                        link.mtu()
                    );
                    break link;
                }
                Err(e) => {
                    println!("PROOF_REJECTED {e}");
                    return Ok(());
                }
            },
            Ok(Ok(_)) => continue,
        }
    };

    // 3. RTT moves the link to active on RNS.
    send(&mut iface, &link.rtt_packet(0.05, &iv_from(1))).await;
    println!("SENT_RTT");
    tokio::time::sleep(Duration::from_millis(400)).await;

    // 4. Send an encrypted application message. RNS must decrypt it (its packet callback).
    send(
        &mut iface,
        &link.data_packet(b"hello-over-the-link", &iv_from(2)),
    )
    .await;
    println!("SENT_DATA hello-over-the-link");

    // 5. Receive and decrypt RNS's reply.
    let mut got_reply = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    while tokio::time::Instant::now() < deadline && !got_reply {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, iface.recv()).await {
            Err(_) => break,
            Ok(Err(_)) => continue,
            Ok(Ok(p))
                if p.destination == link.id()
                    && p.packet_type == PacketType::Data
                    && p.context == 0 =>
            {
                match link.decrypt(&p) {
                    Ok(pt) => {
                        println!("RECV_DATA {}", String::from_utf8_lossy(&pt));
                        got_reply = true;
                    }
                    Err(e) => println!("DECRYPT_FAILED {e}"),
                }
            }
            Ok(Ok(_)) => continue,
        }
    }

    // 6. Idle, then confirm the link still carries data.
    println!("IDLING");
    tokio::time::sleep(Duration::from_secs(4)).await;
    send(&mut iface, &link.data_packet(b"after-idle", &iv_from(3))).await;
    println!("SENT_DATA_AFTER_IDLE after-idle");
    tokio::time::sleep(Duration::from_secs(2)).await;

    println!("DONE");
    Ok(())
}
