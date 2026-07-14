//! Probe the link handshake. This implements no link logic: it provokes RNS into
//! showing us one, and prints every packet it sees.
//!
//! Two unknowns block R3, and a wrong guess on either means no link ever completes, with
//! no useful error:
//!
//!   1. Does a link request carry 64 bytes (two public keys) or 67 (plus a 3-byte
//!      mode/MTU trailer)? `Link.LINK_MTU_SIZE = 3` and `MODE_AES128_CBC`/`MODE_AES256_CBC`
//!      exist, so the AES mode is evidently negotiated rather than fixed.
//!   2. Is the link id the truncated hash of the *whole* request payload, or only of the
//!      64 bytes of keys? Beechat truncates to 64 before hashing, which would silently
//!      discard any trailer.
//!
//! Method, both halves without implementing links:
//!
//!   - retinue announces, so RNS learns the destination and links *to* us. That shows us
//!     the request.
//!   - retinue fires a raw link request *at* RNS's destination. RNS answers with a proof.
//!     That shows us the proof, and the address it puts on the proof is the link id, which
//!     lets us test the two link-id hypotheses directly.
//!
//! Driven by `oracle/capture_link.py`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use retinue::announce::{self, RAND_HASH_LEN};
use retinue::destination::DestinationName;
use retinue::hash::{AddressHash, NameHash, full_hash};
use retinue::iface::tcp::{RecvError, TcpInterfaceListener};
use retinue::identity::PrivateIdentity;
use retinue::packet::{DestinationType, HeaderType, Packet, PacketType, Propagation};

const RETINUE_SEED: [u8; 64] = [0x11; 64];
/// The ephemeral keypair for our outbound link request. Fixed, so the capture is
/// reproducible. A real link would generate this per attempt.
const EPHEMERAL_SEED: [u8; 64] = [0x22; 64];

/// The oracle's destination, `retinue.test` under the fixture identity. It is what we aim
/// our link request at.
const ORACLE_DEST: &str = "a8725a7e212dace39e9f99a8ac5da28c";

fn rand_hash() -> [u8; RAND_HASH_LEN] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after 1970")
        .as_nanos()
        .to_le_bytes();
    let mut out = [0u8; RAND_HASH_LEN];
    out.copy_from_slice(&nanos[..RAND_HASH_LEN]);
    out
}

fn parse_hash(hex: &str) -> AddressHash {
    let mut b = [0u8; 16];
    hex::decode_to_slice(hex, &mut b).expect("valid hex");
    AddressHash::from_bytes(b)
}

/// Both candidate link-id derivations, so we can see which one RNS actually used.
fn link_id_candidates(request_payload: &[u8]) -> (AddressHash, AddressHash) {
    let over_all = AddressHash::of(request_payload);
    let over_keys = AddressHash::of(&request_payload[..request_payload.len().min(64)]);
    (over_all, over_keys)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpInterfaceListener::bind("127.0.0.1:0".parse()?).await?;
    println!("LISTENING {}", listener.local_addr()?.port());

    let mut iface = listener.accept().await?;
    println!("ACCEPTED");

    let identity = PrivateIdentity::from_secret_bytes(&RETINUE_SEED);
    let name = DestinationName::new("retinue", ["interop"]);
    let our_dest = name.destination_hash(identity.public());

    // 1. Announce, so RNS learns us and can link to us.
    let ann = announce::build(
        &identity,
        name.name_hash(),
        &rand_hash(),
        None,
        b"link-probe",
    );
    iface.send(&ann).await?;
    println!("SENT_ANNOUNCE {our_dest}");

    // 2. Fire a raw link request at the oracle's destination, so it proves back to us.
    let ephemeral = PrivateIdentity::from_secret_bytes(&EPHEMERAL_SEED);
    let request_payload = ephemeral.public().to_public_bytes().to_vec();
    let oracle_dest = parse_hash(ORACLE_DEST);

    let request = Packet {
        ifac: false,
        header_type: HeaderType::Type1,
        context_flag: false,
        propagation: Propagation::Broadcast,
        destination_type: DestinationType::Single,
        packet_type: PacketType::LinkRequest,
        hops: 0,
        transport: None,
        destination: oracle_dest,
        context: 0,
        payload: request_payload.clone(),
    };

    let (id_over_all, id_over_keys) = link_id_candidates(&request_payload);
    // Our request is exactly 64 bytes, so both candidates coincide for it. They will not
    // for RNS's request if it carries a trailer, which is the interesting case.
    println!("SENT_LINKREQUEST payload={} bytes", request_payload.len());
    println!("  payload    {}", hex::encode(&request_payload));
    println!("  link_id? over-all-data  {id_over_all}");
    println!("  link_id? over-first-64  {id_over_keys}");
    println!("  full_hash(payload)      {}", hex::encode(full_hash(&request_payload)));

    tokio::time::sleep(Duration::from_millis(300)).await;
    iface.send(&request).await?;

    // 3. Print everything that comes back.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            println!("DONE");
            return Ok(());
        }
        match tokio::time::timeout(remaining, iface.recv()).await {
            Err(_) => {
                println!("DONE");
                return Ok(());
            }
            Ok(Err(RecvError::Io(e))) => {
                println!("IO_ERROR {e}");
                return Ok(());
            }
            Ok(Err(RecvError::Wire(e))) => {
                println!("UNDECODABLE {e}");
            }
            Ok(Ok(p)) => {
                println!(
                    "PACKET type={:?} dest_type={:?} ctx_flag={} context=0x{:02x} \
                     dest={} payload={} bytes",
                    p.packet_type,
                    p.destination_type,
                    u8::from(p.context_flag),
                    p.context,
                    p.destination,
                    p.payload.len(),
                );
                println!("  payload {}", hex::encode(&p.payload));

                match p.packet_type {
                    PacketType::LinkRequest => {
                        // RNS linking to US. This is the request format we need.
                        let (all, keys) = link_id_candidates(&p.payload);
                        println!("  >> RNS LINK REQUEST to {}", p.destination);
                        println!("     payload is {} bytes ({})", p.payload.len(),
                                 if p.payload.len() == 64 { "keys only, NO trailer" }
                                 else { "LONGER than 64: there IS a trailer" });
                        if p.payload.len() > 64 {
                            println!("     trailer  {}", hex::encode(&p.payload[64..]));
                        }
                        println!("     link_id if over all data : {all}");
                        println!("     link_id if over first 64 : {keys}");
                        println!("     (watch which one RNS addresses its next packet to)");
                    }
                    PacketType::Proof => {
                        // RNS proving OUR link request. The address it proves to IS the
                        // link id, so this settles the derivation.
                        println!("  >> RNS PROOF, addressed to {}", p.destination);
                        println!("     our link_id over-all-data : {id_over_all}  match={}",
                                 p.destination == id_over_all);
                        println!("     our link_id over-first-64 : {id_over_keys}  match={}",
                                 p.destination == id_over_keys);
                        println!("     proof payload is {} bytes ({})", p.payload.len(),
                                 match p.payload.len() {
                                     96 => "sig(64) + pubkey(32), NO trailer",
                                     99 => "sig(64) + pubkey(32) + 3-byte trailer",
                                     n if n > 96 => "longer than 96: trailer present",
                                     _ => "unexpected",
                                 });
                        if p.payload.len() > 96 {
                            println!("     trailer  {}", hex::encode(&p.payload[96..]));
                        }
                        println!("     first32  {}", hex::encode(&p.payload[..32]));
                        println!("     last32   {}", hex::encode(&p.payload[p.payload.len().min(96) - 32..96.min(p.payload.len())]));
                    }
                    _ => {}
                }
            }
        }
    }
}

// The probe needs NameHash in scope only for documentation of the announce path.
const _: fn() = || {
    let _ = NameHash::of(b"");
};
