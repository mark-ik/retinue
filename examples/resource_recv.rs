//! retinue receives a resource from RNS: parse the advertisement, request parts in a window,
//! solicit more hashmap via HMU when the advertised hashes run out, then reassemble, decrypt,
//! decompress, verify, and send the proof. RNS then concludes COMPLETE. Handles single-segment
//! resources of any size. Driven by `oracle/interop_resource_recv.py`.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};


use retinue::announce::{self, RAND_HASH_LEN};
use retinue::destination::DestinationName;
use retinue::iface::tcp::{RecvError, TcpInterface, TcpInterfaceListener};
use retinue::identity::PrivateIdentity;
use retinue::link::{self, Link, LinkMode, LinkTrailer, CTX_RESOURCE_REQ};
use retinue::packet::{Packet, PacketType};
use retinue::resource::{Advertisement, Incoming};

const IDENTITY_SEED: [u8; 64] = [0x11; 64];
const EPHEMERAL_SEED: [u8; 64] = [0x77; 64];

fn rh() -> [u8; RAND_HASH_LEN] {
    let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().to_le_bytes();
    let mut o = [0u8; RAND_HASH_LEN];
    o.copy_from_slice(&n[..RAND_HASH_LEN]);
    o
}
static IVC: AtomicU32 = AtomicU32::new(0);
/// A fresh IV per call: time bytes plus a monotonic counter, unique within a run.
fn iv() -> [u8; 16] {
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().to_le_bytes();
    let c = IVC.fetch_add(1, Ordering::Relaxed);
    let mut v = [0u8; 16];
    v[..8].copy_from_slice(&t[..8]);
    v[8..12].copy_from_slice(&c.to_le_bytes());
    v
}
async fn send(i: &mut TcpInterface, p: &Packet) { i.send(p).await.expect("send"); }

/// Assemble, decrypt, decompress, verify, and prove one completed segment. Returns the
/// recovered segment body (to be concatenated across segments), or `None` on failure.
async fn finish(
    iface: &mut TcpInterface,
    l: &Link,
    inc: &Incoming,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let token = inc.assemble_token()?;
    let decrypted = l.open(&token)?;
    match inc.recover(&decrypted) {
        Ok(data) => {
            println!("SEGMENT_ASSEMBLED token={} data={} compressed={}", token.len(), data.len(), inc.is_compressed());
            let proof = inc.proof(&data);
            send(iface, &l.resource_proof_packet(&inc.resource_hash(), &proof)).await;
            Ok(Some(data))
        }
        Err(e) => {
            println!("RECOVER_FAILED {e}");
            Ok(None)
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpInterfaceListener::bind("127.0.0.1:0".parse()?).await?;
    println!("LISTENING {}", listener.local_addr()?.port());
    let mut iface = listener.accept().await?;

    let identity = PrivateIdentity::from_secret_bytes(&IDENTITY_SEED);
    let name = DestinationName::new("retinue", ["resource"]);
    let our_dest = name.destination_hash(identity.public());
    send(&mut iface, &announce::build(&identity, name.name_hash(), &rh(), None, b"res")).await;

    let mut cadence = tokio::time::interval(Duration::from_secs(2));
    cadence.tick().await;

    let mut link: Option<Link> = None;
    let mut incoming: Option<Incoming> = None;
    // Multi-segment accumulation: a resource above ~1 MB arrives as several segments, each
    // its own advertisement (i = 1-based index, l = total). The full payload is their
    // recovered bodies concatenated.
    let mut assembled: Vec<u8> = Vec::new();
    let mut this_segment = 0u64;
    let mut total_segments = 1u64;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);

    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let packet = tokio::select! {
            _ = cadence.tick(), if link.is_none() => {
                send(&mut iface, &announce::build(&identity, name.name_hash(), &rh(), None, b"res")).await;
                continue;
            }
            r = tokio::time::timeout(remaining, iface.recv()) => match r {
                Err(_) => break,
                Ok(Err(RecvError::Wire(_))) => continue,
                Ok(Err(RecvError::Io(_))) => break,
                Ok(Ok(p)) => p,
            },
        };

        match &link {
            None if packet.packet_type == PacketType::LinkRequest && packet.destination == our_dest => {
                let (l, proof) = link::accept(&packet, &identity, &EPHEMERAL_SEED,
                    LinkTrailer { mode: LinkMode::Aes256Cbc, mtu: 500 })?;
                println!("LINK_UP {}", l.id());
                send(&mut iface, &proof).await;
                link = Some(l);
            }
            Some(l) if packet.destination == l.id() => {
                match packet.context {
                    // Advertisement: parse, request the parts it names.
                    0x02 => {
                        let plain = l.decrypt(&packet)?;
                        let adv = Advertisement::parse(&plain)?;
                        println!("ADV segment {}/{} d={} n={} hashmap={} compressed={}",
                            adv.i, adv.l, adv.data_size, adv.parts, adv.hashmap_parts(),
                            adv.flags & 0x02 != 0);
                        this_segment = adv.i as u64;
                        total_segments = adv.l as u64;
                        let inc = Incoming::new(&adv)?;
                        send(&mut iface, &l.sealed_packet(CTX_RESOURCE_REQ,
                            &inc.request(&inc.missing_known()), &iv())).await;
                        println!("REQUESTED {} known parts (of {}) [segment {}/{}]",
                            inc.missing_known().len(), inc.total_parts(), this_segment, total_segments);
                        incoming = Some(inc);
                    }
                    // Part: a raw token slice.
                    0x01 => {
                        if let Some(inc) = incoming.as_mut() {
                            inc.accept_part(&packet.payload);
                            if inc.is_complete() {
                                // Recover this segment, prove it, and append to the payload.
                                if let Some(body) = finish(&mut iface, l, inc).await? {
                                    assembled.extend_from_slice(&body);
                                }
                                incoming = None;
                                if this_segment >= total_segments {
                                    println!("ALL_SEGMENTS_DONE {} bytes", assembled.len());
                                    println!("DATA_HASH {}", hex::encode(retinue::hash::full_hash(&assembled)));
                                    println!("DATA_LEN {}", assembled.len());
                                    break;
                                }
                                // else: wait for the next segment's advertisement.
                            } else if inc.needs_hmu() {
                                // Advertised hashes exhausted; solicit the rest of the hashmap.
                                send(&mut iface, &l.sealed_packet(CTX_RESOURCE_REQ,
                                    &inc.solicit_hmu(), &iv())).await;
                            }
                        }
                    }
                    // Hashmap update: more part hashes; request them.
                    0x04 => {
                        if let Some(inc) = incoming.as_mut() {
                            let plain = l.decrypt(&packet)?;
                            if let Ok(hmu) = retinue::resource::parse_hmu(&plain) {
                                let added = inc.ingest_hmu(&hmu);
                                println!("HMU +{added} hashes ({} of {})", inc.order_len(), inc.total_parts());
                                let want = inc.missing_known();
                                if !want.is_empty() {
                                    send(&mut iface, &l.sealed_packet(CTX_RESOURCE_REQ,
                                        &inc.request(&want), &iv())).await;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    println!("DONE");
    Ok(())
}
