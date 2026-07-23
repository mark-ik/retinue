//! Send one Sennet text packet through Tulle direct-PHY firmware and wait for
//! its RF echo or rebroadcast.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use sennet::node::Channel;
use sennet::packet_id::PacketIdState;
use sennet::transport::{BROADCAST_DESTINATION, ChannelKey, Header};
use tulle::PhyProfile;
use tulle::airtime::AirtimeBudget;
use tulle::direct_phy_serial::{DirectPhySerialConfig, DirectPhySerialLink};

fn hex_bytes(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2), "hex must have even length");
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("hex byte"))
        .collect()
}

fn reserve_packet_identity(path: &Path, source: u32, initial: u32) -> (u32, u32) {
    let mut state = match std::fs::read(path) {
        Ok(bytes) => PacketIdState::decode(&bytes).expect("valid packet-ID state file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            PacketIdState::new(source, initial)
        }
        Err(error) => panic!("read packet-ID state: {error}"),
    };
    assert_eq!(
        state.source(),
        source,
        "state file belongs to a different source"
    );
    let identity = state.reserve().expect("packet-ID space available");

    // Advance durable state before the radio sees the packet. A torn record is
    // rejected on restart rather than silently resetting and reusing an ID.
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .expect("open packet-ID state for update");
    file.write_all(&state.encode())
        .expect("write packet-ID state");
    file.sync_all().expect("persist packet-ID state");
    (identity.source, identity.packet_id)
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert!(
        args.len() >= 8,
        "usage: direct_phy_text PORT STATE_FILE SOURCE_HEX INITIAL_PACKET_ID_HEX CHANNEL_HASH_HEX KEY_HEX TEXT"
    );
    let source = u32::from_str_radix(&args[3], 16).expect("source hex");
    let initial_packet_id = u32::from_str_radix(&args[4], 16).expect("initial packet id hex");
    let (source, packet_id) =
        reserve_packet_identity(Path::new(&args[2]), source, initial_packet_id);
    let hash = u8::from_str_radix(&args[5], 16).expect("channel hash hex");
    let key = match hex_bytes(&args[6]).as_slice() {
        bytes @ [..] if bytes.len() == 16 => {
            ChannelKey::Aes128(bytes.try_into().expect("16-byte key"))
        }
        bytes @ [..] if bytes.len() == 32 => {
            ChannelKey::Aes256(bytes.try_into().expect("32-byte key"))
        }
        _ => panic!("key must be 16 or 32 bytes"),
    };
    let text = args[7..].join(" ");
    let channel = Channel { hash, key };
    let frame = channel
        .seal_text(
            Header {
                destination: BROADCAST_DESTINATION,
                source,
                packet_id,
                hop_limit: 3,
                want_ack: false,
                via_mqtt: false,
                hop_start: 3,
                channel_hash: hash,
                next_hop: 0,
                relay_node: source as u8,
            },
            &text,
        )
        .expect("text transport packet");

    let profile = PhyProfile::meshtastic_long_fast(906_875_000);
    let budget = AirtimeBudget::new(60_000, 1_000);
    let mut radio =
        DirectPhySerialLink::open(&args[1], profile, budget, DirectPhySerialConfig::default())
            .expect("open direct-PHY serial port");
    radio.wait_online().await.expect("direct-PHY online");
    let airtime = radio.send(frame).await.expect("radio transmit");
    println!("transmitted in {:.3} ms", airtime.as_secs_f64() * 1_000.0);

    let receipt = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let received = radio.recv().await.expect("radio stopped");
            if let Some(message) = channel.open_text(&received.frame).expect("received packet") {
                break (received, message);
            }
        }
    })
    .await
    .expect("no matching RF receipt within 15 seconds");
    println!(
        "received {:?} from {:08x}, RSSI {} dBm, SNR {:.1} dB",
        receipt.1.text, receipt.1.header.source, receipt.0.rssi_dbm, receipt.0.snr_db
    );
    radio.shutdown().await.expect("close direct-PHY link");
}
