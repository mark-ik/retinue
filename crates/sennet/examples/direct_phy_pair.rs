//! Bidirectional Sennet text acceptance across two Tulle direct-PHY radios.
//!
//! Each source uses its own durable packet-ID state. The state is advanced and
//! flushed before a frame is handed to either radio.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sennet::node::{Channel, ReceivedText};
use sennet::packet_id::PacketIdState;
use sennet::transport::{BROADCAST_DESTINATION, ChannelKey, Header};
use tulle::PhyProfile;
use tulle::airtime::AirtimeBudget;
use tulle::direct_phy_serial::{DirectPhySerialConfig, DirectPhySerialLink};
use tulle::link::Received;

const PUBLIC_LONGFAST: Channel = Channel {
    hash: 8,
    key: ChannelKey::Aes128([
        0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59, 0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69,
        0x01,
    ]),
};

fn reserve_packet_identity(path: &Path, source: u32) -> (u32, u32) {
    let initial = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_millis() as u32;
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

fn text_frame(state: &Path, source: u32, text: &str) -> Vec<u8> {
    let (source, packet_id) = reserve_packet_identity(state, source);
    PUBLIC_LONGFAST
        .seal_text(
            Header {
                destination: BROADCAST_DESTINATION,
                source,
                packet_id,
                hop_limit: 3,
                want_ack: false,
                via_mqtt: false,
                hop_start: 3,
                channel_hash: PUBLIC_LONGFAST.hash,
                next_hop: 0,
                relay_node: source as u8,
            },
            text,
        )
        .expect("text transport packet")
}

async fn receive_text(
    radio: &mut DirectPhySerialLink,
    source: u32,
    expected: &str,
) -> Option<(Received, ReceivedText)> {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let received = radio.recv().await.expect("radio stopped");
            if let Ok(Some(message)) = PUBLIC_LONGFAST.open_text(&received.frame)
                && message.header.source == source
                && message.text == expected
            {
                break (received, message);
            }
        }
    })
    .await
    .ok()
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut args = std::env::args().skip(1);
    let left_port = args.next().unwrap_or_else(|| "COM6".into());
    let right_port = args.next().unwrap_or_else(|| "COM10".into());
    let left_state = args.next().unwrap_or_else(|| {
        panic!("usage: direct_phy_pair LEFT_PORT RIGHT_PORT LEFT_STATE RIGHT_STATE")
    });
    let right_state = args.next().unwrap_or_else(|| {
        panic!("usage: direct_phy_pair LEFT_PORT RIGHT_PORT LEFT_STATE RIGHT_STATE")
    });
    assert!(args.next().is_none(), "unexpected extra argument");

    let profile = PhyProfile::meshtastic_long_fast(906_875_000);
    let config = DirectPhySerialConfig::default();
    let mut left = DirectPhySerialLink::open(
        &left_port,
        profile,
        AirtimeBudget::new(60_000, 1_000),
        config.clone(),
    )
    .expect("open left direct-PHY serial port");
    let mut right = DirectPhySerialLink::open(
        &right_port,
        profile,
        AirtimeBudget::new(60_000, 1_000),
        config,
    )
    .expect("open right direct-PHY serial port");
    tokio::try_join!(left.wait_online(), right.wait_online()).expect("direct-PHY radios online");
    println!("radios online: {left_port}=left, {right_port}=right");

    let left_source = 0x6c65_6674;
    let right_source = 0x7269_6768;
    let right_text = "sennet t114 to v4";
    let right_frame = text_frame(Path::new(&right_state), right_source, right_text);
    right.send(right_frame).await.expect("right radio transmit");
    let right_to_left = receive_text(&mut left, right_source, right_text).await;
    match &right_to_left {
        Some((receipt, _)) => println!(
            "right-to-left text passed: RSSI {} dBm, SNR {:.1} dB",
            receipt.rssi_dbm, receipt.snr_db
        ),
        None => eprintln!("right-to-left text failed: no matching RF text within 20 seconds"),
    }

    let left_text = "sennet v4 to t114";
    let left_frame = text_frame(Path::new(&left_state), left_source, left_text);
    left.send(left_frame).await.expect("left radio transmit");
    let left_to_right = receive_text(&mut right, left_source, left_text).await;
    match &left_to_right {
        Some((receipt, _)) => println!(
            "left-to-right text passed: RSSI {} dBm, SNR {:.1} dB",
            receipt.rssi_dbm, receipt.snr_db
        ),
        None => eprintln!("left-to-right text failed: no matching RF text within 20 seconds"),
    }

    left.shutdown().await.expect("close left direct-PHY link");
    right.shutdown().await.expect("close right direct-PHY link");

    assert!(
        right_to_left.is_some() && left_to_right.is_some(),
        "bidirectional direct-PHY receipt failed"
    );
    println!("SENNET DIRECT-PHY PAIR HEADED PASSED");
}
