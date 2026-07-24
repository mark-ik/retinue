//! Configure a Tulle direct-PHY radio and print the next text packet on one
//! Sennet channel. This is the receive half of the headed RF acceptance test.

use std::time::Duration;

use sennet::node::Channel;
use sennet::transport::ChannelKey;
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

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(
        args.len(),
        4,
        "usage: direct_phy_receive PORT CHANNEL_HASH_HEX KEY_HEX"
    );
    let hash = u8::from_str_radix(&args[2], 16).expect("channel hash hex");
    let key = match hex_bytes(&args[3]).as_slice() {
        bytes @ [..] if bytes.len() == 16 => {
            ChannelKey::Aes128(bytes.try_into().expect("16-byte key"))
        }
        bytes @ [..] if bytes.len() == 32 => {
            ChannelKey::Aes256(bytes.try_into().expect("32-byte key"))
        }
        _ => panic!("key must be 16 or 32 bytes"),
    };
    let channel = Channel { hash, key };
    let profile = PhyProfile::meshtastic_long_fast(906_875_000);
    let budget = AirtimeBudget::new(60_000, 1_000);
    let mut radio =
        DirectPhySerialLink::open(&args[1], profile, budget, DirectPhySerialConfig::default())
            .expect("open direct-PHY serial port");
    radio.wait_online().await.expect("direct-PHY online");

    let receipt = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let received = radio.recv().await.expect("radio stopped");
            match channel.open_text(&received.frame) {
                Ok(Some(message)) => break (received, message),
                Ok(None) => {}
                Err(_) => {}
            }
        }
    })
    .await
    .expect("no matching RF text within 20 seconds");
    println!(
        "received {:?} from {:08x}, RSSI {} dBm, SNR {:.1} dB",
        receipt.1.text, receipt.1.header.source, receipt.0.rssi_dbm, receipt.0.snr_db
    );
    radio.shutdown().await.expect("close direct-PHY link");
}
