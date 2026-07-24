//! Build one broadcast text packet for direct-PHY radio experiments.

use sennet::application::encode_text;
use sennet::transport::{ChannelKey, Header, Packet};

fn hex_bytes(value: &str) -> Vec<u8> {
    assert!(
        value.len().is_multiple_of(2),
        "hex value must have even length"
    );
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("hex byte"))
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert!(
        args.len() >= 6,
        "usage: seal_text SOURCE_HEX PACKET_ID_HEX CHANNEL_HASH_HEX KEY_HEX TEXT"
    );
    let source = u32::from_str_radix(&args[1], 16).expect("source hex");
    let packet_id = u32::from_str_radix(&args[2], 16).expect("packet id hex");
    let channel_hash = u8::from_str_radix(&args[3], 16).expect("channel hash hex");
    let key = match hex_bytes(&args[4]).as_slice() {
        bytes @ [..] if bytes.len() == 16 => {
            ChannelKey::Aes128(bytes.try_into().expect("16-byte key"))
        }
        bytes @ [..] if bytes.len() == 32 => {
            ChannelKey::Aes256(bytes.try_into().expect("32-byte key"))
        }
        _ => panic!("key must be 16 or 32 bytes"),
    };
    let mut packet = Packet {
        header: Header {
            destination: u32::MAX,
            source,
            packet_id,
            hop_limit: 3,
            want_ack: false,
            via_mqtt: false,
            hop_start: 3,
            channel_hash,
            next_hop: 0,
            relay_node: source as u8,
        },
        payload: encode_text(&args[5..].join(" ")),
    };
    packet.apply_channel_cipher(&key);
    for byte in packet.encode().expect("transport packet") {
        print!("{byte:02x}");
    }
    println!();
}
