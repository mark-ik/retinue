//! A real radio packet captured by Tulle's independent direct-PHY firmware.
//!
//! The sender was a stock LongFast node used strictly as a black-box oracle.
//! This test names the public transport header, decrypts with the independently
//! published public channel key, and then stops at protobuf structure.

use sennet::application::{self, ApplicationEnvelope};
use sennet::flood::{
    FloodDecision, FloodIgnore, ManagedFlood, ManagedFloodConfig, RelayDelayWindow,
};
use sennet::protobuf::{self, Reader, Value};
use sennet::transport::{BROADCAST_DESTINATION, ChannelKey, Packet};
use std::time::Duration;

const RADIO_FRAME: [u8; 49] = [
    0xff, 0xff, 0xff, 0xff, 0x64, 0xfa, 0x6a, 0xf6, 0x12, 0x71, 0x82, 0xa1, 0x63, 0x08, 0x00, 0x64,
    0x01, 0x8d, 0x76, 0x04, 0x48, 0x7a, 0x17, 0x58, 0xad, 0xaf, 0xe1, 0x36, 0xc0, 0x6f, 0x47, 0x8e,
    0xc2, 0xa6, 0xcf, 0x2c, 0x92, 0xee, 0x0b, 0xa0, 0xb1, 0x77, 0x70, 0xca, 0x5f, 0xd0, 0x44, 0x31,
    0x94,
];

const PUBLIC_LONGFAST_KEY: ChannelKey = ChannelKey::Aes128([
    0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59, 0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01,
]);

const SENNET_TX_FRAME: [u8; 47] = [
    0xff, 0xff, 0xff, 0xff, 0x28, 0xfb, 0x6a, 0xf6, 0x22, 0x07, 0x22, 0xb7, 0x63, 0x08, 0x00, 0x28,
    0xf2, 0x57, 0x80, 0x65, 0xad, 0x92, 0x16, 0x9a, 0x5a, 0x2b, 0x31, 0x94, 0x09, 0xda, 0xa6, 0x65,
    0x0d, 0x94, 0x7a, 0x2d, 0xe7, 0x19, 0x6c, 0x35, 0xb2, 0x30, 0xf0, 0x0b, 0x20, 0xd1, 0xe3,
];

/// Built by `application::encode_text` without the still-unnamed field 9.
const SENNET_SEMANTIC_TX_FRAME: [u8; 44] = [
    0xff, 0xff, 0xff, 0xff, 0x28, 0xfb, 0x6a, 0xf6, 0x22, 0x07, 0x26, 0xb7, 0x63, 0x08, 0x00, 0x28,
    0x4b, 0x7d, 0x51, 0xa4, 0xc9, 0xc7, 0x21, 0x3e, 0xa4, 0x48, 0xe7, 0x5c, 0x57, 0x82, 0x1c, 0x0e,
    0x59, 0xda, 0xb7, 0x32, 0x02, 0xad, 0x10, 0x7f, 0x40, 0x78, 0x55, 0xd7,
];

/// Raw client frame emitted by the stock COM7 node after accepting the packet
/// above over RF. The application bytes sit at the observed path 2 > 4.
const STOCK_CLIENT_RECEIPT: [u8; 78] = [
    0x12, 0x4c, 0x0d, 0x28, 0xfb, 0x6a, 0xf6, 0x15, 0xff, 0xff, 0xff, 0xff, 0x22, 0x1c, 0x08, 0x01,
    0x12, 0x18, 0x73, 0x65, 0x6e, 0x6e, 0x65, 0x74, 0x20, 0x73, 0x65, 0x6d, 0x61, 0x6e, 0x74, 0x69,
    0x63, 0x20, 0x61, 0x70, 0x69, 0x20, 0x30, 0x37, 0x32, 0x32, 0x35, 0x22, 0x07, 0x26, 0xb7, 0x3d,
    0xcc, 0x96, 0x60, 0x6a, 0x45, 0x00, 0x00, 0xa0, 0x40, 0x48, 0x03, 0x60, 0xd5, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x78, 0x03, 0x98, 0x01, 0x28, 0xa8, 0x01, 0x01,
];

#[test]
fn direct_phy_capture_decrypts_at_the_transport_boundary() {
    let mut packet = Packet::decode(&RADIO_FRAME).unwrap();
    assert_eq!(packet.header.destination, BROADCAST_DESTINATION);
    assert_eq!(packet.header.source, 0xf66a_fa64);
    assert_eq!(packet.header.packet_id, 0xa182_7112);
    assert_eq!(packet.header.hop_limit, 3);
    assert_eq!(packet.header.hop_start, 3);
    assert_eq!(packet.header.channel_hash, 8);
    assert_eq!(packet.header.relay_node, 0x64);

    packet.apply_channel_cipher(&PUBLIC_LONGFAST_KEY);
    assert_eq!(
        packet.payload,
        b"\x08\x01\x12\x1btulle direct phy probe 0722\x48\x00"
    );
    assert_eq!(
        protobuf::structure(&packet.payload),
        [(1, 0), (2, 2), (9, 0)]
    );
    assert_eq!(
        application::decode_text(&packet.payload).unwrap(),
        "tulle direct phy probe 0722"
    );
}

#[test]
fn managed_flood_relay_preserves_captured_ciphertext_and_nonce_identity() {
    let delay =
        RelayDelayWindow::new(Duration::from_millis(25), Duration::from_millis(125)).unwrap();
    let mut relay = ManagedFlood::new(ManagedFloodConfig {
        channel_hash: 8,
        relay_node: 0x28,
        seen_capacity: 32,
        delay,
    })
    .unwrap();

    let FloodDecision::Relay {
        frame: forwarded,
        delay: selected_window,
    } = relay.consider(&RADIO_FRAME).unwrap()
    else {
        panic!("first captured packet should be relayed");
    };
    assert_eq!(selected_window, delay);

    let original = Packet::decode(&RADIO_FRAME).unwrap();
    let forwarded = Packet::decode(&forwarded).unwrap();
    assert_eq!(forwarded.header.source, original.header.source);
    assert_eq!(forwarded.header.packet_id, original.header.packet_id);
    assert_eq!(forwarded.header.nonce(), original.header.nonce());
    assert_eq!(forwarded.header.hop_limit, original.header.hop_limit - 1);
    assert_eq!(forwarded.header.relay_node, 0x28);
    assert_eq!(forwarded.payload, original.payload);

    assert_eq!(
        relay.consider(&RADIO_FRAME).unwrap(),
        FloodDecision::Ignore(FloodIgnore::Duplicate)
    );
}

#[test]
fn stock_node_accepted_sennet_sealed_transport_packet() {
    let mut packet = Packet::decode(&SENNET_TX_FRAME).unwrap();
    assert_eq!(packet.header.source, 0xf66a_fb28);
    assert_eq!(packet.header.packet_id, 0xb722_0722);
    packet.apply_channel_cipher(&PUBLIC_LONGFAST_KEY);
    assert_eq!(
        packet.payload,
        b"\x08\x01\x12\x19sennet direct phy tx 0722\x48\x00"
    );
    assert_eq!(
        protobuf::structure(&packet.payload),
        [(1, 0), (2, 2), (9, 0)]
    );
    assert_eq!(
        application::decode_text(&packet.payload).unwrap(),
        "sennet direct phy tx 0722"
    );
}

#[test]
fn stock_node_accepted_the_reconstructed_text_encoder() {
    let mut packet = Packet::decode(&SENNET_SEMANTIC_TX_FRAME).unwrap();
    assert_eq!(packet.header.source, 0xf66a_fb28);
    assert_eq!(packet.header.packet_id, 0xb726_0722);
    packet.apply_channel_cipher(&PUBLIC_LONGFAST_KEY);

    assert_eq!(
        packet.payload,
        application::encode_text("sennet semantic api 0722")
    );
    assert_eq!(
        ApplicationEnvelope::decode(&packet.payload)
            .unwrap()
            .text()
            .unwrap(),
        "sennet semantic api 0722"
    );
    assert_eq!(protobuf::structure(&packet.payload), [(1, 0), (2, 2)]);

    let Value::Len(received_packet) = Reader::new(&STOCK_CLIENT_RECEIPT)
        .find(|field| field.number == 2)
        .expect("received-packet variant")
        .value
    else {
        panic!("received-packet variant is nested");
    };
    let Value::Len(received_application) = Reader::new(received_packet)
        .find(|field| field.number == 4)
        .expect("application payload")
        .value
    else {
        panic!("application payload is nested");
    };
    assert_eq!(
        application::decode_text(received_application).unwrap(),
        "sennet semantic api 0722"
    );
}
