//! R1 framing, replayed against a real RNS 1.3.8 TCP stream.
//!
//! `tcp_stream.bin` is the literal byte stream RNS wrote to a socket. Nothing here is
//! synthetic: if our de-framing is wrong, these fail.
//!
//! Regenerate with `oracle/.venv/Scripts/python.exe -u oracle/capture_tcp.py`.

use retinue::announce::Announce;
use retinue::iface::hdlc::{Deframer, frame};
use retinue::packet::{Packet, PacketType};

fn fixture(name: &str) -> Vec<u8> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");
    std::fs::read(format!("{path}{name}"))
        .unwrap_or_else(|e| panic!("missing fixture {name}: {e}. Run oracle/capture_tcp.py."))
}

/// De-frame the real stream and find RNS's announces in it.
#[test]
fn we_can_deframe_a_real_rns_tcp_stream() {
    let stream = fixture("tcp_stream.bin");
    let mut d = Deframer::new();
    let frames = d.push(&stream);

    // RNS sent an interface-chatter packet plus our two announces.
    assert!(frames.len() >= 2, "expected several frames, got {}", frames.len());

    let announces: Vec<Announce> = frames
        .iter()
        .filter_map(|f| Packet::decode(f).ok())
        .filter(|p| p.packet_type == PacketType::Announce)
        .map(|p| Announce::decode(&p).expect("RNS announce must validate"))
        .collect();

    assert_eq!(announces.len(), 2, "expected two announces in the stream");
    for a in &announces {
        assert_eq!(a.destination.to_string(), "a8725a7e212dace39e9f99a8ac5da28c");
    }
    // One of them carries the adversarial app_data full of HDLC special bytes.
    assert!(
        announces
            .iter()
            .any(|a| a.app_data == [0x7e, 0x7d, 0x7e, 0x7d, 0x00, 0xff]),
        "the escape-exercising announce did not survive de-framing intact",
    );
}

/// TCP splits wherever it likes. Feed the real stream one byte at a time and the same
/// frames must fall out.
#[test]
fn a_real_stream_survives_being_split_arbitrarily() {
    let stream = fixture("tcp_stream.bin");

    let mut whole = Deframer::new();
    let expected = whole.push(&stream);

    let mut drip = Deframer::new();
    let mut got = Vec::new();
    for &b in &stream {
        got.extend(drip.push(&[b]));
    }
    assert_eq!(got, expected);

    let mut chunky = Deframer::new();
    let mut got = Vec::new();
    for chunk in stream.chunks(7) {
        got.extend(chunky.push(chunk));
    }
    assert_eq!(got, expected);
}

/// The destination hash of the fixture identity contains a literal `0x7E`, so RNS had to
/// escape it. Our framing must produce the identical stuffing.
#[test]
fn our_framing_reproduces_rns_byte_stuffing() {
    let packet = fixture("tcp_frame_announce.bin");
    let framed = frame(&packet);

    // a8 72 5a 7e ... must go out as a8 72 5a 7d 5e ...
    let needle = [0xa8, 0x72, 0x5a, 0x7d, 0x5e, 0x21];
    assert!(
        framed.windows(needle.len()).any(|w| w == needle),
        "the 0x7E in the destination hash was not escaped to 7d 5e",
    );

    // And it must appear in the real stream exactly the same way.
    let stream = fixture("tcp_stream.bin");
    assert!(stream.windows(needle.len()).any(|w| w == needle));

    let mut d = Deframer::new();
    assert_eq!(d.push(&framed), vec![packet]);
}

/// The escape byte itself is escaped too. Proven by asking RNS to announce app_data
/// containing both special bytes, and reading what it put on the wire.
#[test]
fn our_framing_escapes_the_escape_byte_like_rns_does() {
    let packet = fixture("tcp_frame_announce_escapes.bin");
    let framed = frame(&packet);

    // app_data 7e 7d 7e 7d 00 ff goes out as 7d5e 7d5d 7d5e 7d5d 00 ff.
    let needle = [0x7d, 0x5e, 0x7d, 0x5d, 0x7d, 0x5e, 0x7d, 0x5d, 0x00, 0xff];
    assert!(
        framed.windows(needle.len()).any(|w| w == needle),
        "our stuffing of the app_data does not match what RNS emitted",
    );

    let stream = fixture("tcp_stream.bin");
    assert!(
        stream.windows(needle.len()).any(|w| w == needle),
        "sanity: RNS's own stream should contain this stuffing",
    );

    let a = Announce::decode(&Packet::decode(&packet).unwrap()).unwrap();
    assert_eq!(a.app_data, [0x7e, 0x7d, 0x7e, 0x7d, 0x00, 0xff]);
}
