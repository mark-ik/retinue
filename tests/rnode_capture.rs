//! Gold tests: tulle's RNode implementation against the live-hardware captures.
//!
//! The fixtures were captured from real RNodes (Heltec T114 c2:c7:3c and Heltec V4 c3:c8:3f,
//! firmware 1.86) driven by RNS 1.3.8 through a pyserial tee. These tests replay them:
//! the init sequence we emit must match the oracle's frame for frame, and feeding the
//! captured device bytes must produce the same online state and received packets RNS saw.

use serde_json::Value;
use tulle::kiss;
use tulle::lora::{CodingRate, LoRaParams};
use tulle::modem::{Modem, ModemEvent};
use tulle::rnode::RNode;

/// The radio config both captures used.
fn capture_params() -> LoRaParams {
    LoRaParams {
        spreading_factor: 8,
        bandwidth_hz: 125_000,
        coding_rate: CodingRate::Cr45,
        frequency_hz: 915_000_000,
        tx_power_dbm: 7,
        preamble_syms: 8,
        explicit_header: true,
        crc: true,
    }
}

fn fixture(name: &str) -> Value {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// All bytes in one direction, concatenated in event order.
fn direction_bytes(cap: &Value, dir: &str, from_event: usize) -> Vec<u8> {
    cap["events"]
        .as_array()
        .unwrap()
        .iter()
        .skip(from_event)
        .filter(|e| e["dir"] == dir)
        .flat_map(|e| hex(e["hex"].as_str().unwrap()))
        .collect()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// KISS-deframe a byte stream into command frames.
fn deframe(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut d = kiss::Deframer::new(1024);
    let mut out = Vec::new();
    d.push(bytes, &mut out);
    out
}

/// Our init conversation must match the oracle's, frame for frame: same commands, same
/// payloads, same order. (Framing byte-equality is deliberately not asserted: consecutive
/// KISS frames may share a FEND, which is wire-legal either way.)
#[test]
fn init_sequence_matches_the_oracle_capture() {
    let cap = fixture("rnode_serial_capture.json");
    let oracle_frames = deframe(&direction_bytes(&cap, "host->rnode", 0));
    // The capture repeats the batch (RNS revalidates); compare against the first run:
    // detect + 3 probes + freq/bw/txp/sf/cr/state = 10 frames.
    let oracle_first = &oracle_frames[..10];

    let mut rnode = RNode::new(capture_params());
    rnode.start();
    let ours = deframe(&rnode.take_outbound());

    assert_eq!(ours.len(), 10, "ten init frames");
    for (i, (ours, oracle)) in ours.iter().zip(oracle_first).enumerate() {
        assert_eq!(
            ours, oracle,
            "init frame {i} differs from the oracle capture"
        );
    }
}

/// Replaying the captured device responses brings the modem online, records the firmware
/// version, and produces no phantom received packets (that capture had no RX traffic).
#[test]
fn replaying_device_responses_brings_the_radio_online() {
    let cap = fixture("rnode_serial_capture.json");
    let mut rnode = RNode::new(capture_params());
    rnode.start();
    rnode.take_outbound();

    rnode.on_serial(&direction_bytes(&cap, "rnode->host", 0));

    assert!(rnode.is_detected(), "detect response recognised");
    assert!(rnode.is_online(), "radio-state echo 01 brings it online");
    assert_eq!(rnode.fw_version(), Some((1, 86)), "firmware 1.86 probed");
    assert!(rnode.last_error().is_none(), "no error frames in the capture");
    let received: Vec<_> = std::iter::from_fn(|| rnode.poll())
        .filter(|e| matches!(e, ModemEvent::Received { .. }))
        .collect();
    assert!(received.is_empty(), "no data frames in the TX capture");
}

/// Replaying the two-radio RX capture yields exactly the three announces RNS validated,
/// each with the RSSI/SNR the stat triplet carried.
#[test]
fn rx_capture_replays_to_three_received_announces() {
    let cap = fixture("rnode_rx_capture.json");
    let mark = cap["rx_ready_marker"].as_u64().unwrap() as usize;
    let mut rnode = RNode::new(capture_params());
    rnode.start();
    rnode.take_outbound();

    rnode.on_serial(&direction_bytes(&cap, "rnode->host", mark));

    let received: Vec<_> = std::iter::from_fn(|| rnode.poll())
        .filter_map(|e| match e {
            ModemEvent::Received {
                frame,
                rssi_dbm,
                snr_db,
            } => Some((frame, rssi_dbm, snr_db)),
            _ => None,
        })
        .collect();

    assert_eq!(received.len(), 3, "three announces were transmitted");
    for (frame, rssi, snr) in &received {
        assert_eq!(frame.len(), 167, "a 167-byte announce");
        assert_eq!(frame[0], 0x01, "announce flags");
        assert_eq!(frame[1], 0x00, "zero hops");
        assert_eq!(*rssi, -60, "captured RSSI: 97 - 157 = -60 dBm");
        assert!(
            (*snr - 14.75).abs() < 0.6,
            "captured SNR near 14.25..14.75 dB, got {snr}"
        );
    }
    // All three carry the same destination hash (one announcing identity).
    let dest: Vec<_> = received.iter().map(|(f, _, _)| &f[2..18]).collect();
    assert_eq!(dest[0], dest[1]);
    assert_eq!(dest[1], dest[2]);
}

/// The TX path: enqueue wraps the raw packet in a DATA frame and prices its airtime.
#[test]
fn enqueue_frames_data_and_prices_airtime() {
    let cap = fixture("rnode_serial_capture.json");
    let mut rnode = RNode::new(capture_params());
    rnode.start();
    rnode.take_outbound();
    // Bring it online with the captured responses first: enqueue refuses while offline.
    assert!(rnode.enqueue(b"too early").is_err(), "offline enqueue refused");
    rnode.on_serial(&direction_bytes(&cap, "rnode->host", 0));
    assert!(rnode.is_online());

    let packet = vec![0xAB; 167];
    let airtime = rnode.enqueue(&packet).unwrap();
    assert_eq!(airtime, capture_params().time_on_air(167));

    let out = rnode.take_outbound();
    let frames = deframe(&out);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0][0], 0x00, "DATA command");
    assert_eq!(&frames[0][1..], packet.as_slice(), "raw packet, verbatim");
}
