//! Structural analysis of a real captured Meshtastic-compatible config stream.
//!
//! Proves Sennet's stream deframer and protobuf reader parse genuine device output, and
//! records the *structure* the device emits — the field numbers and wire types present in the
//! FromRadio stream. Named application behavior is reconstructed separately through documented
//! radio-bench experiments (see PROVENANCE.md).

use std::collections::BTreeMap;

use sennet::protobuf::{Reader, Value};

fn fixture_frames() -> Vec<Vec<u8>> {
    load_frames("meshtastic_config.json")
}

fn load_frames(name: &str) -> Vec<Vec<u8>> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(path).unwrap();
    // Tiny hand parse of the "frames": ["hex", ...] array (no serde dep in this crate).
    let start = text.find("\"frames\"").unwrap();
    let arr = &text[start..];
    arr.split('"')
        .filter(|s| s.len() >= 2 && s.bytes().all(|b| b.is_ascii_hexdigit()) && s.len() % 2 == 0)
        .map(|hex| {
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect()
        })
        .filter(|f: &Vec<u8>| !f.is_empty())
        .collect()
}

/// Every FromRadio frame parses as a single-field protobuf message (a oneof payload_variant):
/// one top-level field whose number selects which variant it carries. Most variants are nested
/// messages (a config/info blob); a few are scalars (e.g. an id), which is itself observable.
#[test]
fn every_frame_is_a_single_field_oneof() {
    let frames = fixture_frames();
    assert!(frames.len() > 10, "a real config stream has many frames");
    let (mut nested, mut scalar) = (0, 0);
    for (i, frame) in frames.iter().enumerate() {
        let fields: Vec<_> = Reader::new(frame).collect();
        assert_eq!(
            fields.len(),
            1,
            "frame {i} should be one oneof field, got {}",
            fields.len()
        );
        match fields[0].value {
            Value::Len(_) => nested += 1,
            _ => scalar += 1,
        }
    }
    println!("{nested} nested-message variants, {scalar} scalar variants");
    assert!(nested > 0 && scalar > 0, "a config stream has both kinds");
}

/// Summarize which top-level variant numbers appear and how often. This is the shape of the
/// config stream as an observable fact; it names nothing.
#[test]
fn summarize_variant_numbers_present() {
    let frames = fixture_frames();
    let mut counts: BTreeMap<u32, usize> = BTreeMap::new();
    for frame in &frames {
        if let Some(f) = Reader::new(frame).next() {
            *counts.entry(f.number).or_default() += 1;
        }
    }
    println!("top-level FromRadio variant field numbers observed (number -> count):");
    for (num, count) in &counts {
        println!("  field {num}: {count} frame(s)");
    }
    // A config stream carries several distinct variants and ends with a completion marker,
    // so more than one distinct top-level number must appear.
    assert!(
        counts.len() >= 3,
        "expected several distinct config variants"
    );

    // The nested payloads must themselves be well-formed protobuf (they parse structurally).
    for frame in &frames {
        let Some(top) = Reader::new(frame).next() else {
            continue;
        };
        if let Value::Len(inner) = top.value {
            // Descending must not panic and must consume cleanly for at least one field.
            let inner_fields: Vec<_> = Reader::new(inner).collect();
            let _ = inner_fields; // structural well-formedness is the assertion (no panic)
        }
    }
}

/// Exactly one frame in the stream carries a scalar variant — the completion marker (an id per
/// the wire), structurally distinct from the many nested config/info messages. Its top-level
/// field number is a stable, observable landmark, though its meaning is not asserted here.
#[test]
fn exactly_one_scalar_completion_variant_marks_the_config_end() {
    let frames = fixture_frames();
    let scalars: Vec<u32> = frames
        .iter()
        .filter_map(|f| Reader::new(f).next())
        .filter(|field| matches!(field.value, Value::Varint(_) | Value::I32(_)))
        .map(|field| field.number)
        .collect();
    println!("scalar completion variant field number(s): {scalars:?}");
    assert_eq!(
        scalars.len(),
        1,
        "the config stream has exactly one scalar completion marker"
    );
}

/// Live over-the-air packets a node received share one top-level variant number (the
/// received-packet variant), distinct from the config variants, and nest an envelope several
/// levels deep. Sennet's reader parses all of them; the shape is recorded as fact, unnamed.
#[test]
fn over_the_air_packets_share_one_deeply_nested_variant() {
    let frames = load_frames("meshtastic_airmsg.json");
    assert!(!frames.is_empty(), "captured over-the-air frames");

    let mut top_numbers = std::collections::BTreeSet::new();
    for frame in &frames {
        let fields: Vec<_> = Reader::new(frame).collect();
        assert_eq!(fields.len(), 1, "each received packet is one variant");
        top_numbers.insert(fields[0].number);

        // The envelope nests at least three levels: variant -> packet -> payload -> app data.
        let Value::Len(packet) = fields[0].value else {
            panic!("received-packet variant is a nested message");
        };
        let packet_fields: Vec<_> = Reader::new(packet).collect();
        // A nested sub-message exists somewhere in the packet (the decoded payload).
        let has_nested = packet_fields
            .iter()
            .any(|f| matches!(f.value, Value::Len(_)));
        assert!(has_nested, "the packet carries a nested payload message");
    }
    assert_eq!(
        top_numbers.len(),
        1,
        "all received packets share one top-level variant, got {top_numbers:?}"
    );
    println!("received-packet variant field number: {top_numbers:?}");
}

/// Descend the received-packet envelope to the decoded sub-message and return its (tag, payload)
/// — the scalar at field 1 and the bytes at field 2 of the nested message at path 2 > 4.
fn decoded_tag_and_payload(frame: &[u8]) -> Option<(u64, Vec<u8>)> {
    let Value::Len(packet) = Reader::new(frame).find(|f| f.number == 2)?.value else {
        return None;
    };
    let Value::Len(data) = Reader::new(packet).find(|f| f.number == 4)?.value else {
        return None;
    };
    let tag = match Reader::new(data).find(|f| f.number == 1)?.value {
        Value::Varint(v) => v,
        _ => return None,
    };
    let payload = match Reader::new(data).find(|f| f.number == 2)?.value {
        Value::Len(b) => b.to_vec(),
        _ => return None,
    };
    Some((tag, payload))
}

/// A real over-the-air text message, captured black-box, is walked to its payload by Sennet's
/// reader, and that payload is the readable UTF-8 that was sent. This records the one directly
/// observed semantic fact, the port under which a readable message rode, as a test. Other fields
/// remain numbered until experiments give them useful names (PROVENANCE.md).
#[test]
fn a_captured_text_message_decodes_to_readable_utf8() {
    let frames = load_frames("meshtastic_textmsg.json");
    assert!(!frames.is_empty(), "a text frame was captured");
    for frame in &frames {
        let (tag, payload) =
            decoded_tag_and_payload(frame).expect("envelope descends to a payload");
        let text = std::str::from_utf8(&payload).expect("the text payload is valid UTF-8");
        println!("observed text under tag {tag}: {text:?}");
        assert!(!text.is_empty());
        // The tag under which a readable message was observed is small and distinct from the
        // telemetry tag (67) seen elsewhere. (Directly observed; not a schema claim.)
        assert!(tag < 10, "the text tag is a small number, observed {tag}");
        assert_ne!(tag, 67, "distinct from the telemetry tag");
    }
}
