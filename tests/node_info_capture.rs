//! Semantic reconstruction receipts for node identity.
//!
//! These fixtures were captured from the same stock COM7 node. The official
//! CLI changed one user setting at a time between captures; Sennet's
//! schema-free capture path recorded the resulting raw `FromRadio` frames.

use sennet::node_info::NodeInfo;

fn fixture_frames(name: &str) -> Vec<Vec<u8>> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(path).unwrap();
    let start = text.find("\"frames\"").unwrap();
    text[start..]
        .split('"')
        .filter(|value| {
            value.len() >= 2
                && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                && value.len() % 2 == 0
        })
        .map(|hex| {
            (0..hex.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
                .collect()
        })
        .filter(|frame: &Vec<u8>| !frame.is_empty())
        .collect()
}

fn identity(name: &str) -> (u32, String, String, String) {
    let frames = fixture_frames(name);
    let identities: Vec<_> = frames
        .iter()
        .map(|frame| NodeInfo::decode_from_radio(frame))
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .into_iter()
        .flatten()
        .collect();
    assert_eq!(identities.len(), 1, "capture has one node-info record");
    let node = identities[0];
    (
        node.number,
        node.user.id.to_owned(),
        node.user.long_name.to_owned(),
        node.user.short_name.to_owned(),
    )
}

#[test]
fn controlled_long_name_change_identifies_user_field_2() {
    let baseline = identity("meshtastic_nodeinfo_baseline_2026-07-23.json");
    let changed = identity("meshtastic_nodeinfo_long_name_2026-07-23.json");

    assert_eq!(
        baseline,
        (
            0xf66a_fa64,
            "!f66afa64".to_owned(),
            "Meshtastic fa64".to_owned(),
            "fa64".to_owned(),
        )
    );
    assert_eq!(changed.0, baseline.0);
    assert_eq!(changed.1, baseline.1);
    assert_eq!(changed.2, "Sennet NodeInfo Alpha");
    assert_eq!(changed.3, baseline.3);
}

#[test]
fn controlled_short_name_change_identifies_user_field_3() {
    let long_name = identity("meshtastic_nodeinfo_long_name_2026-07-23.json");
    let short_name = identity("meshtastic_nodeinfo_short_name_2026-07-23.json");

    assert_eq!(short_name.0, long_name.0);
    assert_eq!(short_name.1, long_name.1);
    assert_eq!(short_name.2, long_name.2);
    assert_eq!(short_name.3, "SNIA");
}
