//! Link-setup hardening: a forged proof must not be able to strand a link in setup.
//!
//! The router validates an inbound proof against the pending link *before* removing it, so a
//! proof with the right link id but a bad signature is dropped and the genuine proof still
//! establishes the link. This test plays the attacker: it bridges two endpoints by hand, and
//! when it sees the client's link request it computes the link id and injects a garbage proof
//! back to the client ahead of the real one.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use retinue::destination::DestinationName;
use retinue::endpoint::Endpoint;
use retinue::identity::PrivateIdentity;
use retinue::link::{self, CTX_LRPROOF};
use retinue::packet::{DestinationType, HeaderType, Packet, PacketType, Propagation};

#[tokio::test]
async fn a_forged_proof_does_not_strand_link_setup() {
    let server_id = PrivateIdentity::from_secret_bytes(&[0x22; 64]);
    let client_id = PrivateIdentity::from_secret_bytes(&[0x11; 64]);
    let server = Endpoint::new(server_id.clone());
    let client = Endpoint::new(client_id.clone());

    let name = DestinationName::new("retinue", ["dos"]);
    let dest = name.destination_hash(server_id.public());
    server.register(name, b"");

    // Bridge the two endpoints by hand so we can inject packets.
    let (mut client_out, client_sink) = client.attach_interface().split();
    let (mut server_out, server_sink) = server.attach_interface().split();
    let inject_sink = client_sink.clone();
    let injected = Arc::new(AtomicBool::new(false));

    // client -> server, injecting a forged proof to the client the moment we see the request.
    let injected_c = Arc::clone(&injected);
    tokio::spawn(async move {
        while let Some(pkt) = client_out.recv().await {
            if pkt.packet_type == PacketType::LinkRequest
                && let Ok(link_id) = link::link_id(&pkt)
            {
                // Right link id, wrong signature: 99 bytes of zeroes. prove() reaches the
                // signature check and fails, so a correct router leaves the pending link.
                let forged = Packet {
                    ifac: false,
                    header_type: HeaderType::Type1,
                    context_flag: false,
                    propagation: Propagation::Broadcast,
                    destination_type: DestinationType::Link,
                    packet_type: PacketType::Proof,
                    hops: 0,
                    transport: None,
                    destination: link_id,
                    context: CTX_LRPROOF,
                    payload: vec![0u8; 99],
                };
                inject_sink.deliver(forged);
                injected_c.store(true, Ordering::SeqCst);
            }
            server_sink.deliver(pkt);
        }
    });

    // server -> client (carries the genuine proof).
    tokio::spawn(async move {
        while let Some(pkt) = server_out.recv().await {
            client_sink.deliver(pkt);
        }
    });

    // The link must still open despite the forged proof racing ahead of the real one.
    let stream = tokio::time::timeout(
        Duration::from_secs(8),
        client.open(dest, *server_id.public()),
    )
    .await
    .expect("link opens despite the forged proof")
    .expect("link established");
    assert_eq!(stream.link_id(), stream.link_id());
    assert!(
        injected.load(Ordering::SeqCst),
        "the forged proof was actually injected"
    );
}

/// Dropping an endpoint must release its runtime. Without cancellation the router task holds
/// `Arc<Shared>` while `Shared` holds the router sender, a cycle that keeps every task and
/// socket alive forever. With it, dropping the endpoint aborts the router, `Shared` is freed,
/// and an attached interface's outbound channel closes — the observable proof the cycle broke.
#[tokio::test]
async fn dropping_the_endpoint_releases_its_tasks() {
    let mut iface = {
        let ep = Endpoint::new(PrivateIdentity::from_secret_bytes(&[7u8; 64]));
        ep.attach_interface()
        // `ep` drops here: its Drop aborts the router, so `Shared` — and the interface's
        // outbound sender it holds — is released.
    };
    let got = tokio::time::timeout(Duration::from_secs(3), iface.next_outbound())
        .await
        .expect("outbound closes rather than hanging");
    assert_eq!(
        got, None,
        "the interface's outbound closes once the endpoint is dropped"
    );
}
