//! The reliable stream end to end: two endpoints over an in-memory interface, one
//! `open_reliable`, the other `accept_reliable`, exchanging a multi-packet request and
//! response with half-close and eof.
//!
//! The loss tolerance of the machinery — retransmit, reorder, proof-based acks — is proven
//! deterministically in `reliable`'s sans-io tests on a virtual clock. This test proves the
//! *endpoint wiring*: the router dispatching channel-data and proof packets to the driver
//! task, the driver proving receipts and releasing acked sequences, ordered bytes reaching
//! the app, and half-close teardown (the client finishes sending, then reads the reply).

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use retinue::destination::DestinationName;
use retinue::endpoint::Endpoint;
use retinue::identity::PrivateIdentity;
use retinue::lossy::{LossModel, connect};

#[tokio::test]
async fn reliable_request_response_end_to_end() {
    let server_id = PrivateIdentity::from_secret_bytes(&[0x22; 64]);
    let client_id = PrivateIdentity::from_secret_bytes(&[0x11; 64]);
    let server = Endpoint::new(server_id.clone());
    let client = Endpoint::new(client_id.clone());

    let name = DestinationName::new("retinue", ["reliable"]);
    let dest = name.destination_hash(server_id.public());
    server.register_reliable(name, b"");

    // A clean in-memory interface between the two endpoints.
    connect(&client, &server, LossModel::new(1), LossModel::new(2));

    // Server: accept one reliable link (validating the client's proofs against its known
    // identity), read the whole request, reply with its length, and finish.
    let client_pub = *client_id.public();
    let server_task = tokio::spawn(async move {
        let mut stream = server.accept_reliable(client_pub).await.unwrap();
        let mut req = Vec::new();
        stream.read_to_end(&mut req).await.unwrap();
        let mut resp = b"got ".to_vec();
        resp.extend_from_slice(&(req.len() as u32).to_le_bytes());
        stream.write_all(&resp).await.unwrap();
        stream.shutdown().await.unwrap();
        req
    });

    // Client: open the reliable link, send a multi-packet payload, half-close, read the reply.
    let server_pub = *server_id.public();
    let mut stream = tokio::time::timeout(Duration::from_secs(10), client.open_reliable(dest, server_pub))
        .await
        .expect("link opens within timeout")
        .expect("reliable stream");

    let payload: Vec<u8> = (0..3000u32).map(|i| (i.wrapping_mul(7).wrapping_add(3)) as u8).collect();
    stream.write_all(&payload).await.unwrap();
    stream.shutdown().await.unwrap(); // half-close: done sending, still reading

    let mut resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut resp))
        .await
        .expect("response within timeout")
        .unwrap();

    let got_req = tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server finished")
        .unwrap();
    assert_eq!(got_req, payload, "server received the exact multi-packet request");

    let mut expected = b"got ".to_vec();
    expected.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    assert_eq!(resp, expected, "client received the exact response");
}
