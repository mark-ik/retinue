//! Endpoint-level resource publish/fetch over the raw interface seam.

use std::sync::Arc;
use std::time::Duration;

use retinue::destination::DestinationName;
use retinue::endpoint::Endpoint;
use retinue::identity::PrivateIdentity;
use retinue::lossy::{LossModel, connect};

#[tokio::test]
async fn endpoint_publishes_and_fetches_a_resource() {
    let server_id = PrivateIdentity::from_secret_bytes(&[0x22; 64]);
    let client_id = PrivateIdentity::from_secret_bytes(&[0x11; 64]);
    let server = Arc::new(Endpoint::new(server_id.clone()));
    let client = Endpoint::new(client_id);

    let name = DestinationName::new("retinue", ["resource"]);
    let destination = name.destination_hash(server_id.public());
    server.register_resource(name, b"");
    connect(&client, &server, LossModel::new(1), LossModel::new(2));

    let payload: Vec<u8> = (0..12_000_u32)
        .map(|n| n.wrapping_mul(31).wrapping_add(7) as u8)
        .collect();
    let expected = payload.clone();
    let receiver = tokio::spawn({
        let server = Arc::clone(&server);
        async move {
            let mut accepted = server.accept_resource().await.unwrap();
            assert_eq!(accepted.destination, destination);
            accepted.session.fetch().await.unwrap()
        }
    });

    tokio::time::timeout(
        Duration::from_secs(10),
        client.publish_resource(destination, *server_id.public(), &payload),
    )
    .await
    .expect("publish completes")
    .expect("receiver proves the resource");

    let fetched = tokio::time::timeout(Duration::from_secs(5), receiver)
        .await
        .expect("receiver completes")
        .unwrap();
    assert_eq!(fetched, expected);
}

#[tokio::test]
async fn endpoint_fetches_a_resource_published_by_peer() {
    let server_id = PrivateIdentity::from_secret_bytes(&[0x44; 64]);
    let client_id = PrivateIdentity::from_secret_bytes(&[0x33; 64]);
    let server = Arc::new(Endpoint::new(server_id.clone()));
    let client = Endpoint::new(client_id);

    let name = DestinationName::new("retinue", ["resource-fetch"]);
    let destination = name.destination_hash(server_id.public());
    server.register_resource(name, b"");
    connect(&client, &server, LossModel::new(3), LossModel::new(4));

    let payload: Vec<u8> = (0..12_000_u32)
        .map(|n| n.wrapping_mul(17).wrapping_add(11) as u8)
        .collect();
    let expected = payload.clone();
    let publisher = tokio::spawn({
        let server = Arc::clone(&server);
        async move {
            let mut accepted = server.accept_resource().await.unwrap();
            assert_eq!(accepted.destination, destination);
            accepted.session.publish(&payload).await.unwrap();
        }
    });

    let fetched = tokio::time::timeout(
        Duration::from_secs(10),
        client.fetch_resource(destination, *server_id.public()),
    )
    .await
    .expect("fetch completes")
    .expect("published resource verifies");

    tokio::time::timeout(Duration::from_secs(5), publisher)
        .await
        .expect("publisher sees the receipt")
        .unwrap();
    assert_eq!(fetched, expected);
}
